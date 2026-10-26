-- HB Space — Phase 2, migration 1 of 3: core schema.
--
-- Non-destructive: creates new objects only. Holds NO plaintext media, filenames,
-- MIME types, captions, passphrases, or unwrapped keys. Every bytea column below
-- is ciphertext or non-secret cryptographic parameters (salt / IV).
--
-- See SECURITY_ARCHITECTURE.md §5 and §7.

-- ---------------------------------------------------------------------------
-- Private schema for helper functions. It is NOT exposed through the Data API
-- (only `public` and `graphql_public` are by default), so nothing here can be
-- called as an RPC. `authenticated` gets USAGE only so RLS policies can call
-- the specific functions granted below.
-- ---------------------------------------------------------------------------
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

-- ---------------------------------------------------------------------------
-- vaults: exactly one shared vault.
-- ---------------------------------------------------------------------------
create table public.vaults (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  -- Constant column + unique constraint = at most one row in this table.
  singleton boolean not null default true check (singleton),
  constraint vaults_single_vault unique (singleton)
);

comment on table public.vaults is 'HB Space: the single shared vault. Created only via private.provision_vault().';

-- ---------------------------------------------------------------------------
-- vault_members: the two approved accounts. No client can write here.
-- ---------------------------------------------------------------------------
create table public.vault_members (
  vault_id uuid not null references public.vaults (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  added_at timestamptz not null default now(),
  primary key (vault_id, user_id)
);

create index vault_members_user_id_idx on public.vault_members (user_id);

comment on table public.vault_members is 'HB Space: approved members (max 2). Managed from the SQL editor only; immutable rows.';

create function private.enforce_vault_member_rules()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  member_count integer;
begin
  if tg_op = 'UPDATE' then
    raise exception 'vault_members rows are immutable; delete and re-insert instead'
      using errcode = 'insufficient_privilege';
  end if;

  -- Lock the vault row so two concurrent inserts cannot both pass the count.
  perform 1 from public.vaults where id = new.vault_id for update;

  select count(*) into member_count
  from public.vault_members
  where vault_id = new.vault_id;

  if member_count >= 2 then
    raise exception 'a vault cannot have more than two members'
      using errcode = 'check_violation';
  end if;

  return new;
end;
$$;

create trigger vault_members_rules
  before insert or update on public.vault_members
  for each row execute function private.enforce_vault_member_rules();

-- ---------------------------------------------------------------------------
-- Membership helper used by RLS policies.
--
-- SECURITY DEFINER so it reads vault_members as the table owner, which bypasses
-- RLS on that table. This is what prevents policy recursion: policies on other
-- tables call this function, and vault_members' own policy does not.
-- The caller's identity comes only from the verified JWT (auth.uid()); there is
-- no user-id parameter a client could supply.
-- ---------------------------------------------------------------------------
create function private.is_vault_member(p_vault_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.vault_members m
    where m.vault_id = p_vault_id
      and m.user_id = (select auth.uid())
  );
$$;

-- ---------------------------------------------------------------------------
-- vault_key_envelopes: the vault master key wrapped under the passphrase-derived
-- key (kind = 'passphrase') or the recovery-code key (kind = 'recovery').
-- Useless without the corresponding secret, which never reaches the server.
-- ---------------------------------------------------------------------------
create function private.argon2id_params_valid(p jsonb)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select case
    when p is null or jsonb_typeof(p) <> 'object' then false
    when (p - array['m', 't', 'p']) <> '{}'::jsonb then false
    when not (p ? 'm' and p ? 't' and p ? 'p') then false
    when jsonb_typeof(p -> 'm') <> 'number'
      or jsonb_typeof(p -> 't') <> 'number'
      or jsonb_typeof(p -> 'p') <> 'number' then false
    when (p ->> 'm') !~ '^[0-9]{1,9}$'
      or (p ->> 't') !~ '^[0-9]{1,3}$'
      or (p ->> 'p') !~ '^[0-9]{1,3}$' then false
    -- 16 MiB..1 GiB memory, 1..10 passes, single lane. Mirrors the client-side bounds.
    else (p ->> 'm')::integer between 16384 and 1048576
      and (p ->> 't')::integer between 1 and 10
      and (p ->> 'p')::integer = 1
  end;
$$;

create table public.vault_key_envelopes (
  vault_id uuid not null references public.vaults (id) on delete restrict,
  kind text not null check (kind in ('passphrase', 'recovery')),
  format_version smallint not null check (format_version = 1),
  kdf text not null,
  kdf_params jsonb,
  salt bytea not null check (octet_length(salt) = 16),
  iv bytea not null check (octet_length(iv) = 12),
  -- AES-256-GCM(KEK, 32-byte VMK) = 32 bytes ciphertext + 16 bytes tag.
  wrapped_key bytea not null check (octet_length(wrapped_key) = 48),
  -- Incremented on every update; clients use it for optimistic concurrency.
  revision integer not null default 1,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_by uuid references auth.users (id) on delete set null,
  updated_at timestamptz not null default now(),
  primary key (vault_id, kind),
  constraint vault_key_envelopes_kdf_matches_kind check (
    (kind = 'passphrase' and kdf = 'argon2id-v1' and private.argon2id_params_valid(kdf_params))
    or (kind = 'recovery' and kdf = 'hkdf-sha256-v1' and kdf_params is null)
  )
);

comment on table public.vault_key_envelopes is 'HB Space: wrapped vault master key envelopes. Ciphertext only.';

-- Server-stamped audit fields. Client-supplied values are ignored/overwritten.
create function private.stamp_vault_key_envelope()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'INSERT' then
    new.created_by := (select auth.uid());
    new.created_at := now();
    new.revision := 1;
  else
    if new.vault_id is distinct from old.vault_id or new.kind is distinct from old.kind then
      raise exception 'vault_id and kind of an envelope cannot change'
        using errcode = 'insufficient_privilege';
    end if;
    new.created_by := old.created_by;
    new.created_at := old.created_at;
    new.revision := old.revision + 1;
  end if;
  new.updated_by := (select auth.uid());
  new.updated_at := now();
  return new;
end;
$$;

create trigger vault_key_envelopes_stamp
  before insert or update on public.vault_key_envelopes
  for each row execute function private.stamp_vault_key_envelope();

-- ---------------------------------------------------------------------------
-- media_items: one row per encrypted photo/video. All descriptive metadata is
-- inside encrypted_meta. Storage object names are DERIVED from (vault_id, id),
-- never chosen freely by the client, and contain no filename.
-- ---------------------------------------------------------------------------
create table public.media_items (
  -- Client-generated random UUID: it is bound into the ciphertext header (AAD)
  -- before upload, so it must be known before the row exists.
  id uuid primary key,
  vault_id uuid not null references public.vaults (id) on delete restrict,
  uploaded_by uuid references auth.users (id) on delete set null,
  status text not null default 'pending' check (status in ('pending', 'ready')),
  format_version smallint not null check (format_version = 1),
  has_thumbnail boolean not null default false,
  object_path text generated always as (vault_id::text || '/' || id::text) stored,
  thumbnail_path text generated always as (vault_id::text || '/' || id::text || '.t') stored,
  -- iv(12) || AES-GCM(VMK, 32-byte DEK) || tag(16)
  wrapped_dek bytea not null check (octet_length(wrapped_dek) = 60),
  -- iv(12) || AES-GCM(meta_key, JSON padded to a multiple of 256 bytes) || tag(16)
  encrypted_meta bytea not null check (
    octet_length(encrypted_meta) between 284 and 65564
    and (octet_length(encrypted_meta) - 28) % 256 = 0
  ),
  -- Total size of the content object; checked against Storage when marking ready.
  ciphertext_size bigint not null check (ciphertext_size >= 56 and ciphertext_size <= 5368709120),
  created_at timestamptz not null default now(),
  ready_at timestamptz,
  constraint media_items_ready_at_matches_status check ((status = 'ready') = (ready_at is not null))
);

create unique index media_items_object_path_idx on public.media_items (object_path);
create unique index media_items_thumbnail_path_idx on public.media_items (thumbnail_path);
create index media_items_vault_created_idx on public.media_items (vault_id, created_at desc);

comment on table public.media_items is 'HB Space: encrypted media records. No plaintext names, types, or captions.';

create function private.guard_media_item()
returns trigger
language plpgsql
security definer -- reads storage.objects to verify the upload; never trusts client input for this
set search_path = ''
as $$
declare
  stored_size bigint;
begin
  if tg_op = 'INSERT' then
    -- Never trust client-supplied ownership or state.
    new.uploaded_by := (select auth.uid());
    new.status := 'pending';
    new.ready_at := null;
    new.created_at := now();
    return new;
  end if;

  -- UPDATE: the only permitted change is pending -> ready by the uploader.
  if (new.id, new.vault_id, new.uploaded_by, new.format_version, new.has_thumbnail,
      new.wrapped_dek, new.encrypted_meta, new.ciphertext_size, new.created_at)
     is distinct from
     (old.id, old.vault_id, old.uploaded_by, old.format_version, old.has_thumbnail,
      old.wrapped_dek, old.encrypted_meta, old.ciphertext_size, old.created_at) then
    raise exception 'media_items fields are immutable except status'
      using errcode = 'insufficient_privilege';
  end if;

  if not (old.status = 'pending' and new.status = 'ready') then
    raise exception 'only pending -> ready transitions are allowed'
      using errcode = 'check_violation';
  end if;

  if old.uploaded_by is distinct from (select auth.uid()) then
    raise exception 'only the uploader can finalise an upload'
      using errcode = 'insufficient_privilege';
  end if;

  select (o.metadata ->> 'size')::bigint into stored_size
  from storage.objects o
  where o.bucket_id = 'private-media' and o.name = old.object_path;

  if stored_size is null then
    raise exception 'encrypted object has not been uploaded'
      using errcode = 'check_violation';
  end if;
  if stored_size <> old.ciphertext_size then
    raise exception 'uploaded object size does not match the declared ciphertext size'
      using errcode = 'check_violation';
  end if;
  if old.has_thumbnail and not exists (
    select 1 from storage.objects o
    where o.bucket_id = 'private-media' and o.name = old.thumbnail_path
  ) then
    raise exception 'encrypted thumbnail has not been uploaded'
      using errcode = 'check_violation';
  end if;

  new.ready_at := now();
  return new;
end;
$$;

create trigger media_items_guard
  before insert or update on public.media_items
  for each row execute function private.guard_media_item();

-- ---------------------------------------------------------------------------
-- Provisioning (owner only, from the SQL editor). Not callable by any API role.
-- ---------------------------------------------------------------------------
create function private.provision_vault(p_member_a uuid, p_member_b uuid)
returns uuid
language plpgsql
set search_path = ''
as $$
declare
  new_vault_id uuid;
begin
  if p_member_a is null or p_member_b is null or p_member_a = p_member_b then
    raise exception 'provide two different user ids';
  end if;
  if (select count(*) from auth.users where id in (p_member_a, p_member_b)) <> 2 then
    raise exception 'both user ids must exist in auth.users';
  end if;

  insert into public.vaults default values returning id into new_vault_id; -- fails if a vault already exists
  insert into public.vault_members (vault_id, user_id)
  values (new_vault_id, p_member_a), (new_vault_id, p_member_b);
  return new_vault_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- Function privileges: nothing is executable by default.
-- ---------------------------------------------------------------------------
revoke all on function private.enforce_vault_member_rules() from public;
revoke all on function private.is_vault_member(uuid) from public;
revoke all on function private.argon2id_params_valid(jsonb) from public;
revoke all on function private.stamp_vault_key_envelope() from public;
revoke all on function private.guard_media_item() from public;
revoke all on function private.provision_vault(uuid, uuid) from public;

-- Policies run as the calling role, so it needs EXECUTE on the membership check.
grant execute on function private.is_vault_member(uuid) to authenticated;
-- CHECK constraints call this as the inserting role.
grant execute on function private.argon2id_params_valid(jsonb) to authenticated;
