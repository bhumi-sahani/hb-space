-- HB Space — Phase 4, migration 5: private folders, trash, and organising media.
--
-- WHAT THIS ADDS (additive; nothing is dropped, no data is rewritten):
--   1. public.media_folders: opaque folder ids, an opaque parent id, and an
--      ENCRYPTED name blob. No plaintext folder names exist anywhere on the server.
--   2. media_items.folder_id (null = vault root) and media_items.trashed_at
--      (null = active). Existing rows get null/null: they stay at the root, active.
--   3. A replacement of private.guard_media_item() (the migration-1 file is NOT
--      edited; this migration redefines the function). The pending -> ready logic
--      is unchanged; a new branch lets a READY item change only folder_id and its
--      trash state. Every other column of a ready item stays immutable.
--   4. One new UPDATE policy on media_items so either member (not only the
--      uploader) can move / trash / restore READY items.
--   5. RLS, policies, grants, and triggers for media_folders.
--
-- WHAT THIS DOES NOT CHANGE:
--   - No existing policy is dropped or altered. Storage policies are untouched:
--     object names stay <vault_id>/<item_id> (+ ".t" for the encrypted thumbnail),
--     which never contain folder ids or names.
--   - Deletion rules are unchanged (any member may delete media rows/objects).
--     Permanent deletion is only offered from the Trash view in the app; the
--     server-side risk that a stolen member session can delete is documented in
--     SECURITY_ARCHITECTURE.md (finding F1).
--
-- Safe to run against the live project with existing media and key envelopes.
-- See SECURITY_ARCHITECTURE.md §7 (data model), §13 (Phase 4 notes), §15 (finding F1).

-- ---------------------------------------------------------------------------
-- 1. Folders
-- ---------------------------------------------------------------------------
create table public.media_folders (
  -- Client-generated random UUID: it is bound into the encrypted name's AAD
  -- before the row exists.
  id uuid primary key,
  vault_id uuid not null references public.vaults (id) on delete restrict,
  -- null = top level. Immutable after creation, so cycles are impossible.
  parent_id uuid,
  -- 0 for top-level folders; computed by the server from the parent.
  depth smallint not null default 0,
  -- iv(12) || AES-GCM(VMK, JSON padded to a multiple of 256 bytes) || tag(16).
  -- Holds the folder name; never plaintext.
  encrypted_meta bytea not null check (
    octet_length(encrypted_meta) between 284 and 4124
    and (octet_length(encrypted_meta) - 28) % 256 = 0
  ),
  revision integer not null default 1,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_by uuid references auth.users (id) on delete set null,
  updated_at timestamptz not null default now(),
  -- Target of the composite foreign keys below, which force parent folders and
  -- an item's folder to belong to the SAME vault.
  constraint media_folders_vault_id_id_key unique (vault_id, id),
  constraint media_folders_parent_same_vault foreign key (vault_id, parent_id)
    references public.media_folders (vault_id, id) on delete restrict,
  constraint media_folders_not_own_parent check (parent_id is null or parent_id <> id),
  constraint media_folders_depth_range check (depth between 0 and 7)
);

create index media_folders_parent_idx on public.media_folders (vault_id, parent_id);

comment on table public.media_folders is 'HB Space: folders. Opaque ids only; the name is inside encrypted_meta.';

-- Server-stamped fields, depth, and immutability of structure.
-- Runs as the caller (no SECURITY DEFINER): a member can see every folder of
-- their vault through RLS; anyone else is rejected by RLS regardless.
create function private.guard_media_folder()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  parent_depth smallint;
begin
  if tg_op = 'INSERT' then
    if new.parent_id is null then
      new.depth := 0;
    else
      select f.depth into parent_depth
      from public.media_folders f
      where f.id = new.parent_id and f.vault_id = new.vault_id;
      if parent_depth is null then
        raise exception 'parent folder not found in this vault'
          using errcode = 'foreign_key_violation';
      end if;
      if parent_depth >= 7 then
        raise exception 'folders can be nested at most 8 levels deep'
          using errcode = 'check_violation';
      end if;
      new.depth := parent_depth + 1;
    end if;
    new.revision := 1;
    new.created_by := (select auth.uid());
    new.created_at := now();
  else
    -- UPDATE: only the encrypted name may change (rename).
    if (new.id, new.vault_id, new.parent_id, new.depth, new.created_by, new.created_at)
       is distinct from
       (old.id, old.vault_id, old.parent_id, old.depth, old.created_by, old.created_at) then
      raise exception 'only a folder''s encrypted name can change'
        using errcode = 'insufficient_privilege';
    end if;
    new.revision := old.revision + 1;
  end if;
  new.updated_by := (select auth.uid());
  new.updated_at := now();
  return new;
end;
$$;

create trigger media_folders_guard
  before insert or update on public.media_folders
  for each row execute function private.guard_media_folder();

-- A folder can be deleted only when it holds no ACTIVE or PENDING items.
-- Subfolders block deletion through the foreign key (on delete restrict).
-- Items already in the trash are kept and moved to the root (folder_id -> null,
-- via the foreign key below), so restoring them still works.
create function private.guard_media_folder_delete()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if exists (
    select 1 from public.media_items m
    where m.vault_id = old.vault_id
      and m.folder_id = old.id
      and (m.trashed_at is null or m.status <> 'ready')
  ) then
    raise exception 'folder is not empty'
      using errcode = 'check_violation';
  end if;
  return old;
end;
$$;

create trigger media_folders_guard_delete
  before delete on public.media_folders
  for each row execute function private.guard_media_folder_delete();

-- ---------------------------------------------------------------------------
-- 2. media_items: folder and trash state
-- ---------------------------------------------------------------------------
alter table public.media_items
  add column folder_id uuid,
  add column trashed_at timestamptz,
  -- Same-vault folder only. Deleting a folder (only possible when it holds no
  -- active items) moves its trashed items to the root instead of failing.
  add constraint media_items_folder_same_vault foreign key (vault_id, folder_id)
    references public.media_folders (vault_id, id) on delete set null (folder_id);

create index media_items_folder_idx on public.media_items (vault_id, folder_id);

comment on column public.media_items.folder_id is 'Opaque folder id (null = root). No folder name or path is stored.';
comment on column public.media_items.trashed_at is 'Set by the server when an item is moved to the trash; null = active.';

-- ---------------------------------------------------------------------------
-- 3. Replacement guard for media_items.
--
-- INSERT: unchanged from migration 1, plus trashed_at is forced to null.
-- UPDATE of a PENDING item: unchanged from migration 1 (only pending -> ready by
--   the uploader, after the server has verified the stored object(s)); folder_id
--   and trashed_at may not change during this step.
-- UPDATE of a READY item (new): only folder_id and trashed_at may change; status
--   stays 'ready'. trashed_at is stamped by the server (client values ignored).
-- ---------------------------------------------------------------------------
create or replace function private.guard_media_item()
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
    new.trashed_at := null;
    return new;
  end if;

  if (new.id, new.vault_id, new.uploaded_by, new.format_version, new.has_thumbnail,
      new.wrapped_dek, new.encrypted_meta, new.ciphertext_size, new.created_at)
     is distinct from
     (old.id, old.vault_id, old.uploaded_by, old.format_version, old.has_thumbnail,
      old.wrapped_dek, old.encrypted_meta, old.ciphertext_size, old.created_at) then
    raise exception 'media_items fields are immutable except status, folder and trash state'
      using errcode = 'insufficient_privilege';
  end if;

  if old.status = 'ready' then
    -- Organising a finished item: move between folders, trash, restore.
    if new.status is distinct from 'ready' then
      raise exception 'only pending -> ready transitions are allowed'
        using errcode = 'check_violation';
    end if;
    new.ready_at := old.ready_at;
    if new.trashed_at is null then
      new.trashed_at := null;                -- restore (or stays active)
    elsif old.trashed_at is null then
      new.trashed_at := now();               -- moved to trash now
    else
      new.trashed_at := old.trashed_at;      -- already in trash: keep original time
    end if;
    return new;
  end if;

  -- old.status = 'pending': the migration-1 rules, unchanged.
  if (new.folder_id, new.trashed_at) is distinct from (old.folder_id, old.trashed_at) then
    raise exception 'a pending upload cannot be moved or trashed'
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

-- create or replace keeps the existing privileges; restate them explicitly.
revoke all on function private.guard_media_item() from public;

-- ---------------------------------------------------------------------------
-- 4. Privileges
-- ---------------------------------------------------------------------------
alter table public.media_folders enable row level security;
revoke all on table public.media_folders from anon, authenticated;

grant select on table public.media_folders to authenticated;
grant insert (id, vault_id, parent_id, encrypted_meta) on table public.media_folders to authenticated;
grant update (encrypted_meta) on table public.media_folders to authenticated;
grant delete on table public.media_folders to authenticated;

-- Items can be uploaded straight into a folder, then moved / trashed / restored.
grant insert (folder_id) on table public.media_items to authenticated;
grant update (folder_id, trashed_at) on table public.media_items to authenticated;

revoke all on function private.guard_media_folder() from public;
revoke all on function private.guard_media_folder_delete() from public;

-- ---------------------------------------------------------------------------
-- 5. RLS policies (all scoped to authenticated vault members; no bare true)
-- ---------------------------------------------------------------------------
create policy "members can read folders"
  on public.media_folders for select
  to authenticated
  using (private.is_vault_member(vault_id));

create policy "members can create folders"
  on public.media_folders for insert
  to authenticated
  with check (private.is_vault_member(vault_id) and created_by = (select auth.uid()));

create policy "members can rename folders"
  on public.media_folders for update
  to authenticated
  using (private.is_vault_member(vault_id))
  with check (private.is_vault_member(vault_id));

create policy "members can delete folders"
  on public.media_folders for delete
  to authenticated
  using (private.is_vault_member(vault_id));

-- Either member may organise READY items. Pending items remain governed only
-- by the existing "uploader can finalise own media" policy.
create policy "members can organise ready media"
  on public.media_items for update
  to authenticated
  using (private.is_vault_member(vault_id) and status = 'ready')
  with check (private.is_vault_member(vault_id) and status = 'ready');
