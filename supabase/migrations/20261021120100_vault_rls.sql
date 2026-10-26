-- HB Space — Phase 2, migration 2 of 3: privileges and Row Level Security.
--
-- Three layers, all server-side:
--   1. Table/column GRANTs: what statement types each role may attempt at all.
--   2. RLS policies: which rows those statements may touch (membership-based).
--   3. Triggers (migration 1): server-stamped identity and state transitions.
--
-- Supabase's default privileges grant ALL on new public tables to anon and
-- authenticated. We revoke that and grant back only what the app needs, so a
-- missing or mistaken policy is not the only line of defence.
--
-- No policy uses a bare `true`. Identity comes only from auth.uid() (the verified
-- JWT `sub`); no policy trusts a client-supplied user id. Every policy is scoped
-- `to authenticated`, so anon is denied both by grants and by RLS.

-- ---------------------------------------------------------------------------
-- Enable RLS on every table exposed through the API.
-- ---------------------------------------------------------------------------
alter table public.vaults enable row level security;
alter table public.vault_members enable row level security;
alter table public.vault_key_envelopes enable row level security;
alter table public.media_items enable row level security;

-- ---------------------------------------------------------------------------
-- Reset privileges.
-- ---------------------------------------------------------------------------
revoke all on table public.vaults, public.vault_members, public.vault_key_envelopes, public.media_items
  from anon, authenticated;

-- vaults / vault_members: read-only for clients. Membership is managed only by
-- the project owner in the SQL editor (postgres role).
grant select on table public.vaults to authenticated;
grant select on table public.vault_members to authenticated;

-- vault_key_envelopes: read, create, re-wrap. Never delete (prevents accidental
-- lockout). Audit columns (created_by, updated_by, revision, timestamps) are not
-- client-writable; the stamp trigger sets them.
grant select on table public.vault_key_envelopes to authenticated;
grant insert (vault_id, kind, format_version, kdf, kdf_params, salt, iv, wrapped_key)
  on table public.vault_key_envelopes to authenticated;
grant update (format_version, kdf, kdf_params, salt, iv, wrapped_key)
  on table public.vault_key_envelopes to authenticated;

-- media_items: read, create (as pending), finalise (status only), delete.
-- uploaded_by, status-on-insert, paths and timestamps are not client-writable.
grant select on table public.media_items to authenticated;
grant insert (id, vault_id, format_version, has_thumbnail, wrapped_dek, encrypted_meta, ciphertext_size)
  on table public.media_items to authenticated;
grant update (status) on table public.media_items to authenticated;
grant delete on table public.media_items to authenticated;

-- ---------------------------------------------------------------------------
-- vaults
-- ---------------------------------------------------------------------------
create policy "members can read their vault"
  on public.vaults for select
  to authenticated
  using (private.is_vault_member(id));

-- ---------------------------------------------------------------------------
-- vault_members
-- Only your own membership row is visible. This policy deliberately does NOT
-- call is_vault_member(), so there is no recursion. No insert/update/delete
-- policies or grants exist: members cannot add, remove, or alter anyone.
-- ---------------------------------------------------------------------------
create policy "users can read their own membership"
  on public.vault_members for select
  to authenticated
  using (user_id = (select auth.uid()));

-- ---------------------------------------------------------------------------
-- vault_key_envelopes
-- ---------------------------------------------------------------------------
create policy "members can read key envelopes"
  on public.vault_key_envelopes for select
  to authenticated
  using (private.is_vault_member(vault_id));

create policy "members can create key envelopes"
  on public.vault_key_envelopes for insert
  to authenticated
  with check (private.is_vault_member(vault_id));

create policy "members can re-wrap key envelopes"
  on public.vault_key_envelopes for update
  to authenticated
  using (private.is_vault_member(vault_id))
  with check (private.is_vault_member(vault_id));

-- ---------------------------------------------------------------------------
-- media_items
-- Read and delete share the same rule: any member of the item's vault.
-- ---------------------------------------------------------------------------
create policy "members can read media"
  on public.media_items for select
  to authenticated
  using (private.is_vault_member(vault_id));

create policy "members can add pending media"
  on public.media_items for insert
  to authenticated
  with check (
    private.is_vault_member(vault_id)
    and uploaded_by = (select auth.uid())
    and status = 'pending'
  );

create policy "uploader can finalise own media"
  on public.media_items for update
  to authenticated
  using (
    private.is_vault_member(vault_id)
    and uploaded_by = (select auth.uid())
  )
  with check (
    private.is_vault_member(vault_id)
    and uploaded_by = (select auth.uid())
    and status = 'ready'
  );

create policy "members can delete media"
  on public.media_items for delete
  to authenticated
  using (private.is_vault_member(vault_id));
