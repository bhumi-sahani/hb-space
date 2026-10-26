-- HB Space — Phase 2, migration 3 of 3: private Storage bucket and object policies.
--
-- Objects in `private-media` are ciphertext only, named `<vault_id>/<item_id>`
-- (content) or `<vault_id>/<item_id>.t` (thumbnail). Names carry no filename.
--
-- Object access is tied to DATABASE ROWS, not to a client-supplied path: an
-- object name is accepted only if it exactly equals the server-generated path
-- of a media_items row in a vault the caller belongs to. Knowing or guessing a
-- path grants nothing.
--
-- Storage API permission needs (Supabase docs): upload = INSERT; download = SELECT;
-- remove = SELECT + DELETE; upsert/move/overwrite = UPDATE (+ SELECT, INSERT).
-- We grant SELECT, INSERT and DELETE, and deny UPDATE entirely: ciphertext
-- objects are write-once.

-- ---------------------------------------------------------------------------
-- Bucket: private, ciphertext MIME type only, size-capped.
-- 50 MiB matches the Supabase Free plan's per-object maximum; raise both this
-- and the project's global limit together on paid plans.
-- If the bucket already exists, this only tightens it (forces public = false).
-- ---------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('private-media', 'private-media', false, 52428800, array['application/octet-stream'])
on conflict (id) do update
  set public = false,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- ---------------------------------------------------------------------------
-- Helpers. SECURITY DEFINER so they read media_items / vault_members as owner
-- (no dependence on, or recursion through, those tables' RLS). Identity comes
-- only from auth.uid().
-- ---------------------------------------------------------------------------
create function private.can_read_media_object(p_bucket_id text, p_name text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select p_bucket_id = 'private-media'
    and exists (
      select 1
      from public.media_items m
      join public.vault_members vm
        on vm.vault_id = m.vault_id
       and vm.user_id = (select auth.uid())
      where p_name = m.object_path
         or (m.has_thumbnail and p_name = m.thumbnail_path)
    );
$$;

create function private.can_upload_media_object(p_bucket_id text, p_name text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select p_bucket_id = 'private-media'
    and exists (
      select 1
      from public.media_items m
      join public.vault_members vm
        on vm.vault_id = m.vault_id
       and vm.user_id = (select auth.uid())
      where m.status = 'pending'
        and m.uploaded_by = (select auth.uid())
        and (p_name = m.object_path or (m.has_thumbnail and p_name = m.thumbnail_path))
    );
$$;

revoke all on function private.can_read_media_object(text, text) from public;
revoke all on function private.can_upload_media_object(text, text) from public;
-- anon needs EXECUTE too, because the restrictive guards below apply to every
-- role (so a future public/anon policy cannot open this bucket). For anon,
-- auth.uid() is null and both functions return false. The private schema is not
-- exposed through the Data API, so this does not make them callable as RPCs.
grant usage on schema private to anon;
grant execute on function private.can_read_media_object(text, text) to anon, authenticated;
grant execute on function private.can_upload_media_object(text, text) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- RESTRICTIVE guard policies (apply to every role, ANDed with all other
-- policies). Even if someone later adds a broad permissive policy on
-- storage.objects (e.g. from a template), private-media stays locked to the
-- rules below. Other buckets are unaffected.
-- ---------------------------------------------------------------------------
create policy "private-media guard: select"
  on storage.objects as restrictive for select
  to public
  using (bucket_id <> 'private-media' or private.can_read_media_object(bucket_id, name));

create policy "private-media guard: insert"
  on storage.objects as restrictive for insert
  to public
  with check (bucket_id <> 'private-media' or private.can_upload_media_object(bucket_id, name));

create policy "private-media guard: update"
  on storage.objects as restrictive for update
  to public
  using (bucket_id <> 'private-media')
  with check (bucket_id <> 'private-media');

create policy "private-media guard: delete"
  on storage.objects as restrictive for delete
  to public
  using (bucket_id <> 'private-media' or private.can_read_media_object(bucket_id, name));

-- ---------------------------------------------------------------------------
-- PERMISSIVE policies (the actual grants), authenticated only.
-- Download and delete share one rule: same authorization as reading.
-- ---------------------------------------------------------------------------
create policy "private-media: members read item objects"
  on storage.objects for select
  to authenticated
  using (private.can_read_media_object(bucket_id, name));

create policy "private-media: uploader writes pending item objects"
  on storage.objects for insert
  to authenticated
  with check (private.can_upload_media_object(bucket_id, name));

create policy "private-media: members delete item objects"
  on storage.objects for delete
  to authenticated
  using (private.can_read_media_object(bucket_id, name));

-- No UPDATE policy: objects cannot be overwritten, moved, or upserted.
