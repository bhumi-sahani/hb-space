-- HB Space — RLS / Storage policy verification for a REAL Supabase project.
--
-- HOW TO RUN: paste into Supabase Dashboard -> SQL Editor and run, AFTER all
-- five migrations (including 20261022120000_vault_key_proof.sql and 20261023120000_folders_trash.sql) are applied
-- and the vault is provisioned with both members.
--
-- SAFE: everything runs inside one DO block that ALWAYS ends by raising an
-- exception, so every insert/update/delete it performs is rolled back.
--   * Success shows:  ERROR: HB SPACE RLS VERIFICATION PASSED — ...
--   * Failure shows:  ERROR: FAIL: <what went wrong>
-- It impersonates roles with SET ROLE + request.jwt.claims (the method Supabase
-- documents for testing RLS). The "outsider" is a random user id that is not
-- a vault member — i.e. any authenticated-but-unapproved account.
-- It never prints secrets; it only reports pass/fail.
--
-- SCRIPT VERSION 5 (for migrations 1–5). A pass message that does not say
-- "script v5" means an older copy was run. Older copies are NOT compatible:
-- the Phase 2 copy expected a member to re-wrap a key envelope WITHOUT a
-- key-possession proof, which migration 4 correctly forbids. It fails with
-- "a valid vault key proof is required to write key envelopes".
-- Always paste this file fresh from the repository.
--
-- Key envelopes: this script only checks that unproven or wrongly-proven
-- writes are REJECTED. It never holds the real vault key, so it never changes
-- a real envelope. Only on a vault with no envelopes yet does it create a
-- throwaway envelope under a random test-only proof (rolled back) to exercise
-- the success path.

do $verify$
declare
  v_vault uuid;
  v_a uuid;
  v_b uuid;
  v_outsider uuid := gen_random_uuid();
  v_item uuid := gen_random_uuid();
  v_folder uuid := gen_random_uuid();
  v_subfolder uuid := gen_random_uuid();
  v_ts timestamptz;
  v_path text;
  v_n integer;
  v_bool boolean;
  v_text text;
  v_has_env boolean;
  v_storage_writable boolean;
  v_revision integer;
  -- Random test-only key proof (never a real one): verifier = sha256(proof).
  v_proof bytea := uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid());
  v_wrong_proof bytea := uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid());
  t text;
begin
  ---------------------------------------------------------------------------
  -- Static configuration checks (as the project owner)
  ---------------------------------------------------------------------------
  select id into v_vault from public.vaults;
  if v_vault is null then
    raise exception 'SETUP: no vault provisioned yet — run supabase/provisioning/provision_vault.sql first';
  end if;
  select user_id into v_a from public.vault_members where vault_id = v_vault order by user_id limit 1;
  select user_id into v_b from public.vault_members where vault_id = v_vault order by user_id offset 1 limit 1;
  if v_b is null then
    raise exception 'SETUP: the vault must have exactly two members';
  end if;

  select public into v_bool from storage.buckets where id = 'private-media';
  if v_bool is null then raise exception 'FAIL: bucket private-media does not exist'; end if;
  if v_bool then raise exception 'FAIL: bucket private-media is PUBLIC'; end if;

  foreach t in array array['vaults', 'vault_members', 'vault_key_envelopes', 'media_items', 'media_folders'] loop
    select relrowsecurity into v_bool from pg_class where oid = ('public.' || t)::regclass;
    if not v_bool then raise exception 'FAIL: RLS is disabled on public.%', t; end if;
    if has_table_privilege('anon', 'public.' || t, 'SELECT,INSERT,UPDATE,DELETE') then
      raise exception 'FAIL: anon has privileges on public.%', t;
    end if;
  end loop;

  select string_agg(tablename || '.' || policyname, ', ') into v_text
  from pg_policies
  where schemaname = 'public'
    and tablename in ('vaults', 'vault_members', 'vault_key_envelopes', 'media_items', 'media_folders')
    and (trim(qual) = 'true' or trim(with_check) = 'true');
  if v_text is not null then raise exception 'FAIL: unrestricted policies found: %', v_text; end if;

  select string_agg(tablename || '.' || policyname, ', ') into v_text
  from pg_policies
  where schemaname = 'public'
    and tablename in ('vaults', 'vault_members', 'vault_key_envelopes', 'media_items', 'media_folders')
    and not ('authenticated' = any (roles));
  if v_text is not null then raise exception 'FAIL: policies not scoped to authenticated: %', v_text; end if;

  select count(*) into v_n from pg_policies
  where schemaname = 'storage' and tablename = 'objects'
    and policyname like 'private-media guard:%' and permissive = 'RESTRICTIVE';
  if v_n <> 4 then raise exception 'FAIL: expected 4 restrictive private-media guard policies, found %', v_n; end if;

  if has_function_privilege('authenticated', 'private.provision_vault(uuid, uuid)', 'EXECUTE') then
    raise exception 'FAIL: authenticated can execute provision_vault';
  end if;

  -- Phase 3 (finding F2): envelope writes need a key-possession proof.
  if not exists (
    select 1 from pg_trigger
    where tgrelid = 'public.vault_key_envelopes'::regclass and tgname = 'vault_key_envelopes_proof' and tgenabled <> 'D'
  ) then
    raise exception 'FAIL: key-proof trigger missing or disabled on vault_key_envelopes (apply migration 20261022120000_vault_key_proof.sql)';
  end if;
  if exists (select 1 from public.vault_key_envelopes where key_proof is not null) then
    raise exception 'FAIL: a key proof has been persisted';
  end if;
  if has_column_privilege('authenticated', 'public.vault_key_envelopes', 'key_verifier', 'UPDATE') then
    raise exception 'FAIL: authenticated can update key_verifier';
  end if;

  -- Phase 4 (migration 5): folders, trash, organising.
  if to_regclass('public.media_folders') is null
     or not exists (select 1 from information_schema.columns
                    where table_schema = 'public' and table_name = 'media_items' and column_name = 'trashed_at') then
    raise exception 'FAIL: folders/trash schema missing (apply migration 20261023120000_folders_trash.sql)';
  end if;
  foreach t in array array['media_folders_guard', 'media_folders_guard_delete'] loop
    if not exists (select 1 from pg_trigger where tgrelid = 'public.media_folders'::regclass and tgname = t and tgenabled <> 'D') then
      raise exception 'FAIL: trigger % missing or disabled on media_folders', t;
    end if;
  end loop;
  if has_column_privilege('authenticated', 'public.media_folders', 'parent_id', 'UPDATE')
     or has_column_privilege('authenticated', 'public.media_folders', 'created_by', 'INSERT')
     or has_column_privilege('authenticated', 'public.media_items', 'encrypted_meta', 'UPDATE')
     or has_column_privilege('authenticated', 'public.media_items', 'status', 'INSERT') then
    raise exception 'FAIL: a structural/audit column is client-writable';
  end if;
  select count(*) into v_n from information_schema.columns
  where table_schema = 'public' and table_name = 'media_folders'
    and column_name not in ('id', 'vault_id', 'parent_id', 'depth', 'encrypted_meta', 'revision',
                            'created_by', 'created_at', 'updated_by', 'updated_at');
  if v_n > 0 then raise exception 'FAIL: media_folders has unexpected columns (folder names must stay encrypted)'; end if;

  select exists (select 1 from public.vault_key_envelopes where vault_id = v_vault and kind = 'passphrase') into v_has_env;
  v_storage_writable := has_table_privilege('authenticated', 'storage.objects', 'INSERT');
  if not v_storage_writable then
    raise notice 'NOTE: authenticated cannot INSERT into storage.objects via SQL on this project; storage upload checks are skipped here. Use the in-app access self-test.';
  end if;

  ---------------------------------------------------------------------------
  -- Anonymous
  ---------------------------------------------------------------------------
  perform set_config('role', 'anon', true);
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);

  begin perform 1 from public.vaults; raise exception 'FAIL: anon can query vaults';
  exception when insufficient_privilege then null; end;
  begin perform 1 from public.vault_members; raise exception 'FAIL: anon can query vault_members';
  exception when insufficient_privilege then null; end;
  begin perform 1 from public.vault_key_envelopes; raise exception 'FAIL: anon can query vault_key_envelopes';
  exception when insufficient_privilege then null; end;
  begin perform 1 from public.media_items; raise exception 'FAIL: anon can query media_items';
  exception when insufficient_privilege then null; end;
  begin perform 1 from public.media_folders; raise exception 'FAIL: anon can query media_folders';
  exception when insufficient_privilege then null; end;
  begin
    select count(*) into v_n from storage.objects where bucket_id = 'private-media';
    if v_n > 0 then raise exception 'FAIL: anon can see private-media objects'; end if;
  exception when insufficient_privilege then null; end;

  ---------------------------------------------------------------------------
  -- Authenticated outsider (not a member)
  ---------------------------------------------------------------------------
  perform set_config('role', 'authenticated', true);
  perform set_config('request.jwt.claims', json_build_object('sub', v_outsider, 'role', 'authenticated')::text, true);

  foreach t in array array['vaults', 'vault_members', 'vault_key_envelopes', 'media_items', 'media_folders'] loop
    execute format('select count(*) from public.%I', t) into v_n;
    if v_n > 0 then raise exception 'FAIL: outsider can read % row(s) of public.%', v_n, t; end if;
  end loop;

  select count(*) into v_n from storage.objects where bucket_id = 'private-media';
  if v_n > 0 then raise exception 'FAIL: outsider can see private-media objects'; end if;

  begin
    insert into public.vault_members (vault_id, user_id) values (v_vault, v_outsider);
    raise exception 'FAIL: outsider added themselves as a member';
  exception when insufficient_privilege then null; end;

  begin
    insert into public.media_items (id, vault_id, format_version, wrapped_dek, encrypted_meta, ciphertext_size)
    values (gen_random_uuid(), v_vault, 1, decode(repeat('00', 60), 'hex'), decode(repeat('00', 284), 'hex'), 100);
    raise exception 'FAIL: outsider inserted media';
  exception when insufficient_privilege then null; end;

  begin
    -- Carries a self-consistent proof, so only RLS can stop it.
    insert into public.vault_key_envelopes (vault_id, kind, format_version, kdf, kdf_params, salt, iv, wrapped_key, key_verifier, key_proof)
    values (v_vault, 'recovery', 1, 'hkdf-sha256-v1', null,
            decode(repeat('00', 16), 'hex'), decode(repeat('00', 12), 'hex'), decode(repeat('00', 48), 'hex'),
            sha256(v_proof), v_proof);
    raise exception 'FAIL: outsider inserted a key envelope';
  exception when insufficient_privilege or unique_violation then
    -- unique_violation would mean the RLS check passed and only the PK stopped it.
    if sqlstate = '23505' then raise exception 'FAIL: outsider passed RLS on vault_key_envelopes insert'; end if;
  end;

  update public.vault_key_envelopes set iv = iv;
  get diagnostics v_n = row_count;
  if v_n > 0 then raise exception 'FAIL: outsider can modify key envelopes'; end if;

  update public.media_items set status = 'ready';
  get diagnostics v_n = row_count;
  if v_n > 0 then raise exception 'FAIL: outsider can update media'; end if;

  delete from public.media_items;
  get diagnostics v_n = row_count;
  if v_n > 0 then raise exception 'FAIL: outsider can delete media'; end if;

  update public.media_items set trashed_at = now(), folder_id = null;
  get diagnostics v_n = row_count;
  if v_n > 0 then raise exception 'FAIL: outsider can move or trash media'; end if;

  begin
    insert into public.media_folders (id, vault_id, encrypted_meta) values (gen_random_uuid(), v_vault, decode(repeat('00', 284), 'hex'));
    raise exception 'FAIL: outsider created a folder';
  exception when insufficient_privilege then null; end;

  update public.media_folders set encrypted_meta = encrypted_meta;
  get diagnostics v_n = row_count;
  if v_n > 0 then raise exception 'FAIL: outsider can rename folders'; end if;

  delete from public.media_folders;
  get diagnostics v_n = row_count;
  if v_n > 0 then raise exception 'FAIL: outsider can delete folders'; end if;

  if v_storage_writable then
    begin
      insert into storage.objects (bucket_id, name, metadata)
      values ('private-media', v_vault || '/' || gen_random_uuid(), '{"size": 100}');
      raise exception 'FAIL: outsider uploaded into private-media';
    exception when insufficient_privilege then null; end;
  end if;

  ---------------------------------------------------------------------------
  -- Member A
  ---------------------------------------------------------------------------
  perform set_config('request.jwt.claims', json_build_object('sub', v_a, 'role', 'authenticated')::text, true);

  select count(*) into v_n from public.vaults;
  if v_n <> 1 then raise exception 'FAIL: member A cannot see the vault'; end if;
  select count(*) into v_n from public.vault_members;
  if v_n <> 1 then raise exception 'FAIL: member A sees % membership rows (expected only their own)', v_n; end if;

  select private.is_vault_member(gen_random_uuid()) into v_bool;
  if v_bool then raise exception 'FAIL: membership check accepts an arbitrary vault id'; end if;

  begin
    insert into public.vault_members (vault_id, user_id) values (v_vault, v_outsider);
    raise exception 'FAIL: member A can add a member';
  exception when insufficient_privilege then null; end;
  begin
    delete from public.vault_members where user_id = v_b;
    raise exception 'FAIL: member A can remove a member';
  exception when insufficient_privilege then null; end;
  begin
    delete from public.vault_key_envelopes;
    raise exception 'FAIL: member A can delete key envelopes';
  exception when insufficient_privilege then null; end;

  -- Key envelopes (finding F2): a signed-in member must NOT be able to replace key
  -- material without the key-possession proof derived from the unlocked vault key.
  if v_has_env then
    select revision into v_revision from public.vault_key_envelopes where vault_id = v_vault and kind = 'passphrase';
    begin
      update public.vault_key_envelopes set iv = iv where vault_id = v_vault and kind = 'passphrase';
      raise exception 'FAIL: member A replaced key material without a key proof';
    exception when insufficient_privilege then null; end;
    begin
      update public.vault_key_envelopes set iv = iv, key_proof = v_wrong_proof where vault_id = v_vault and kind = 'passphrase';
      raise exception 'FAIL: member A replaced key material with a wrong key proof';
    exception when insufficient_privilege then null; end;
    begin
      insert into public.vault_key_envelopes (vault_id, kind, format_version, kdf, kdf_params, salt, iv, wrapped_key, key_verifier, key_proof)
      values (v_vault, 'recovery', 1, 'hkdf-sha256-v1', null,
              decode(repeat('00', 16), 'hex'), decode(repeat('00', 12), 'hex'), decode(repeat('00', 48), 'hex'),
              sha256(v_proof), v_proof);
      raise exception 'FAIL: member A added an envelope for a different key';
    exception when insufficient_privilege or unique_violation then null; end;
    select count(*) into v_n from public.vault_key_envelopes
      where vault_id = v_vault and kind = 'passphrase' and revision = v_revision;
    if v_n <> 1 then raise exception 'FAIL: envelope changed during proof checks'; end if;
    -- The success path needs the real vault key; it is covered by the PGlite suite and the app's Settings screen.
  else
    -- No real envelope yet: exercise the full rule set with a throwaway test proof (rolled back).
    begin
      insert into public.vault_key_envelopes (vault_id, kind, format_version, kdf, kdf_params, salt, iv, wrapped_key, key_verifier)
      values (v_vault, 'passphrase', 1, 'argon2id-v1', '{"m":65536,"t":3,"p":1}',
              decode(repeat('00', 16), 'hex'), decode(repeat('00', 12), 'hex'), decode(repeat('00', 48), 'hex'), sha256(v_proof));
      raise exception 'FAIL: envelope created without a key proof';
    exception when insufficient_privilege then null; end;

    insert into public.vault_key_envelopes (vault_id, kind, format_version, kdf, kdf_params, salt, iv, wrapped_key, key_verifier, key_proof)
    values (v_vault, 'passphrase', 1, 'argon2id-v1', '{"m":65536,"t":3,"p":1}',
            decode(repeat('00', 16), 'hex'), decode(repeat('00', 12), 'hex'), decode(repeat('00', 48), 'hex'), sha256(v_proof), v_proof);
    select count(*) into v_n from public.vault_key_envelopes
      where vault_id = v_vault and kind = 'passphrase' and created_by = v_a and revision = 1 and key_proof is null;
    if v_n <> 1 then raise exception 'FAIL: envelope audit fields not stamped, or proof persisted'; end if;

    begin
      update public.vault_key_envelopes set iv = iv where vault_id = v_vault and kind = 'passphrase';
      raise exception 'FAIL: member A replaced key material without a key proof';
    exception when insufficient_privilege then null; end;
    begin
      update public.vault_key_envelopes set iv = iv, key_proof = v_wrong_proof where vault_id = v_vault and kind = 'passphrase';
      raise exception 'FAIL: member A replaced key material with a wrong key proof';
    exception when insufficient_privilege then null; end;

    update public.vault_key_envelopes set iv = iv, key_proof = v_proof where vault_id = v_vault and kind = 'passphrase';
    get diagnostics v_n = row_count;
    if v_n <> 1 then raise exception 'FAIL: member A cannot re-wrap with the correct key proof'; end if;
    select count(*) into v_n from public.vault_key_envelopes
      where vault_id = v_vault and kind = 'passphrase' and revision = 2 and updated_by = v_a and key_proof is null;
    if v_n <> 1 then raise exception 'FAIL: envelope revision/updated_by not stamped by the server'; end if;

    begin
      insert into public.vault_key_envelopes (vault_id, kind, format_version, kdf, kdf_params, salt, iv, wrapped_key, key_verifier, key_proof)
      values (v_vault, 'recovery', 1, 'hkdf-sha256-v1', null,
              decode(repeat('00', 16), 'hex'), decode(repeat('00', 12), 'hex'), decode(repeat('00', 48), 'hex'),
              sha256(v_wrong_proof), v_wrong_proof);
      raise exception 'FAIL: member A added an envelope for a different key';
    exception when insufficient_privilege then null; end;
  end if;

  -- Folders (test rows only; rolled back).
  insert into public.media_folders (id, vault_id, encrypted_meta) values (v_folder, v_vault, decode(repeat('00', 284), 'hex'));
  select count(*) into v_n from public.media_folders where id = v_folder and created_by = v_a and depth = 0 and revision = 1;
  if v_n <> 1 then raise exception 'FAIL: folder audit fields not stamped by the server'; end if;
  insert into public.media_folders (id, vault_id, parent_id, encrypted_meta)
  values (v_subfolder, v_vault, v_folder, decode(repeat('00', 284), 'hex'));
  select count(*) into v_n from public.media_folders where id = v_subfolder and depth = 1;
  if v_n <> 1 then raise exception 'FAIL: subfolder depth not computed by the server'; end if;
  begin
    insert into public.media_folders (id, vault_id, parent_id, encrypted_meta)
    values (gen_random_uuid(), v_vault, gen_random_uuid(), decode(repeat('00', 284), 'hex'));
    raise exception 'FAIL: folder created under a non-existent parent';
  exception when foreign_key_violation then null; end;
  begin
    insert into public.media_folders (id, vault_id, encrypted_meta) values (gen_random_uuid(), v_vault, decode(repeat('00', 300), 'hex'));
    raise exception 'FAIL: malformed encrypted folder name accepted';
  exception when check_violation then null; end;

  insert into public.media_items (id, vault_id, format_version, wrapped_dek, encrypted_meta, ciphertext_size, folder_id)
  values (v_item, v_vault, 1, decode(repeat('00', 60), 'hex'), decode(repeat('00', 284), 'hex'), 100, v_folder)
  returning object_path into v_path;
  begin
    update public.media_items set trashed_at = now() where id = v_item;
    raise exception 'FAIL: a pending upload was trashed';
  exception when insufficient_privilege then null; end;
  begin
    delete from public.media_folders where id = v_subfolder;
    delete from public.media_folders where id = v_folder;
    raise exception 'FAIL: a folder holding an item was deleted';
  exception when check_violation then null; end;
  if v_path is distinct from (v_vault || '/' || v_item) then raise exception 'FAIL: unexpected object path'; end if;
  select count(*) into v_n from public.media_items where id = v_item and uploaded_by = v_a and status = 'pending';
  if v_n <> 1 then raise exception 'FAIL: media uploaded_by/status not enforced by the server'; end if;

  begin
    update public.media_items set status = 'ready' where id = v_item;
    raise exception 'FAIL: media marked ready without an uploaded object';
  exception when check_violation then null; end;

  if v_storage_writable then
    begin
      insert into storage.objects (bucket_id, name, metadata)
      values ('private-media', v_vault || '/' || gen_random_uuid(), '{"size": 100}');
      raise exception 'FAIL: member uploaded to a path with no media row';
    exception when insufficient_privilege then null; end;

    insert into storage.objects (bucket_id, name, metadata) values ('private-media', v_path, '{"size": 100}');
    update public.media_items set status = 'ready' where id = v_item;
    get diagnostics v_n = row_count;
    if v_n <> 1 then raise exception 'FAIL: uploader could not finalise the item'; end if;

    update storage.objects set name = name || 'x' where bucket_id = 'private-media' and name = v_path;
    get diagnostics v_n = row_count;
    if v_n > 0 then raise exception 'FAIL: private-media objects can be updated/moved'; end if;
  end if;

  ---------------------------------------------------------------------------
  -- Member B (shared access, same delete rule as read)
  ---------------------------------------------------------------------------
  perform set_config('request.jwt.claims', json_build_object('sub', v_b, 'role', 'authenticated')::text, true);

  select count(*) into v_n from public.media_items where id = v_item;
  if v_n <> 1 then raise exception 'FAIL: member B cannot read shared media'; end if;

  select count(*) into v_n from public.media_folders where id in (v_folder, v_subfolder);
  if v_n <> 2 then raise exception 'FAIL: member B cannot see shared folders'; end if;
  update public.media_folders set encrypted_meta = decode(repeat('01', 284), 'hex') where id = v_folder;
  select count(*) into v_n from public.media_folders where id = v_folder and revision = 2 and updated_by = v_b and created_by = v_a;
  if v_n <> 1 then raise exception 'FAIL: folder rename not stamped by the server'; end if;
  begin
    update public.media_folders set parent_id = v_subfolder where id = v_folder;
    raise exception 'FAIL: a folder was re-parented';
  exception when insufficient_privilege then null; end;

  if v_storage_writable then
    -- The item is ready: member B (not the uploader) can move, trash, and restore it.
    update public.media_items set folder_id = v_subfolder where id = v_item;
    get diagnostics v_n = row_count;
    if v_n <> 1 then raise exception 'FAIL: member B cannot move a ready item'; end if;
    update public.media_items set trashed_at = '2000-01-01' where id = v_item returning trashed_at into v_ts;
    if v_ts is null or v_ts < now() - interval '1 hour' then raise exception 'FAIL: trash time not stamped by the server'; end if;
    update public.media_items set trashed_at = null where id = v_item;
    select count(*) into v_n from public.media_items where id = v_item and trashed_at is null and status = 'ready';
    if v_n <> 1 then raise exception 'FAIL: member B cannot restore an item'; end if;
    begin
      update public.media_items set status = 'pending' where id = v_item;
      raise exception 'FAIL: a ready item went back to pending';
    exception when check_violation then null; end;
  end if;

  if v_storage_writable then
    select count(*) into v_n from storage.objects where bucket_id = 'private-media' and name = v_path;
    if v_n <> 1 then raise exception 'FAIL: member B cannot read the shared object'; end if;
    if not private.can_read_media_object('private-media', v_path) then
      raise exception 'FAIL: member B is not authorised to delete the shared object';
    end if;
  end if;

  -- Outsider again, while the row still exists: knowing the exact path grants nothing.
  perform set_config('request.jwt.claims', json_build_object('sub', v_outsider, 'role', 'authenticated')::text, true);
  if private.can_read_media_object('private-media', v_path) then
    raise exception 'FAIL: outsider is authorised for a known object path';
  end if;
  select count(*) into v_n from public.media_items where id = v_item;
  if v_n > 0 then raise exception 'FAIL: outsider can read media by id'; end if;

  perform set_config('request.jwt.claims', json_build_object('sub', v_b, 'role', 'authenticated')::text, true);
  delete from public.media_items where id = v_item;
  get diagnostics v_n = row_count;
  if v_n <> 1 then raise exception 'FAIL: member B cannot delete shared media'; end if;

  -- Empty now: folders can be deleted (child first; the parent is protected while it has subfolders).
  begin
    delete from public.media_folders where id = v_folder;
    raise exception 'FAIL: a folder with a subfolder was deleted';
  exception when foreign_key_violation then null; end;
  delete from public.media_folders where id in (v_subfolder);
  delete from public.media_folders where id in (v_folder);
  select count(*) into v_n from public.media_folders where id in (v_folder, v_subfolder);
  if v_n <> 0 then raise exception 'FAIL: member B cannot delete empty folders'; end if;

  perform set_config('role', 'none', true);
  raise exception 'HB SPACE RLS VERIFICATION PASSED — script v5 (migrations 1–5); all test changes have been rolled back.';
end
$verify$;
