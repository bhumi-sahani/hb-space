-- HB Space — one-time vault provisioning. NOT a migration; run manually.
--
-- When: after the three migrations are applied AND both user accounts exist
--       (Authentication -> Users).
-- Where: Supabase Dashboard -> SQL Editor (runs as the project owner).
--
-- 1. In Authentication -> Users, click each of the two users and copy their
--    "User UID". (A UID is an identifier, not a secret, but don't paste it
--    into public places.)
-- 2. Replace BOTH placeholder UUIDs below. The all-zero placeholders are
--    rejected, so running this unedited does nothing.
-- 3. Run. It creates the single vault and its two members. Running it again
--    fails safely because only one vault may exist.

select private.provision_vault(
  'f19adc54-70a5-48fe-9ea8-b06185f8dfe7'::uuid,  -- member 1 User UID
  'f2e0ebd3-26bb-4763-8474-84912962bc60'::uuid   -- member 2 User UID
) as vault_id;

-- Check the result (should list exactly two rows):
-- select m.vault_id, m.user_id, u.email
-- from public.vault_members m join auth.users u on u.id = m.user_id;

-- To replace a member later (e.g. a re-created account), membership rows are
-- immutable by design; delete and re-insert in one transaction:
-- begin;
--   delete from public.vault_members where user_id = '<old uid>';
--   insert into public.vault_members (vault_id, user_id)
--     select id, '<new uid>'::uuid from public.vaults;
-- commit;
