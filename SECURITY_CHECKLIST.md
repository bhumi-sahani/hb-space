# HB Space — Security Checklist

Tick items only after verifying them yourself on the **real** project. A passing frontend test, or a passing
PGlite test, is **not** evidence that the hosted database or storage is configured securely.

## Repository and secrets

- [ ] `git ls-files | grep -i env` lists only `.env.example`
- [ ] No `service_role`, `sb_secret_`, database password, or passphrase anywhere in the repo or its history
- [ ] Only `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`, and `VITE_ENABLE_PASSKEYS` are set in Netlify
- [ ] GitHub, Netlify, and Supabase accounts all have 2FA enabled
- [ ] `npm audit` reports no high/critical issues (Phase 3: 0 vulnerabilities)

## Supabase Auth

- [ ] "Allow new users to sign up" is **off** (this, plus `vault_members`, is what limits access to the two accounts; the app has no email allowlist)
- [ ] Anonymous sign-ins are **off**
- [ ] Exactly two users exist, and both are confirmed (plus any temporary test user, deleted afterwards)
- [ ] Unused providers (OAuth, phone, SSO, magic link) are disabled
- [ ] Minimum password length is 12 or more
- [ ] Site URL and redirect URLs list only the production origin (plus localhost for dev)
- [ ] Sign-in with a wrong password shows only "Email or password is incorrect."

## Passkeys

- [ ] Authentication → Passkeys is enabled, with RP ID = the bare production domain
- [ ] RP origins are HTTPS (loopback allowed for dev only) and match the RP ID
- [ ] Adding a passkey asks for the account password first, and a wrong password is refused
- [ ] Passkey sign-in works on each member's phone, and cancelling the prompt shows a calm "cancelled" message
- [ ] Removing a passkey makes it stop working for sign-in

## Database and RLS (after applying migrations)

- [ ] All five migrations were applied in order, each exactly once
- [ ] `provision_vault.sql` was run with the two real User UIDs, and `vault_members` has exactly 2 rows
- [ ] `supabase/tests/rls_verification.sql` ends with **HB SPACE RLS VERIFICATION PASSED — script v5** (no `FAIL:`)
- [ ] Data API exposed schemas do **not** include `private`
- [ ] Vault tables are **not** in the `supabase_realtime` publication
- [ ] Security Advisor shows no issues for `vaults`, `vault_members`, `vault_key_envelopes`, `media_items`, `media_folders`
- [ ] No extra policies exist on these tables beyond those in the migrations:
      `select tablename, policyname, cmd, roles from pg_policies where schemaname = 'public';`

## Storage (after applying migrations)

- [ ] Bucket `private-media` is **Private** in the dashboard
- [ ] Bucket limits show MIME type `application/octet-stream` and 50 MB (or your plan's chosen limit)
- [ ] `select policyname, permissive, cmd from pg_policies where schemaname = 'storage' and tablename = 'objects';`
      shows the 4 `private-media guard:` RESTRICTIVE policies and 3 `private-media:` permissive policies, and nothing
      else you don't recognise

## Live access check (from real sessions)

- [ ] Member 1: Settings → Access check: all pass
- [ ] Member 2: Settings → Access check: all pass
- [ ] Temporary third account: Vault tab shows "No access", the access check passes, and the account is deleted
      afterwards
- [ ] Signed out: the app shows only the login screen. In DevTools, a request to `/rest/v1/media_items` with only the
      publishable key returns an error or `[]`
- [ ] After the round trip, no leftover test object remains in `private-media` and no leftover `media_items` row
      remains

## Cryptography _(Phase 3)_

Automated (`npm run check`). These do **not** prove the live project is configured correctly:

- [ ] `npm test` passes: crypto round trip, tamper/truncation/reorder/swap, wrong key/passphrase, malformed input,
      Argon2id known-answer vector, key-persistence scan, upload order and cleanup, lock behavior, RLS + F2 suite
- [ ] `npm audit` reports 0 vulnerabilities, and `hash-wasm` is pinned at exactly 4.12.0

Migration 4 on the real project (SQL editor, by the owner):

- [ ] Before applying: `select count(*) from public.vault_key_envelopes;` returns **0**. (The migration refuses to
      run otherwise. If it is not 0, stop and investigate; do not delete rows.)
- [ ] `20261022120000_vault_key_proof.sql` applied exactly once; migrations 1–3 untouched
- [ ] The updated `supabase/tests/rls_verification.sql` still ends with **HB SPACE RLS VERIFICATION PASSED**
- [ ] Security Advisor re-run: no new findings
- [ ] After vault setup: `select count(*) from public.vault_key_envelopes where key_proof is not null;` returns 0

Real browser, real project (synthetic files only, e.g. `test-image.bin`; never real photos):

- [ ] Signed in, the Vault tab shows **Set up vault encryption** (first time) or **Vault locked**, never media
- [ ] Setup: the recovery code is shown once, and nothing is stored until "I have written it down" is ticked
- [ ] A wrong passphrase shows only "Unable to unlock the vault."; the correct one shows "Vault unlocked"
- [ ] After uploading a synthetic file, the Storage object name is `<vault_id>/<uuid>` (no filename), and a
      downloaded copy starts with hex `48 42 53 01` ("HBS\x01"), not the original bytes
- [ ] The `media_items` row has no readable filename or type, and `status` is `ready`
- [ ] Opening the item shows or saves the exact original; two uploads of the same file produce different objects
- [ ] Lock Vault returns to "Vault locked" while staying signed in; the opened item disappears
- [ ] DevTools → Application: no passphrase, key, or recovery code in Local Storage, Session Storage, or IndexedDB
- [ ] Second member, on their own device: unlocks with the same passphrase and opens the first member's item
- [ ] Change passphrase: the old one fails, the new one works, earlier items still open
- [ ] The recovery code resets the passphrase and unlocks
- [ ] Settings → Access check (both members): "Cannot rewrite vault key envelopes with only a login session" passes
- [ ] Mobile viewport and a real phone: setup, unlock, upload, open, and lock are all usable
- [ ] Both members have written the recovery code down offline; nobody sent the passphrase by message or email
- [ ] Only after all of the above: passkeys tested separately (`VITE_ENABLE_PASSKEYS=true`); a passkey sign-in
      still lands on **Vault locked**

## Private media vault _(Phase 4)_

Automated (`npm run check`). These do **not** prove the live project or a real browser behave correctly:

- [ ] `npm test` passes: folder-name and thumbnail crypto, upload allow-list, thumbnails, upload queue (retry/cancel),
      folders, move, permanent delete (confirmation, partial failure), ZIP contents, routing/refresh,
      migration 5 RLS suite (incl. mutation tests), leak scans
- [ ] `npm audit` reports 0 vulnerabilities, and `fflate` is pinned at exactly 0.8.3

Migration 5 on the real project (SQL editor, by the owner):

- [ ] `20261023120000_folders_trash.sql` reviewed, then applied exactly once; migrations 1–4 untouched
- [ ] The updated `supabase/tests/rls_verification.sql` ends with **HB SPACE RLS VERIFICATION PASSED — script v5**
- [ ] Security Advisor re-run: no new findings (`media_folders` has RLS enabled)
- [ ] `select column_name from information_schema.columns where table_name = 'media_folders';` shows no name column
- [ ] Settings → Access check (both members): the folder/trash checks pass and no "Unreadable folder" is left behind

Real browser, real project (synthetic files only: generated test images and one small test video, never real media):
- [ ] Already signed-in device: opening the app shows the vault passphrase directly (no email/password form, no Sign out in the header)
- [ ] Settings → Sign out of this device → the "Sign-in needed" screen appears with no passphrase field; passkey (or Account recovery) signs back in, then the vault asks for the passphrase

- [ ] Upload several images and one small MP4 at once: each shows encrypting → uploading → done; thumbnails appear
- [ ] Storage: new objects are `<vault_id>/<uuid>` and `<vault_id>/<uuid>.t`, no names; downloaded copies start
      with hex `48 42 53 01` and do not open as JPEG/PNG/MP4
- [ ] Storage objects are not reachable signed out (private bucket; no public or signed URLs)
- [ ] `media_items`/`media_folders` rows contain no readable file or folder names (only hex blobs and ids)
- [ ] DevTools → Network during upload: only Supabase requests; request bodies contain no filename, folder name,
      or image bytes
- [ ] The video plays in the viewer (play/pause, seek, volume, fullscreen); MOV/HEVC that the browser can't play
      says so and offers download
- [ ] Viewer: swipe/arrow keys move between items; zoom works; closing returns to the grid
- [ ] Create a folder, upload into it, rename it, move an item out, delete the empty folder; a non-empty folder
      cannot be deleted
- [ ] Select all in a folder → Delete shows the exact count and names and "cannot be undone"; after confirming,
      exactly those items are gone (rows and Storage objects); other folders untouched; Cancel changes nothing
- [ ] Viewer → Delete asks first, then removes the item permanently
- [ ] Single download saves the original filename; multi-select download offers ZIP or separate files; folder
      "Download all" ZIP opens and contains subfolders by name
- [ ] Refresh on a folder and on Settings: still signed in, same page; vault asks to unlock, then returns
      to the same folder
- [ ] Lock Vault mid-session: the grid, viewer, thumbnails, and upload queue disappear
- [ ] Camera (phone, https): photo and short video upload and appear; afterwards **neither is in the phone's
      Photos/Gallery app**; the camera light turns off on Close and on Lock Vault; front/back switch works
- [ ] Camera: deny camera permission → a clear message plus "Use the device camera instead"; deny only the
      microphone → video records without sound
- [ ] Phone: grid has no horizontal scrolling; long-press selects; the selection bar sits above the tab bar; safe
      areas respected
- [ ] DevTools → Application: no passphrase, key, recovery code, file names, or thumbnails in Local/Session
      Storage or IndexedDB (only the Supabase auth session)

## Frontend and deployment _(Phase 6)_

- [ ] Site is served only over HTTPS, with HSTS present
- [ ] CSP is enforced, and the browser console shows no violations during normal use
- [ ] No third-party requests other than Supabase (check the DevTools Network tab)
- [ ] No source maps in production
- [ ] Lock and sign-out clear media from the screen, and the back button does not show decrypted media
- [ ] Tested on a small Android phone, an iPhone, a tablet, and desktop, in portrait and landscape
- [ ] Offline encrypted backup procedure documented and tested (finding F1)
- [ ] CSP allows WebAssembly only via `script-src 'self' 'wasm-unsafe-eval'` (never `'unsafe-eval'`), and vault unlock
      works under it
- [ ] `/dev/harness.html` is not present on the deployed site
- [ ] CSP allows `blob:` in `img-src` and `media-src` (thumbnails, viewer, video) and nothing broader
- [ ] `Permissions-Policy` allows `camera=(self)` and `microphone=(self)` (in-app camera) and nothing broader
