# HB Space ❤️

A private, two-person photo and video vault. Media is encrypted in the browser before upload. The server
stores ciphertext only, and two layers of server-side checks (Supabase Auth plus Row Level Security) restrict who
can reach even that.

> **Current status: Phase 4 (private media vault).** Gallery with encrypted thumbnails, full-screen viewer and video
> playback, multi-file uploads, private folders (encrypted names), multi-select, permanent delete (with confirmation; there is no trash), and local ZIP
> downloads. Phases 1–3 are live on the real project. Phase 4 needs **one new migration** (migration 5, step 6
> below) and has **not yet been verified in a real browser against the real project**. Until that is done, use
> **synthetic test files only** for Phase 4 features. See
> [SECURITY_ARCHITECTURE.md §12](SECURITY_ARCHITECTURE.md#12-implementation-status).

- [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md): threat model, key management, data formats, RLS design,
  Phase 2 review
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md): setup, verification, and release checklist

## Stack

React 19 + TypeScript + Vite · Supabase (Auth, Postgres + RLS, private Storage) · Web Crypto AES-256-GCM ·
Netlify (static hosting). No custom backend server.

## Project layout

```
src/
  config/env.ts                 Validated public config; refuses secret keys
  lib/supabase.ts               The single browser Supabase client
  services/auth.ts              Sign-in (password, passkey), sign-out, server session check
  services/authErrors.ts        Maps errors to fixed, non-leaky messages
  services/passkeys.ts          Passkey list/add (with password step-up)/rename/remove
  services/vault.ts             Vault membership lookup (UI hint; RLS enforces)
  services/accessSelfTest.ts    Live authorization probes run from Settings
  lib/crypto/                   AES-256-GCM object format, key envelopes, Argon2id, metadata, type sniffing
  services/vaultSession.ts      In-memory unlocked key (non-extractable) + lock + blob: URL tracking
  services/vaultKeys.ts         Vault setup, unlock, change passphrase, recovery code
  services/vaultBackend.ts      Supabase boundary; strict parsing of server rows
  services/media.ts             Encrypted upload (type allow-list, thumbnails) / list / open / move / permanent delete
  services/folders.ts           Folders with encrypted names (create, rename, delete-if-empty)
  services/uploadQueue.ts       Sequential multi-file upload queue (retry, cancel)
  services/thumbnailLoader.ts   Lazy, size-capped decryption of encrypted thumbnails for the gallery
  services/downloads.ts         Single/multiple downloads and local ZIPs (fflate, store only)
  lib/media/thumbnails.ts       In-browser thumbnail generation (image + video frame), never uploaded unencrypted
  lib/media/camera.ts           In-app camera helpers (photo/video capture straight into the encrypted upload)
  lib/router.ts                 Hash router (#/, #/folder/<id>, #/settings); opaque ids only
  services/testing/             In-memory backend that enforces the server rules (tests + dev harness)
  hooks/                        useAuth, useMembership, useVaultStatus
  components/ui.tsx             Buttons, fields, alerts, icons
  screens/                      Login, shell, vault (setup / locked / gallery / viewer / camera), settings
  dev/harness.tsx               DEV ONLY: real UI + crypto against the in-memory backend (/dev/harness.html)
  styles/global.css             Dark, mobile-first theme
supabase/
  migrations/                   Version-controlled SQL, applied in filename order
  provisioning/provision_vault.sql   One-time: create the vault with the two members
  tests/rls.test.ts             RLS/Storage policy tests on PGlite (runs in `npm test`)
  tests/rls_verification.sql    Same checks for the REAL project's SQL editor (always rolls back)
```

## Local setup

Requires Node 20+.

```bash
npm install
cp .env.example .env.local     # then fill in values (never commit this file)
npm run dev
```

Environment variables (all are **public**, compiled into the bundle):

| Variable | Value |
|---|---|
| `VITE_SUPABASE_URL` | `https://<project-ref>.supabase.co` |
| `VITE_SUPABASE_PUBLISHABLE_KEY` | Publishable key (`sb_publishable_…`) or legacy anon key |
| `VITE_ENABLE_PASSKEYS` | `true` once passkeys are enabled in the dashboard |
| `VITE_STORAGE_LIMIT_GB` | Optional. Your plan's file-storage quota in GB for the gallery's "used of total" display (default `1`, the Free plan). Display only. |

**Never** put a `service_role`/`sb_secret_` key, database password, vault passphrase, recovery code, or any
encryption key in any `VITE_*` variable or file. The app detects privileged keys and refuses to start. Keep
`VITE_ENABLE_PASSKEYS=false` until the encrypted vault has been verified (checklist).

**Dev harness:** with `npm run dev`, open `/dev/harness.html` to try setup, unlock, upload (with real thumbnail
generation), folders, permanent delete, the viewer, and ZIP downloads in a real browser with real Web Crypto, against an
in-memory fake backend (no network, nothing persisted, reload to reset). It is not part of the production build.

## Scripts

| Command | Purpose |
|---|---|
| `npm run dev` | Dev server |
| `npm test` | Unit/component tests **and** the PGlite RLS suite |
| `npm run lint` / `npm run typecheck` | ESLint / TypeScript |
| `npm run build` | Production build to `dist/` |
| `npm run check` | All of the above |

## Supabase setup (manual dashboard steps)

Do these in order. Nothing in this repository changes your remote project automatically.

### 1. Project and keys

1. Create a Supabase project. Store the **database password** in a password manager, never in this repo.
2. **Project Settings → API Keys:** copy the **Project URL** and the **publishable** key into `.env.local` (and later
   into Netlify). Do **not** copy the secret or `service_role` key anywhere.

### 2. Authentication

3. **Authentication → Sign In / Providers**
   - **Allow new users to sign up: OFF**
   - **Allow anonymous sign-ins: OFF**
   - **Email** provider: enabled. Under its password settings, set the minimum length to **12+**.
   - Every other provider (OAuth, phone, SSO): disabled.
   - If available on your plan, enable leaked-password protection.
4. **Authentication → Users → Add user → Create new user**, twice: email, a strong unique password, and
   **Auto Confirm User** ticked. Copy each user's **User UID**.
5. **Authentication → URL Configuration:** Site URL = your production URL (e.g. `https://<site>.netlify.app`).
   Redirect URLs: the production URL and `http://localhost:5173`.

### 3. Database schema, RLS, Storage

6. **SQL Editor:** open each file in `supabase/migrations/` **in filename order**, paste it, and run it once:
   1. `20261021120000_vault_schema.sql`
   2. `20261021120100_vault_rls.sql`
   3. `20261021120200_storage_private_media.sql`
   4. `20261022120000_vault_key_proof.sql` _(Phase 3, additive. If 1–3 are already applied, run only this one.
      First check `select count(*) from public.vault_key_envelopes;` is 0; the file refuses to run otherwise.)_
   5. `20261023120000_folders_trash.sql` _(Phase 4, additive: folders, trash, moving. Safe with existing media and
      keys; existing items stay at the root. If 1–4 are already applied, run only this one. **Apply it before
      deploying the Phase 4 app**: the Phase 4 app reports "not set up for this version" until it exists.)_

   They only create objects (the bucket statement can only make an existing `private-media` bucket stricter).
   Re-running one fails with "already exists" rather than changing data. If you later install the Supabase CLI,
   `supabase link` + `supabase db push` applies the same files.
7. **Storage:** confirm `private-media` is listed as **Private**. Never toggle it public.
8. **SQL Editor:** open `supabase/provisioning/provision_vault.sql`, replace both placeholder UUIDs with the two User
   UIDs, and run it.
9. **SQL Editor:** paste and run `supabase/tests/rls_verification.sql`. It must end with
   `ERROR: HB SPACE RLS VERIFICATION PASSED — script v5 (migrations 1–5); all test changes have been rolled back.` The "ERROR" is intentional:
   it is how the script undoes its test writes. If the message lacks "script v5", an old copy was run: paste the file fresh. Any message starting `FAIL:` means stop and investigate.
10. **Project Settings → Data API:** exposed schemas must be `public` (and `graphql_public`) only. **Never** add
    `private`.
11. **Database → Publications:** the vault tables must **not** be in `supabase_realtime`.
12. **Advisors → Security Advisor:** run it and resolve anything it reports for these tables.

### 4. Passkeys (optional)

13. **Authentication → Passkeys:** enable, then set:
    - Relying Party Display Name: `HB Space`
    - Relying Party ID: the bare production domain, e.g. `<site>.netlify.app` (no scheme, port, or path). Use
      `localhost` only for local-only testing. **Changing the RP ID later invalidates every registered passkey.**
    - Relying Party Origins (comma-separated, max 5): e.g. `https://<site>.netlify.app`. Each must be HTTPS,
      except loopback (`http://localhost:5173`), and must match or be a subdomain of the RP ID.
14. Set `VITE_ENABLE_PASSKEYS=true`, rebuild, sign in with email/password, then **Settings → Passkeys → Add a
    passkey**. You'll be asked for your account password first.

Passkeys sign you in. They do **not** unlock the vault; that needs the separate vault passphrase.

### 5. Verify from real sessions

15. Sign in as **each** member → **Settings → Access check → Run access check**. All checks must pass. As a member,
    this uploads, downloads, and deletes a 64-byte file of random bytes.
16. Create a temporary **third** user (step 4), sign in as them, and confirm the Vault tab says "No access to this
    vault" and the access check passes. Then **delete that user**.

### 6. Set up vault encryption (once, after migration 4)

17. Agree on a **vault passphrase** together, in person (any length is accepted; a longer one, such as four or more unrelated words, is much harder to guess). It
    is not your login password. Never send it by message or email.
18. One member signs in → **Vault** → **Set up vault encryption** → enter the passphrase twice. A **recovery code**
    is shown once: write it on paper and store it offline. Tick the box and **Finish setup**. Nothing is saved until
    then.
19. The other member signs in on their own device and unlocks with the same passphrase.
20. Run **Settings → Access check** again as each member; "Cannot rewrite vault key envelopes with only a login
    session" must pass.
21. Work through the Phase 3 section of [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md) with **synthetic** files
    before uploading anything real.

### 7. Phase 4 (after migration 5)

22. Re-run `supabase/tests/rls_verification.sql` (it now also checks folders and trash) and the Security Advisor.
23. Sign in as each member → **Settings → Access check**: the new folder/trash checks must pass, and the test folder
    is removed afterwards.
24. Work through the Phase 4 section of [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md) with **synthetic** images and
    one small synthetic video before using it for real media.

## Account recovery

- **Forgotten login password:** the owner sends a reset from the Supabase dashboard (Authentication → Users).
- **Lost passkey device:** sign in with email/password and remove that passkey in Settings. Use "Sign out of all
  devices" if a phone is lost.
- **Vault passphrase:** separate from login. Change it in **Settings → Vault security** (needs the current one). The
  vault key is unchanged, so nothing is re-encrypted; tell the other member the new passphrase in person.
- **Forgotten vault passphrase:** on the locked screen, choose "Use the recovery code" and set a new passphrase.
- **Recovery code:** shown once at setup. A replacement can be created in Settings (needs the passphrase).
- **If both the vault passphrase and the recovery code are lost, the media cannot be recovered by anyone**, including
  the developers and Supabase. There is no backdoor and no copy of the key anywhere.

## Deployment (Netlify)

Planned for Phase 6 (`netlify.toml` with security headers and CSP). For now: build command `npm run build`, publish
directory `dist`, and set the three `VITE_*` variables in Site settings → Environment variables.
