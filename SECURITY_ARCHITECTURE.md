# HB Space — Security Architecture

Status: **Phase 4 (private media vault: gallery, encrypted thumbnails, folders, trash, local ZIP downloads, routing)
implemented and tested locally.** Phases 1–3 (migrations 1–4, encrypted upload/view) are live on the real Supabase
project and were verified there by the owner. Phase 4 adds migration 5 (`20261023120000_folders_trash.sql`), which is
**not yet applied** to the real project, and the Phase 4 UI has **not yet been exercised in a real browser against
the real project** (§12).
Sections marked _(planned)_ describe what later phases will build; they are **not implemented yet**. The table in
§12 tracks what actually exists. No part of this system is "100% secure";
this document states what it protects against and what it does not.

---

## 1. Goals

HB Space is a private photo/video vault for exactly two people.

1. Only two approved accounts can reach vault data, enforced by the database and storage server (RLS), not the UI.
2. Media and sensitive metadata are encrypted in the browser before upload. Supabase stores ciphertext only.
3. The decryption key never leaves the members' browsers in usable form.
4. Losing the vault passphrase must not silently destroy data. A recovery mechanism exists, and its limits are
   stated clearly.

## 2. Actors and trust boundaries

| Component | Trusted for | Not trusted for |
|---|---|---|
| Member's unlocked browser/device | Everything (plaintext lives here) | — |
| Supabase Auth | Identity (who is signing in) | Seeing media; holding encryption keys |
| Supabase Postgres + RLS | Enforcing who may read/write ciphertext and wrapped keys | Confidentiality of media (it only sees ciphertext) |
| Supabase Storage | Availability of ciphertext | Confidentiality or integrity (integrity is checked by AEAD in the client) |
| Netlify | Serving the app's static files | **It can serve modified JavaScript.** See §10 |
| Network | — | Everything; HTTPS required |
| Any frontend input: routes, IDs, filenames, MIME types, URLs | — | Everything |
| Server-returned rows and objects (ids, paths, sizes, bytea, ciphertext, metadata) | — | Everything until parsed strictly and, for ciphertext, until AES-GCM authentication succeeds |
| `localStorage` / `sessionStorage` / URL and query parameters | — | Holding or supplying any key material (none is ever stored there) |

## 3. Threat model

**Protects against:**

- Someone with Supabase project, database, or storage-bucket read access (including a leaked database dump or
  backup) reading photos, videos, filenames, captions, or thumbnails. They get ciphertext and wrapped keys only.
- A third authenticated Supabase user (if signup were ever accidentally enabled) reading or changing vault rows or
  objects. RLS restricts access to explicit members.
- Unauthenticated access to rows or objects. The `anon` role has no privileges, and there are no public URLs.
- Tampering with stored ciphertext, including truncating, reordering, or swapping files. AES-GCM authentication
  rejects it, and the UI shows an error rather than corrupted media.
- Offline guessing of the vault passphrase. Argon2id with memory-hard parameters makes each guess expensive,
  though a weak passphrase can still be cracked.
- Theft of a signed-out device, or one whose vault is locked. No key or plaintext is persisted.

**Does NOT protect against:**

- A compromised device, OS, or malicious browser extension. They can read the screen, memory, or keystrokes.
- Someone using a device that is **already unlocked**.
- XSS or malicious JavaScript served by the host (§10). Client-side encryption only helps while the code doing the
  encryption is honest.
- A member who chooses to share or export media.
- Traffic analysis. Ciphertext sizes, upload and download times, item counts, IP addresses, and which account acts
  when all remain visible (§8).
- Denial of service or data deletion by Supabase or by a member. **Keep your own encrypted backups.**
- Weak passphrases. Argon2id slows guessing but cannot make a short or common passphrase safe.
- Screenshots, screen recording, or the OS photo picker caching originals.

## 4. Authentication _(implemented; password login and membership verified on the real project by the owner)_

- **Supabase Auth**, email/password plus passkeys.
- **Public signup disabled** in the dashboard (Authentication → Sign In / Providers → "Allow new users to sign up"
  off). The app has no signup UI, but that is cosmetic. The dashboard setting is the real control.
- **Provisioning:** the owner creates both users in the dashboard (Authentication → Users → Add user), then runs
  `supabase/provisioning/provision_vault.sql` with their UIDs (§5).
- **Passkeys** use only APIs that exist in the pinned SDK (`@supabase/supabase-js` **2.109.0**; docs require
  ≥ 2.105.0), enabled with `createClient(..., { auth: { experimental: { passkey: true } } })`, which the app sets
  when `VITE_ENABLE_PASSKEYS=true`:
  - sign-in: `auth.signInWithPasskey()`
  - add: `auth.registerPasskey()`
  - manage: `auth.passkey.list()`, `auth.passkey.update({ passkeyId, friendlyName })` (≤ 120 chars),
    `auth.passkey.delete({ passkeyId })`

  Registration requires a signed-in user, so passkeys never create accounts. Dashboard: Authentication → Passkeys,
  with RP ID = the bare production domain and HTTPS origins (loopback excepted). Changing the RP ID invalidates every
  registered passkey. The feature is marked experimental by Supabase.
- **Step-up before adding a passkey:** Supabase only needs an active session to register a passkey. The app also
  re-checks the account password, using the session's own email, never a typed one, and confirming the returned user
  id matches. Otherwise someone holding an unlocked, signed-in phone could add their own passkey and keep access.
  This is defense in depth in the client, not a server control: a stolen session token used directly against the
  API can still call the registration endpoint.
- **Sessions:** PKCE flow, refresh tokens persisted in `localStorage` so phones stay signed in. On load, the cached
  session is re-verified with `auth.getUser()`, and a server rejection signs the device out. "Sign out of all
  devices" revokes every refresh token; existing access tokens stay valid until they expire (default 1 h).
  Trade-off: XSS or a malicious extension could steal the session token. That yields ciphertext access and the
  ability to delete (§15, finding F1), but not plaintext, because the vault key is a separate secret.
- **Error handling:** all auth and data errors map to fixed messages (`src/services/authErrors.ts`,
  `src/services/vault.ts`). Raw backend text is never shown.

### Passkeys are not encryption keys

A passkey proves possession of a credential to Supabase Auth. Its private key is non-extractable and is **never**
used as, or turned into, an AES key. Signing in with a passkey does **not** unlock the vault.

A possible future enhancement is the WebAuthn **PRF extension**, which can produce a per-credential secret able to
wrap the vault key. Supabase's SDK does not expose PRF output today. Adding it would need its own design and is out
of scope.

## 5. Authorization model _(migrations 1–4 applied on the real project; migration 5 added in Phase 4, not yet applied)_

### 5.1 Layers

1. **Grants.** Supabase's default `ALL` grants to `anon`/`authenticated` on new public tables are revoked. Only the
   needed statements are granted back, at column level where writes are involved. `anon` has **no** table
   privileges.
2. **RLS** on every exposed table, with every policy scoped `to authenticated`. No bare `true` expressions.
   Identity comes only from `auth.uid()` (the verified JWT `sub`), never from a client-supplied user id.
3. **Triggers** stamp identity and enforce state transitions server-side, so client-supplied `uploaded_by`,
   `status`, `created_by`, `revision`, and timestamps are ignored or rejected.

### 5.2 Membership

- `vaults` holds **at most one row** (a unique constant column).
- `vault_members` holds **at most two rows per vault** (trigger with a row lock against races). Rows are
  **immutable** (update raises), and clients have **no** insert, update, or delete grants. There is no role or
  admin column to escalate. Changes happen only in the SQL editor.
- `private.is_vault_member(vault_id)`: `SECURITY DEFINER`, `search_path = ''`, `stable`. It checks
  `vault_members` for `(select auth.uid())` and takes no user-id parameter. It lives in the **`private` schema,
  which is not exposed by the Data API**, so it can't be called as an RPC. (Phase 1 planned it in `public`; moved
  for this reason.)
- **No recursion:** `vault_members`' own policy is `user_id = (select auth.uid())` and calls no function. The other
  tables' policies call the definer function, which reads `vault_members` as table owner, bypassing RLS.

### 5.3 Table rules

| Table | SELECT | INSERT | UPDATE | DELETE |
|---|---|---|---|---|
| `vaults` | member | — | — | — |
| `vault_members` | own row only | — | — | — |
| `vault_key_envelopes` | member | member (crypto columns only) **+ key proof** (migration 4) | member (crypto columns only; `revision` auto-increments) **+ key proof**; `key_verifier` immutable | — |
| `media_items` | member | member, as `pending` (optionally into a folder of the same vault), `uploaded_by` forced to caller, never pre-trashed | (a) uploader only: `pending → ready`, only if the Storage object exists with the declared size (plus thumbnail if declared); (b) **m5:** any member, READY items only: `folder_id` (same-vault folder) and `trashed_at` (server-stamped) — every other column stays immutable | member |
| `media_folders` **(m5)** | member | member (`id`, `vault_id`, `parent_id`, `encrypted_meta` only; creator, depth, revision server-set; parent must be in the same vault; max 8 levels) | member, `encrypted_meta` only (rename); structure immutable; `revision` auto-increments | member, only if the folder holds no active/pending items and no subfolders |

- **Object paths are generated columns:** `object_path = vault_id/id`, `thumbnail_path = vault_id/id.t`. Clients
  cannot choose a path, and no path contains a filename.
- **Integrity/version fields:** `format_version` (must be 1) on envelopes and media, `revision` for optimistic
  concurrency on envelopes, exact byte-length checks on `salt`/`iv`/`wrapped_key`/`wrapped_dek`, 256-byte padding
  check on `encrypted_meta`, Argon2id parameter bounds (16 MiB–1 GiB, t 1–10, p = 1, no extra keys), and
  `ciphertext_size` cross-checked against Storage.
- **Key envelopes cannot be deleted** by clients, which prevents accidental lockout. Either member can re-wrap.
  This is required for passphrase changes, and see finding F2 in §15.

### 5.4 Storage (`private-media`)

- Bucket: **private**, `allowed_mime_types = ['application/octet-stream']`, `file_size_limit = 50 MiB` (the Free
  plan's per-object maximum). If the bucket already exists, the migration only tightens it.
- **Access is tied to database rows, not paths.** `private.can_read_media_object(bucket, name)` is true only if
  `name` exactly equals the `object_path` (or the `thumbnail_path`, if declared) of a `media_items` row in a vault
  the caller belongs to. `private.can_upload_media_object` additionally requires that row to be `pending` and
  uploaded by the caller. Guessing or crafting a path grants nothing. (Phase 1 planned "membership of the vault in
  the first path segment"; this is stricter.)
- **Permissive policies** (to `authenticated`): SELECT, which covers download and list, uses the read rule. INSERT,
  which covers upload, uses the upload rule. DELETE uses the read rule, so deletion needs exactly the same
  authorization as reading. There is **no UPDATE** policy: objects are write-once, with no upsert, overwrite, or
  move.
- **Restrictive guard policies** (to `public`, i.e. every role) on SELECT, INSERT, UPDATE, and DELETE apply the
  same rules to rows in `private-media` and ignore other buckets. Because restrictive policies are ANDed with all
  permissive ones, a broad policy added later (for example from a template) still cannot open this bucket. This is
  tested. `anon` needs `EXECUTE` on the two helpers for the guards to evaluate; for `anon` they always return false.
- **Delete order:** the client removes Storage objects first (the policy needs the row), then the row. A row whose
  objects are gone shows as broken and can still be deleted. Objects whose row is gone are unreadable by API roles
  and must be cleaned up in the dashboard.
- Downloads use authenticated `storage.from(...).download()`. The app creates no signed URLs (see F4).

### 5.5 Verification

- `supabase/tests/rls.test.ts` runs the real migrations on **PGlite** (Postgres 17 in WASM) with a minimal
  Supabase stub (roles, default grants, `auth.uid()`, `storage` tables). It runs 84 tests (Phase 2, migration 4, and migration 5) as `anon`, an
  authenticated outsider, a session without `sub`, and both members. It was mutation-tested: weakening a policy,
  dropping a guard, skipping the revokes, or trusting client `uploaded_by` each makes it fail. Migration 5 was
  mutation-tested the same way (dropping either folder trigger or the organise policy, removing its membership check,
  a folder read policy without membership, removing the same-vault foreign key, letting pending items move, or
  accepting a client-chosen trash time: each makes tests fail).
- `supabase/tests/rls_verification.sql` runs **in the real project's SQL editor**. It impersonates roles via
  `SET ROLE` and JWT claims, and always rolls back. The PGlite suite also executes this script.
- **In-app access check** (Settings): drives the real Data API and Storage API with the real session. Members get a
  full placeholder round trip with random bytes, cleaned up afterwards. Non-members must see nothing.
- None of these replace looking at a real project's configuration. See SECURITY_CHECKLIST.md.

## 6. Cryptography _(Phase 3: `src/lib/crypto/`, `src/services/vaultKeys.ts`, `src/services/media.ts`, live on the real project; Phase 4 additions §6.10–6.12 unit-tested, not yet verified against the real project — see §12)_

**Core rule:** Supabase Postgres and Storage never receive plaintext media, filenames, MIME types, passphrases, or
unwrapped keys. Files are encrypted in the browser before upload and decrypted in the browser after download.

```
Upload:   file ──read locally──► AES-256-GCM (per-item key) ──► ciphertext Blob ──► private-media bucket
Download: private-media ──► ciphertext ──► validate format ──► AES-256-GCM verify+decrypt ──► blob: URL (in memory)
```

### 6.1 Primitives

| Purpose | Primitive | Implementation |
|---|---|---|
| Content, metadata, key wrapping | AES-256-GCM, 96-bit IV, 128-bit tag | Web Crypto (`crypto.subtle`) |
| Per-item subkeys, recovery KEK, key proof | HKDF-SHA-256 | Web Crypto |
| Key proof verifier | SHA-256 | Web Crypto (client) / `pg_catalog.sha256` (server) |
| Passphrase → key-encryption key | **Argon2id** | `hash-wasm` **4.12.0** (pinned exactly) |
| Randomness | CSPRNG | `crypto.getRandomValues` (filled in 64 KiB slices) |

No cipher is implemented by hand. No ECB, no CBC, no deterministic encryption. Every encryption uses a fresh random
IV (or, for media chunks, a fresh random 56-bit nonce prefix under a fresh per-item key; see §6.3).

**Why `hash-wasm`:** Web Crypto has no Argon2. `hash-wasm` (MIT, zero dependencies, `npm audit` clean) runs the
reference algorithm in WebAssembly, so 64 MiB parameters take ~0.5 s rather than several seconds. A known-answer test
from the Argon2 reference implementation (`phc-winner-argon2` test vector, argon2id v19) runs in the suite and
passes. Its last release is November 2024; Argon2 is a fixed algorithm, so this is acceptable, but re-check before
upgrading. **CSP implication:** WebAssembly compilation needs `script-src 'wasm-unsafe-eval'` once a CSP is enforced
(Phase 6). That token allows WebAssembly compilation only; it does **not** allow JavaScript `eval`. Do **not** use
`'unsafe-eval'`. hash-wasm embeds its WASM inline, so no extra `connect-src` is needed.

**Argon2id parameters (v1):** `m = 65536 KiB (64 MiB), t = 3, p = 1`, 32-byte output, 16-byte random salt (RFC 9106
second recommendation with p = 1; above the OWASP minimum). Stored per envelope with a version (`kdf =
'argon2id-v1'`). Before use, the client **rejects** (never clamps or substitutes) anything outside `16 MiB ≤ m ≤ 1
GiB, 1 ≤ t ≤ 10, p = 1`, extra keys, strings, or fractions. The database enforces the same bounds. Passphrases are
NFC-normalised so the same passphrase typed on different devices derives the same key. Minimum length 12.

### 6.2 Key hierarchy

```
vault passphrase ──Argon2id(salt, params)──► KEK ──AES-GCM unwrap──┐
recovery code (128-bit) ──HKDF──────────────► RK  ──AES-GCM unwrap──┤
                                                                    ▼
                                         Vault Master Key (VMK, 256-bit random, never stored)
                                           │                                 │
                                           │ AES-GCM wrap (AAD binds item)   │ HKDF("hbspace/key-proof/v1"‖vault_id)
                                           ▼                                 ▼
                     per-item Data Encryption Key (DEK, 256-bit)      key proof ──SHA-256──► key_verifier (stored)
                                           │ HKDF-SHA-256(info = purpose ‖ item id)
                              ┌────────────┴────────────┐
                              ▼                         ▼
                      content key (chunks)       metadata key (one message)
```

- **VMK**: 32 bytes from `crypto.getRandomValues`, generated once at vault setup. Never derived from the login
  password, session token, passkey, email, user id, or filename. After unlock it is held only as a
  **non-extractable** AES-GCM `CryptoKey` (encrypt/decrypt only) in `src/services/vaultSession.ts`; raw bytes are
  zeroed right after import.
- **Authentication and encryption are separate.** Signing in (password or passkey) never touches the VMK.
  "Logged in" ≠ "vault unlocked".
- **DEK**: unique per item, so content-chunk nonces can be counters with no cross-file reuse. The VMK wraps one DEK
  per item, far below AES-GCM's 2³² random-IV limit.
- **Purpose separation**: content and metadata keys are distinct HKDF outputs, bound to the item id.

### 6.3 Formats (all integers big-endian)

**Wrapped-key envelope** (`vault_key_envelopes`, one row per `kind ∈ {passphrase, recovery}`), stored as typed
columns:

| Field | Value |
|---|---|
| `format_version` | `1` |
| `kdf` / `kdf_params` | `'argon2id-v1'` + `{m,t,p}`, or `'hkdf-sha256-v1'` + `null` (recovery) |
| `salt` | 16 random bytes, fresh on every (re)wrap |
| `iv` | 12 random bytes, fresh on every (re)wrap |
| `wrapped_key` | AES-GCM(KEK, VMK) = 32 + 16 bytes |
| `key_verifier` | SHA-256(key proof), 32 bytes (§6.7) |
| AAD | `"hbspace/vmk/v1" ‖ vault_id(16) ‖ len(kind) ‖ kind ‖ format_version` |

On unlock the client also checks that the stored verifier matches the unwrapped VMK; a mismatch fails closed.

**Media object** (Storage, at `<vault_id>/<item_id>`). STREAM construction over AES-256-GCM:

```
header (40 bytes, also the AAD of every chunk):
  magic 4 "HBS\x01" | version 1 = 0x01 | kind 1 (0x01 content, 0x02 thumbnail) | reserved 2 = 0
  chunk_size 4 = 1 MiB | nonce_prefix 7 random | reserved 5 = 0 | item_id 16
body: chunk_0 ‖ … ‖ chunk_n-1, each = AES-GCM ciphertext ‖ 16-byte tag
  nonce_i = nonce_prefix(7) ‖ uint32(i) ‖ last_flag(1)      last_flag = 1 only on the final chunk
size = 40 + 16·max(1, ⌈len/1 MiB⌉) + len
```

- Validated **before** decryption: magic, version, kind, reserved bytes, chunk size, item id = DB row id, canonical
  total length, and downloaded size = `ciphertext_size` from the row.
- Reordering, truncation, appending, and swapping objects between rows all fail (tested). An empty file is one
  final chunk (56 bytes).
- The format holds no key id: an object is decryptable only through its row's `wrapped_dek`, which the VMK unwraps.
  It never contains the passphrase, VMK, or DEK.

**Wrapped DEK** (`media_items.wrapped_dek`, 60 bytes): `iv(12) ‖ AES-GCM(VMK, DEK)`, AAD `"hbspace/dek/v1" ‖ item_id`.

**Encrypted metadata** (`media_items.encrypted_meta`): `iv(12) ‖ AES-GCM(meta_key, padded)`, AAD
`"hbspace/meta/v1" ‖ item_id`. `padded = uint32 length ‖ UTF-8 JSON ‖ zeros` to a multiple of 256 bytes (hides exact
filename length). JSON: `{v:1, name, mime, size, modified}`. `name` is cleaned (path parts, control and bidi
characters removed, ≤ 255 chars). `mime` is **sniffed from magic bytes**, never from `File.type` or the extension.
After decryption the JSON is still validated field by field.

### 6.4 Sharing between the two members

The schema's envelope key is `(vault_id, kind)`, so there is **one passphrase envelope and one recovery envelope**,
both wrapping the **same** VMK. The VMK is never stored twice and there are no separate per-member keys. Both members
use **one shared vault passphrase**, agreed in person and never sent through the app, email, or chat. Each member
unlocks independently on their own devices.

- The first member to open an empty vault creates the VMK, both envelopes, and a recovery code (shown once; nothing
  is sent until they confirm they wrote it down).
- The second member signs in and enters the same passphrase.
- **Per-member passphrases** (one envelope per member) would need a schema change (a new table or primary key), so
  they are not in Phase 3. They would not change the security of the data, since every envelope opens the same VMK:
  the benefit is only that one member could change their passphrase without the other.

### 6.5 Re-wrapping vs. rotating

- **Re-wrapping (implemented):** change passphrase, reset via recovery code, or issue a new recovery code. The
  client opens an envelope with the current secret, seals the **same** VMK under a new secret with a fresh salt and
  IV, and replaces that one row (optimistic concurrency on `revision`). **No media is re-encrypted**, and existing
  items keep working (tested).
- **Rotating the VMK (not implemented):** a new VMK would require re-wrapping every item's DEK (cheap, no media
  re-upload) and a new `key_verifier` (the migration does not allow clients to change it, so rotation needs its own
  reviewed design). It also does **not** protect ciphertext already downloaded by someone who had the old VMK; that
  needs full re-encryption. Out of scope for Phase 3.

### 6.6 Recovery and loss

- **Recovery code:** 128 random bits, shown once as 26 Crockford Base32 characters in groups of four. It wraps the
  same VMK via HKDF (no slow KDF needed for 128 random bits). It can reset the passphrase. A new code can be issued
  (requires the passphrase), and the old one stops working once the new one is confirmed.
- **If the vault passphrase AND the recovery code are both lost, all media is permanently unrecoverable.** Supabase,
  Netlify, and the developers cannot help. There is **no backdoor**, no escrowed key, and nothing is emailed or sent
  anywhere. The UI says this at setup and in Settings.
- The project owner, with dashboard access, can **delete** data but can never **decrypt** it.

### 6.7 Key-material integrity: key-possession proof (finding F2, migration `20261022120000_vault_key_proof.sql`)

Problem: under Phase 2 rules any member session, including a stolen one, could overwrite both envelopes and lock
everyone out.

Design:

- `proof = HKDF-SHA-256(VMK, salt = ∅, info = "hbspace/key-proof/v1" ‖ vault_id)` (32 bytes);
  `key_verifier = SHA-256(proof)`, stored on every envelope.
- Every INSERT or UPDATE of an envelope by a vault member must include `key_proof`. A trigger
  (`private.enforce_vault_key_proof`, `SECURITY DEFINER`, `search_path = ''`) requires `SHA-256(key_proof)` to equal the
  vault's verifier. The first envelope of a vault establishes the verifier, and must prove it. The trigger then sets
  `key_proof` to null, and a CHECK constraint guarantees it is never stored. `key_verifier` cannot be updated
  (no column grant, and the trigger refuses).
- So writing key material needs the **unlocked VMK**, not just a session. The client derives the proof only from the
  raw VMK it briefly holds while (re)wrapping, after the user re-enters the passphrase or recovery code.
- Non-members pass through the trigger untouched and are refused by the unchanged RLS policies (tested with a
  self-consistent proof, so the test proves RLS, not the trigger, stops them).
- The verifier is a hash of a 256-bit secret, so it cannot be brute-forced and reveals nothing about the VMK. The
  proof crosses the network (HTTPS) on key writes. Anyone who sees it could rewrite envelopes but still not decrypt
  anything; anyone in that position (e.g. XSS while unlocked) could take the VMK itself.
- **Remaining window:** before the vault is set up (no envelopes yet), a stolen member session could set up its own
  key first. Members would notice, because their passphrase would not unlock. Set up the vault promptly after
  applying the migration.
- Media rows are **not** gated by the proof: a stolen session can still add junk rows (shown as unreadable) or
  delete items (F1).

### 6.8 In-memory handling and locking

- The VMK is a non-extractable `CryptoKey` in a module variable (`vaultSession.ts`). It is never placed in React
  state or context, `localStorage`, `sessionStorage`, IndexedDB, URLs, or logs (tested: passphrases, the VMK, KEKs,
  DEKs, and the recovery code never appear in web storage, in anything persisted server-side, or in any request).
- Passphrase inputs are uncontrolled: read once on submit, then the form is reset. Raw key buffers are `fill(0)`'d
  after use.
- **Lock Vault** (button in the vault and in Settings; also on sign-out and on account change) drops the key
  reference, revokes every tracked `blob:` URL, and unmounts the vault view so decrypted names and media leave React
  state. The Supabase session stays signed in.
- An item opened while the vault locks is not shown (checked after download and decrypt).
- **Automatic inactivity lock is not implemented** in Phase 3, deliberately (mobile UX). Lock manually, or sign out.
- **Honest limits:** JavaScript cannot guarantee memory erasure. Strings (the typed passphrase, decrypted filenames)
  are immutable, garbage collection is non-deterministic, and the browser may keep copies (input fields, decoded
  images, the media pipeline, OS photo picker caches). Decrypted media exists only as in-memory `Blob`s and
  `blob:` URLs, never in Cache Storage or a service worker.

### 6.9 Display safety

**Phase 4 upload allow-list:** only files whose bytes sniff as JPEG, PNG, GIF, WebP, AVIF, HEIC, MP4, QuickTime, or
WebM can be uploaded; everything else (including SVG, HTML, PDF, and empty files) is refused **before** encryption.
Thumbnails are accepted, uploaded, and displayed only if they sniff as JPEG, WebP, or PNG and are at most 512 KiB.

Only sniffed JPEG, PNG, GIF, WebP, AVIF, MP4, QuickTime, and WebM are rendered in the page. Anything else, including
SVG and HTML (which could run script in a same-origin `blob:` URL), is offered only as a download typed
`application/octet-stream`. Errors are fixed generic messages ("Unable to unlock the vault.", "Unable to open this
item. …"); they never reveal whether a failure was a wrong key, tampering, malformed data, or a damaged object, and
the client never retries with another key.

### 6.10 Folders (Phase 4, migration 5)

Folders are rows of `media_folders` with a client-generated random `id`, an optional `parent_id`, and
`encrypted_meta`; nothing else describes them.

```
encrypted_meta = iv(12) || AES-256-GCM(VMK, padded JSON) || tag(16)
  AAD          = "hbspace/folder/v1" || vault_id(16) || folder_id(16)
  padded JSON  = uint32 length || {"v":1,"name":...} || zeros, to a multiple of 256 bytes (max 4096)
```

- Encrypted directly under the VMK with a fresh random IV per write (create and every rename). The number of VMK
  encryptions (item key wraps + folder writes) stays far below the 2^32 random-IV limit for AES-GCM.
- The AAD binds the blob to its vault and folder id: a blob copied onto another folder row fails authentication and
  the folder shows as "Unreadable folder".
- Names are cleaned (control, bidi-override, and slash characters removed; max 100 characters) before encryption and
  again after decryption. Padding hides name length up to ~250 bytes.
- Storage paths never involve folders: objects stay `<vault_id>/<item_id>` whatever folder an item is in. Moving
  an item changes only `media_items.folder_id` (an opaque id).
- The hierarchy (which opaque folder is inside which, and which items share a folder) is visible to the provider;
  see §8.

### 6.11 Thumbnails (Phase 4)

```
local File -> createImageBitmap / <video> frame (this browser) -> canvas <= 320 px long edge, never upscaled
  -> JPEG (quality 0.78; re-encoding drops EXIF incl. GPS) -> AES-256-GCM STREAM object, kind 0x02
  -> uploaded as <vault_id>/<item_id>.t   (thumbnail key = HKDF(DEK, "hbspace/thumbnail/v1" || item_id))
```

- Generated before encryption from the user's own file. No server-side or third-party processing, no plaintext
  preview upload, no signed or public URLs.
- The thumbnail has its **own** key (separate HKDF label) and object kind, so a content object cannot be passed off
  as a thumbnail or vice versa (tested).
- Upload order: insert `pending` row with `has_thumbnail` → upload content → upload thumbnail → mark ready (the
  server refuses `ready` until both objects exist). Any failure removes everything created.
- Thumbnail generation is optional: any decode failure, unsupported codec (e.g. HEIC outside Safari, HEVC video), or
  timeout (8 s) means "no thumbnail" and the gallery shows a generic photo/video tile. It never blocks the upload.
- The gallery downloads and decrypts only thumbnails, lazily as tiles scroll into view (at most 4 at once), into
  tracked `blob:` URLs held in a size-capped cache (240) that revokes least-recently-used entries and is disposed
  on lock/unmount. Originals are decrypted only to view or download.
- Image dimensions and video duration measured locally are stored only inside `encrypted_meta` (optional fields;
  Phase 3 items without them still decrypt).
- Existing Phase 3 items have no thumbnail. Adding one later would need a new upload (objects are write-once and
  `has_thumbnail` is immutable).

### 6.12 Video, downloads, and ZIPs (Phase 4)

- **Video playback:** ciphertext → full download (≤ 50 MiB) → authenticated decryption → `blob:` URL →
  `<video controls playsinline>`. Only the item on screen is decrypted; moving to another item, closing the viewer,
  or locking revokes the URL. Native controls provide play/pause, seek, volume, and fullscreen. Codecs the browser
  cannot play are reported as such and offered as a download.
- **Single download:** decrypt → `Blob` typed `application/octet-stream` → saved under the decrypted original
  filename (sanitised for the file system) via a temporary tracked `blob:` URL, revoked after 60 s or on lock.
- **Multiple / folder downloads:** a ZIP built locally with **fflate 0.8.3** (pinned exactly), entries stored without
  compression. Files are downloaded and decrypted **one at a time**; each file's bytes are moved into a `Blob`
  and the plaintext buffer is wiped before the next. "Download all" includes the current folder and its subfolders
  (by decrypted names), and excludes unfinished uploads. Duplicate names get " (2)"; entry names are
  sanitised so they cannot escape the archive. Items that fail to decrypt are left out and reported. Above 1 GB the
  user is warned; above 2 GB the ZIP is refused (no ZIP64, and the archive is held in browser memory). Nothing is
  uploaded; there is no server-side ZIP. Separate-file downloads are also offered (sequential, with a gap).

## 7. Data model _(migrations 1–5)_

```
vaults(id uuid pk, created_at, singleton bool unique)                          -- max 1 row
vault_members(vault_id -> vaults, user_id -> auth.users, added_at,
              pk(vault_id, user_id))                                            -- max 2 per vault, immutable
vault_key_envelopes(vault_id, kind 'passphrase'|'recovery', format_version, kdf, kdf_params jsonb,
                    salt bytea(16), iv bytea(12), wrapped_key bytea(48), revision,
                    key_verifier bytea(32) [m4], key_proof bytea (write-only, always null) [m4],
                    created_by, created_at, updated_by, updated_at, pk(vault_id, kind))
media_items(id uuid pk (client-generated), vault_id, uploaded_by, status 'pending'|'ready', format_version,
            has_thumbnail, object_path GENERATED, thumbnail_path GENERATED, wrapped_dek bytea(60),
            encrypted_meta bytea(284..65564, padded), ciphertext_size, created_at, ready_at,
            folder_id -> media_folders(vault_id, id) [m5], trashed_at [m5])
media_folders(id uuid pk (client-generated), vault_id, parent_id -> media_folders(vault_id, id), depth 0..7,
              encrypted_meta bytea(284..4124, padded), revision, created_by, created_at, updated_by, updated_at) [m5]
```

There are no plaintext names, folder names, MIME types, sizes of the original file, captions, or dimensions.
`media_items.id` is a random UUID generated on the client (`crypto.randomUUID()`) because it is bound into the
ciphertext header (AAD) before upload. A collision fails on the primary key; it never overwrites. Object paths are
`<vault_id>/<item_id>`, derived by the server (generated column) and re-derived by the client, which rejects any row
whose `object_path` differs. User input never determines a path.

**Migration 4 schema changes, and why each is needed:**

| Change | Why |
|---|---|
| `vault_key_envelopes.key_verifier bytea not null, length 32` | Server needs a non-secret commitment to the VMK to check key-possession proofs (F2). |
| `vault_key_envelopes.key_proof bytea`, CHECK `key_proof is null` | A write-only channel to submit the proof with the same INSERT/UPDATE; the constraint guarantees it is never stored. |
| Trigger `vault_key_envelopes_proof` → `private.enforce_vault_key_proof()` | Enforces the proof for members; serialises first inserts by locking the vault row (needs `SECURITY DEFINER`, since members have no UPDATE on `vaults`). |
| `grant insert (key_verifier, key_proof)`, `grant update (key_proof)` | Lets clients send these columns; `key_verifier` deliberately has no UPDATE grant. |

Nothing existing is altered or dropped; RLS policies are unchanged. The migration refuses to run (changing nothing)
if any envelope row already exists.

**Migration 5 schema changes, and why each is needed:**

| Change | Why |
|---|---|
| New table `media_folders` (RLS on; select/insert/update/delete policies all `to authenticated` + `is_vault_member`) | Private folders with opaque ids and encrypted names. |
| `unique (vault_id, id)` + composite foreign keys `(vault_id, parent_id)` and `media_items(vault_id, folder_id)` | The database itself guarantees a parent folder, or an item's folder, is in the **same** vault. |
| Trigger `media_folders_guard` → `private.guard_media_folder()` (invoker rights) | Server-stamps creator/revision/timestamps, computes depth (max 8 levels), makes structure immutable (only the encrypted name can change). |
| Trigger `media_folders_guard_delete` → `private.guard_media_folder_delete()` | Refuses deleting a folder that holds active or pending items; subfolders are protected by the foreign key. |
| `media_items.folder_id`, `media_items.trashed_at` (nullable; existing rows = root, active) | Folder placement and the trash state. |
| `on delete set null (folder_id)` | Deleting an (otherwise empty) folder moves its already-trashed items to the root, so they can still be restored. |
| `create or replace function private.guard_media_item()` | Keeps the migration-1 pending → ready logic **verbatim** and adds one branch: a READY item may change only `folder_id` and `trashed_at` (server-stamped, client value ignored); status stays `ready`. Pending items cannot be moved or trashed; inserts are forced to `trashed_at = null`. The migration-1 file is not edited. |
| Policy `members can organise ready media` (UPDATE, `using/with check (is_vault_member(vault_id) and status = 'ready')`) | Lets either member (not only the uploader) move/trash/restore finished items. Pending rows stay governed only by the existing uploader policy. |
| `grant insert (folder_id)`, `grant update (folder_id, trashed_at)` on `media_items`; folder grants as above | Column-level: nothing else becomes writable. |

No existing policy, grant, or Storage rule is dropped or altered; no data is rewritten. Deletion rules are unchanged.

**Upload order (implemented, `src/services/media.ts`):** size check → real type from magic bytes (allow-list) →
require unlocked vault → random item id → local thumbnail (optional) → encrypt content, metadata, and thumbnail
locally (fresh DEK, IVs, nonce prefixes) → insert `pending` row (opaque `folder_id`, `has_thumbnail`) → upload
content ciphertext → upload thumbnail ciphertext → set `status = 'ready'` (server verifies the stored object size
and the thumbnail) → wipe plaintext buffers. Lock and cancel are checked before every network step; on any failure
or cancel the client removes what it created. The client never uploads before encrypting; there is no plaintext
upload path. Multi-file uploads run through a queue strictly one file at a time (`src/services/uploadQueue.ts`).

**Download order:** require unlocked vault → row already fetched and strictly parsed → download object → length
must equal `ciphertext_size` → validate header → authenticated decryption of every chunk → re-sniff type →
`blob:` URL (tracked, revoked on close and on lock). Any failure gives one generic error and shows nothing.

## 8. Metadata that remains visible to providers

Even with all of the above, Supabase and Netlify can observe:

- Ciphertext sizes (≈ plaintext size + 56 bytes + 16 bytes/MiB), so roughly whether an item is a photo or a long
  video.
- Item count, upload and delete timestamps, and which member uploaded each item (`uploaded_by`).
- Sign-in times, IP addresses, user agents, and access patterns (what is downloaded and when).
- Member email addresses (Supabase Auth).
- That a thumbnail exists for an item, and its approximate size.
- **Phase 4:** the folder tree **shape** (how many folders, which opaque folder is inside which, nesting depth),
  which items share a folder, folder creation/rename times and who did them, which items are in the trash and since
  when, and when items are moved or restored. Folder names and file names are not visible.

## 9. File handling rules _(Phase 4)_

- The whole file is encrypted. Maximum plaintext is **49 MiB** so the ciphertext stays under the 50 MiB bucket limit.
- Uploads are restricted to photos and videos by their **bytes** (§6.9); extensions and `File.type` are ignored.
  The type is re-sniffed after decryption before anything is rendered.
- Thumbnails are generated and encrypted in the browser (§6.11). No plaintext preview ever leaves the device.
- Each upload still holds the whole file, its ciphertext, and (briefly) a decoded image in memory, roughly 2–3× the
  file size at peak. Chunked streaming encryption/decryption (and larger videos) is deferred to Phase 5.
- Logging never includes filenames, folder names, keys, passphrases, or content. The crypto layer throws one fixed
  error type; the UI shows fixed generic messages.

## 10. Frontend and hosting security _(headers: planned, Phase 6)_

The biggest residual risk in browser end-to-end encryption is **code delivery**. Whoever controls the served
JavaScript (Netlify account, GitHub repo, npm dependencies, a successful XSS) can capture passphrases. Mitigations:

- Strict CSP (draft below), no third-party scripts, analytics, fonts, or CDNs.
- React escaping only, with no `dangerouslySetInnerHTML`.
- Minimal and pinned dependencies, `npm audit` in the checklist, and 2FA on the GitHub and Netlify accounts.
- No production source maps.

Draft headers (to be tested on a Netlify deploy preview before enforcing):

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
  img-src 'self' blob: data:; media-src 'self' blob:; font-src 'self';
  connect-src 'self' https://<project-ref>.supabase.co wss://<project-ref>.supabase.co;
  manifest-src 'self'; worker-src 'self' blob:; base-uri 'none'; form-action 'self';
  frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Frame-Options: DENY
Cache-Control (index.html): no-store
```

## 11. Configuration safety (implemented)

- Only `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`, and `VITE_ENABLE_PASSKEYS` are read. All are public by
  nature.
- `src/config/env.ts` **refuses to start** if the key is an `sb_secret_…` key or a JWT whose role is not `anon`, if
  the URL is not HTTPS (loopback excepted), or if the URL carries a path or credentials. Error messages never echo
  values.
- `.env*` files are git-ignored, except `.env.example`, which contains names only.

## 12. Implementation status

| Area | Status |
|---|---|
| Config validation (fail-closed on secret keys) | ✅ Implemented + unit tested |
| Sign-in: normal flow is existing session → vault passphrase; "Sign-in needed" screen only without a valid session (passkey, or password under "Account recovery"); no signup | ✅ Implemented + tests; ⏳ new screen not yet tried on the real project |
| Session verification with server, sign-out (this device / all devices) | ✅ Implemented; Phase 4: only a definite "session invalid" answer signs out on load |
| Passkey sign-in, add (with password step-up), rename, remove | ✅ Implemented; `VITE_ENABLE_PASSKEYS=false`; ⏳ live passkey test |
| Migrations 1–4 | ✅ Applied on the real project (owner) |
| Migration 5: folders, trash, organising | ✅ Written; ✅ 22 new PGlite tests incl. mutation tests; ⏳ **not yet applied to the real project** |
| SQL-editor verification script | ✅ Updated for migration 5; passes on PGlite with and without key envelopes; ⏳ re-run on the real project after migration 5 |
| In-app access check | ✅ New harmless Phase 4 probes (folder create/re-parent, trash/restore, organise cannot change ciphertext, non-empty folder delete refused); ⏳ re-run on the real project |
| Phase 3 crypto, vault setup/unlock/lock, encrypted upload/view | ✅ Implemented; ✅ live on the real project (owner) |
| Encrypted thumbnails, video thumbnails | ✅ Implemented + unit/service tests (synthetic files); ⏳ real browser (canvas/video decoding cannot run in the test DOM) |
| Gallery grid, full-screen viewer, video playback | ✅ Implemented + component tests; ⏳ real browser + real project |
| Multi-file upload queue (retry, cancel) | ✅ Implemented + tests |
| Folders (create, rename, browse, delete-if-empty, move items) | ✅ Implemented + tests |
| Multi-select, select all, permanent delete with confirmation (no trash, owner decision) | ✅ Implemented + tests |
| Single / multiple / folder downloads, local ZIP | ✅ Implemented + tests (ZIP contents verified by unzipping) |
| Hash routing, refresh behaviour | ✅ Implemented + tests |
| Real-browser test of Phase 4 (desktop, mobile viewport, phone; real small video) | ⏳ **Not done** (see the report and SECURITY_CHECKLIST.md) |
| Security headers / CSP (needs `'wasm-unsafe-eval'`, `img-src blob:`, `media-src blob:`) | ⏳ Phase 6 |

## 13. Phase 4 security notes

- **No vault passphrase rules** (owner decision, 2026-10-26). Any non-empty passphrase is accepted; the earlier
  12-character minimum was removed. The "repeat passphrase" match check stays (it prevents typos, not weak choices).
  **Risk:** the passphrase is the only protection of the vault key if the database or a backup is ever copied
  (provider breach, leaked dump). Argon2id (64 MiB, t=3) slows guessing, but a short or common passphrase can still be
  found offline in hours or less, and then every photo can be decrypted. A long passphrase (several unrelated words)
  remains strongly recommended.
- **No login form in the normal flow** (owner decision, 2026-10-23). Each device signs in once and keeps its
  Supabase session (persisted, auto-refreshed); opening the app goes straight to the vault passphrase. Without a
  valid session the app shows only a minimal "Sign-in needed" screen: passkey sign-in, and the account password
  behind "Account recovery". There is **no passphrase-only path**: vault rows and objects are reachable only with an
  authenticated session that RLS accepts as a vault member, and the passphrase only decrypts what RLS returns.
  The header and lock-screen "Sign out" buttons were removed; signing out is in Settings. Nothing in the frontend
  decides who is authorized: there is **no email allowlist** in the app. The two accounts are the only ones
  because sign-ups are disabled in Supabase Auth and membership rows exist only for them (`vault_members`, RLS).
  Trade-off: a device that stays signed in relies on the device lock plus the vault passphrase; use "Sign out of all
  devices" if a phone is lost.

- **No trash; Delete is always permanent** (owner decision, 2026-10-23, replacing the earlier Trash design). Delete
  in the gallery, the selection bar, and the viewer destroys the encrypted objects and then the row, after a
  confirmation that states the exact count, lists the names, and says it cannot be undone. **There is no undo and no
  recovery in the app: a mistaken confirmation loses the media for both members. Keep offline encrypted backups.**
  Deletion is membership-authorized, so a **stolen member session can also delete** via the API (finding F1). A
  key-proof requirement for deletion (like F2) remains possible later.
- **Migration 5's trash columns are unused, not removed** (`trashed_at`, its grant and guard branch stay; the
  applied migration is not edited). The app ignores `trashed_at`: items trashed by the earlier version show up again
  in the gallery, where they can be deleted permanently.
- **A stolen session can also organise:** move items (or set the unused trash flag), create/rename/delete empty folders, and
  overwrite a folder's encrypted name with junk (it then shows as "Unreadable folder"). None of this reveals or
  destroys media. Folder writes do not require the key proof (owner decision).
- **Folder structure metadata** is visible to the provider (§8). Names are not.
- **Unfinished uploads** older than an hour are offered for removal in a notice at the vault root (same permanent-delete
  confirmation). Younger ones are left alone: they may still be uploading on the other member's device.
- **Video thumbnails** are made by playing the file in a local, muted, off-screen `<video>` from a short-lived
  `blob:` URL; nothing leaves the device.
- **Memory:** viewing or zipping decrypts into JavaScript memory; ZIPs are capped at 2 GB. Phones may fail earlier.
- **Routing:** the URL contains only opaque ids. A refresh never restores the vault key: the unlocked state is
  memory-only by design, so the user unlocks again and lands on the same folder.
- **Refresh fix:** previously any 4xx from the Auth server on page load (including 429 rate limits and transient
  token-refresh races) signed the user out. Now only 401/403 or explicit invalid-session codes do; otherwise the app
  keeps the session and shows the offline notice. Data access is still authorized by the server on every request.
- **CSP (Phase 6)** must allow `blob:` for `img-src` and `media-src` (thumbnails, viewer, video) — already in
  the draft in §10.
- **In-app camera:** photos and videos are captured from a `getUserMedia` stream inside the page and handed to the
  same encrypted upload queue as chosen files. They exist only in this tab's memory until encrypted. The device
  camera app is not involved, so nothing is written to the phone's gallery, and photos (drawn from the video frame
  onto a canvas) carry no EXIF or GPS data. Camera and microphone are released when the camera closes, the lens or
  mode changes, or the vault locks; a recording in progress when the vault locks is discarded. Recording stops
  automatically below the upload size limit. The camera needs a secure context (https or localhost); otherwise, or if
  access is refused, the user may choose the **device camera** fallback (`<input capture>`), which opens the
  phone's own camera app. Some camera apps may keep their own copy, and the UI says so. **Permissions-Policy
  (Phase 6)** must allow `camera=(self)` and `microphone=(self)` and nothing broader.

## 14. Phase 3 security notes

**Residual concerns:**

- **Code delivery is still the biggest risk** (§10). Whoever can change the served JavaScript can capture the
  passphrase. CSP and headers are Phase 6.
- **Shared passphrase:** if it leaks from either member, the vault is exposed; change it and consider VMK rotation.
- **Setup race (§6.7):** before first setup, a stolen member session could install its own key. Set the vault up
  promptly.
- **Unlocked device = full access.** No automatic inactivity lock yet.
- **Memory:** JavaScript cannot erase secrets reliably (§6.8).
- **F1 (deletion by a stolen session) and F3 (junk rows)** are unchanged.
- **Metadata visible to the provider** (§8) is unchanged: ciphertext sizes, counts, timestamps, uploader id.

## 15. Phase 2 security review

Reviewed: every policy, grant, trigger, and helper in `supabase/migrations/`. "Tested" means covered by
`supabase/tests/rls.test.ts` on PGlite, which is not yet a real project.

| Question | Result |
|---|---|
| Privilege escalation via RLS? | None found. Members have no write path to `vault_members` (no grants, immutable rows, no role column). Policies never read `user_metadata`/`raw_user_meta_data`, which users can edit. Definer functions use `search_path = ''`, live in the non-exposed `private` schema, and take no user-id argument. `provision_vault` is not executable by API roles (tested). |
| Recursive RLS? | None. `vault_members` policy calls no function. Other policies call definer helpers that read as owner (tested by every member query). |
| Access other records by changing an ID or path? | No. Every row rule is membership of the row's own `vault_id`. Storage names must equal a server-generated path of a row in the caller's vault. A random path in the right folder, a filename-like path, a thumbnail path on an item without a thumbnail, or the same name in another bucket are all refused (tested). |
| Authenticated but unapproved user? | Zero rows from every table, no Storage visibility, and all writes refused (tested as outsider and as a session with no `sub`). Reachable in the real project only if signup is re-enabled or someone creates a user. Even then, still no access. |
| Storage separately from DB rows? | Separate policies on `storage.objects`, tested independently: outsider, anon, and wrong-member uploads; outsider and anon reads; updates or moves; deletes. |
| Delete authorization equals read? | Yes. DB: `is_vault_member` for both. Storage: the same `can_read_media_object` predicate for SELECT and DELETE (tested). |
| Inserting media metadata cannot create unauthorized records? | Insert requires membership of the target vault. `uploaded_by`, `status`, and paths are server-controlled, and byte lengths are checked (tested, including spoofed `uploaded_by`/`status`/`object_path`). |
| Vault-key metadata replaced by an unauthorized user? | No. Outsiders can't read, insert, or update. Envelopes can't be deleted or moved to another vault, and audit fields are server-stamped (tested). |
| Policy combinations broader than intended? | Public tables have only these policies. The verification script fails if any of them has a bare `true` or is not scoped to `authenticated`. Storage is protected against future broad policies by the restrictive guards (tested with a deliberately added `using (true)` policy). |

**Findings and residual risks:**

- **F1 — Stolen session = destructive power.** A stolen or leaked session token, for example via XSS, lets the
  holder delete media and objects. It cannot read plaintext. Mitigations: CSP (Phase 6), short JWT expiry, and
  "sign out of all devices". **Keep offline encrypted backups.** There is no trash (owner decision, §13): every
  Delete in the app is permanent, so accidental deletes are not recoverable either.
- **F2 — Either member, or a stolen member session, could overwrite both key envelopes**, locking everyone out.
  **Addressed in Phase 3** by migration 4 (§6.7): envelope writes now require a key-possession proof derived from
  the unlocked VMK. Effective only once migration 4 is applied to the real project.
- **F3 — Pending-row spam.** A member can create unlimited `pending` rows or objects within the bucket size limit.
  Accepted: only two trusted members can do this.
- **F4 — Signed URLs.** Any member session can ask Storage for a signed URL to an object it can read. That is a
  bearer link to **ciphertext** only. The app never creates them. Newer Storage versions offer operation-scoped
  policy helpers that could block signing; this is not used yet because availability varies by project.
- **F5 — Real Storage internals.** The design assumes the Storage service checks only INSERT for non-upsert
  uploads, SELECT for download and list, and SELECT + DELETE for remove, and that it writes object metadata
  (`size`) itself. This matches Supabase's docs, but **must be confirmed** by the in-app access check on the real
  project. If uploads are unexpectedly refused there, the UPDATE guard and the size check are the first places to
  look.
- **F6 — Membership is visible to the server operator.** Supabase can see which two accounts are members, as with
  all metadata in §8.
- **F7 — Passkey API is experimental.** Supabase may change it, so the SDK is pinned exactly. Re-test passkeys after
  any SDK upgrade.
