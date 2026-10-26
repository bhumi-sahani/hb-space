import type { SupabaseClient } from '@supabase/supabase-js'
import { fromByteaHex, isUuid, toByteaHex } from '../lib/crypto/bytes'
import { isWellFormedEnvelope, PROOF_BYTES, type SealedEnvelope, type StoredEnvelope } from '../lib/crypto/envelope'
import { parseArgon2Params } from '../lib/crypto/kdf'
import { HEADER_BYTES } from '../lib/crypto/mediaFormat'
import { GCM_TAG_BYTES } from '../lib/crypto/primitives'
import { META_BLOCK, META_MAX_PADDED, WRAPPED_DEK_BYTES } from '../lib/crypto/item'
import { isValidFolderMetaLength } from '../lib/crypto/folder'

/**
 * Narrow boundary between vault logic and Supabase. Everything that crosses it
 * toward the server is ciphertext or non-secret parameters; everything coming
 * back is treated as untrusted and validated before use.
 */

export const MEDIA_BUCKET = 'private-media'
/** Bucket file_size_limit (migration 3): 50 MiB. */
export const BUCKET_OBJECT_LIMIT = 52428800

export type BackendErrorKind = 'not-set-up' | 'network' | 'conflict' | 'denied' | 'not-empty' | 'generic'

export class BackendError extends Error {
  readonly kind: BackendErrorKind
  constructor(kind: BackendErrorKind) {
    super(`vault backend error: ${kind}`)
    this.name = 'BackendError'
    this.kind = kind
  }
}

export interface MediaRecord {
  id: string
  vaultId: string
  status: 'pending' | 'ready'
  uploadedBy: string | null
  wrappedDek: Uint8Array<ArrayBuffer>
  encryptedMeta: Uint8Array<ArrayBuffer>
  ciphertextSize: number
  createdAt: string
  /** Phase 4: opaque folder id (null = root), trash state, encrypted thumbnail present. */
  folderId: string | null
  trashedAt: string | null
  hasThumbnail: boolean
}

export interface NewMediaRow {
  id: string
  vaultId: string
  wrappedDek: Uint8Array
  encryptedMeta: Uint8Array
  ciphertextSize: number
  folderId: string | null
  hasThumbnail: boolean
}

export interface FolderRecord {
  id: string
  vaultId: string
  parentId: string | null
  depth: number
  encryptedMeta: Uint8Array<ArrayBuffer>
  revision: number
  createdAt: string
  updatedAt: string
}

export interface NewFolderRow {
  id: string
  vaultId: string
  parentId: string | null
  encryptedMeta: Uint8Array
}

/** Largest encrypted thumbnail object accepted on download (thumbnail cap + format overhead). */
export const MAX_THUMBNAIL_OBJECT = 512 * 1024 + 4096
/** Maximum folder nesting (server enforces depth 0..7). */
export const MAX_FOLDER_DEPTH = 7

export interface VaultBackend {
  listEnvelopes(vaultId: string): Promise<StoredEnvelope[]>
  /** `proof` is checked server-side against the verifier and never stored. */
  insertEnvelope(vaultId: string, envelope: SealedEnvelope, keyVerifier: Uint8Array, proof: Uint8Array): Promise<void>
  /** Optimistic concurrency: fails with 'conflict' unless the stored revision equals expectedRevision. */
  updateEnvelope(vaultId: string, envelope: SealedEnvelope, proof: Uint8Array, expectedRevision: number): Promise<void>
  insertPendingMedia(row: NewMediaRow): Promise<void>
  uploadObject(path: string, ciphertext: Uint8Array<ArrayBuffer>): Promise<void>
  markReady(id: string): Promise<void>
  /** Every media row of the vault (fetched in pages; not capped at the API's row limit). */
  listMedia(vaultId: string): Promise<{ records: MediaRecord[]; damaged: number }>
  /** `maxBytes` bounds what is accepted; larger objects fail without being kept. */
  downloadObject(path: string, maxBytes?: number): Promise<Uint8Array<ArrayBuffer>>
  deleteObject(path: string): Promise<void>
  /** Removes several objects in one request (e.g. content + thumbnail). */
  deleteObjects(paths: string[]): Promise<void>
  deleteMedia(id: string): Promise<void>
  /** Moves READY items. Returns the ids the server actually updated. */
  setMediaFolder(vaultId: string, ids: string[], folderId: string | null): Promise<string[]>
  /** Trashes or restores READY items. Returns the ids the server actually updated. */
  setMediaTrashed(vaultId: string, ids: string[], trashed: boolean): Promise<string[]>
  listFolders(vaultId: string): Promise<{ records: FolderRecord[]; damaged: number }>
  insertFolder(row: NewFolderRow): Promise<void>
  /** Optimistic concurrency on rename: 'conflict' unless the stored revision matches. */
  updateFolderMeta(vaultId: string, id: string, encryptedMeta: Uint8Array, expectedRevision: number): Promise<void>
  /** 'not-empty' if the folder still holds active/pending items or subfolders. */
  deleteFolder(vaultId: string, id: string): Promise<void>
}

/** Object names are derived locally from validated ids, never taken from the server or user input. */
export function objectPathFor(vaultId: string, itemId: string): string {
  if (!isUuid(vaultId) || !isUuid(itemId)) throw new BackendError('generic')
  return `${vaultId}/${itemId}`
}

/** Encrypted thumbnail object: same opaque name plus ".t" (matches the server's generated column). */
export function thumbnailPathFor(vaultId: string, itemId: string): string {
  return `${objectPathFor(vaultId, itemId)}.t`
}

// ---------------------------------------------------------------------------
// Row parsing (untrusted input)
// ---------------------------------------------------------------------------

export function parseEnvelopeRow(row: unknown, vaultId: string): StoredEnvelope | null {
  if (!row || typeof row !== 'object') return null
  const r = row as Record<string, unknown>
  if (r.vault_id !== vaultId || (r.kind !== 'passphrase' && r.kind !== 'recovery')) return null
  if (r.format_version !== 1 || !Number.isSafeInteger(r.revision) || (r.revision as number) < 1) return null
  const salt = fromByteaHex(r.salt)
  const iv = fromByteaHex(r.iv)
  const wrappedKey = fromByteaHex(r.wrapped_key)
  const keyVerifier = fromByteaHex(r.key_verifier)
  if (!salt || !iv || !wrappedKey || !keyVerifier || keyVerifier.length !== 32) return null
  const kdfParams = r.kind === 'passphrase' ? parseArgon2Params(r.kdf_params) : r.kdf_params === null ? null : undefined
  if (kdfParams === undefined) return null
  const env: StoredEnvelope = {
    vaultId,
    kind: r.kind,
    formatVersion: 1,
    kdf: r.kdf as StoredEnvelope['kdf'],
    kdfParams,
    salt,
    iv,
    wrappedKey,
    keyVerifier,
    revision: r.revision as number,
  }
  return isWellFormedEnvelope(env) ? env : null
}

export function isValidEncryptedMetaLength(length: number): boolean {
  const body = length - 12 - GCM_TAG_BYTES
  return body >= META_BLOCK && body <= META_MAX_PADDED && body % META_BLOCK === 0
}

export function parseMediaRow(row: unknown, vaultId: string): MediaRecord | null {
  if (!row || typeof row !== 'object') return null
  const r = row as Record<string, unknown>
  if (!isUuid(r.id) || r.vault_id !== vaultId || r.format_version !== 1) return null
  if (r.status !== 'pending' && r.status !== 'ready') return null
  if (r.uploaded_by !== null && !isUuid(r.uploaded_by)) return null
  // The server's generated path must match what we derive; we never use the server's string directly.
  if (r.object_path !== objectPathFor(vaultId, r.id)) return null
  const wrappedDek = fromByteaHex(r.wrapped_dek)
  const encryptedMeta = fromByteaHex(r.encrypted_meta)
  if (!wrappedDek || wrappedDek.length !== WRAPPED_DEK_BYTES) return null
  if (!encryptedMeta || !isValidEncryptedMetaLength(encryptedMeta.length)) return null
  const size = r.ciphertext_size
  if (!Number.isSafeInteger(size) || (size as number) < HEADER_BYTES + GCM_TAG_BYTES || (size as number) > BUCKET_OBJECT_LIMIT) return null
  if (typeof r.created_at !== 'string') return null
  // Phase 4 columns (migration 5).
  if (r.folder_id !== null && !isUuid(r.folder_id)) return null
  if (r.trashed_at !== null && typeof r.trashed_at !== 'string') return null
  if (typeof r.has_thumbnail !== 'boolean') return null
  if (r.has_thumbnail && r.thumbnail_path !== thumbnailPathFor(vaultId, r.id)) return null
  // A pending row can never be in the trash (the server forbids it); treat it as malformed.
  if (r.status === 'pending' && r.trashed_at !== null) return null
  return {
    id: r.id,
    vaultId,
    status: r.status,
    uploadedBy: (r.uploaded_by as string | null) ?? null,
    wrappedDek,
    encryptedMeta,
    ciphertextSize: size as number,
    createdAt: r.created_at,
    folderId: (r.folder_id as string | null) ?? null,
    trashedAt: (r.trashed_at as string | null) ?? null,
    hasThumbnail: r.has_thumbnail,
  }
}

export function parseFolderRow(row: unknown, vaultId: string): FolderRecord | null {
  if (!row || typeof row !== 'object') return null
  const r = row as Record<string, unknown>
  if (!isUuid(r.id) || r.vault_id !== vaultId) return null
  if (r.parent_id !== null && (!isUuid(r.parent_id) || r.parent_id === r.id)) return null
  if (!Number.isSafeInteger(r.depth) || (r.depth as number) < 0 || (r.depth as number) > MAX_FOLDER_DEPTH) return null
  if (!Number.isSafeInteger(r.revision) || (r.revision as number) < 1) return null
  if (typeof r.created_at !== 'string' || typeof r.updated_at !== 'string') return null
  const encryptedMeta = fromByteaHex(r.encrypted_meta)
  if (!encryptedMeta || !isValidFolderMetaLength(encryptedMeta.length)) return null
  return {
    id: r.id,
    vaultId,
    parentId: (r.parent_id as string | null) ?? null,
    depth: r.depth as number,
    encryptedMeta,
    revision: r.revision as number,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }
}

// ---------------------------------------------------------------------------
// Supabase implementation
// ---------------------------------------------------------------------------

interface ErrorLike {
  code?: string
  message?: string
  status?: number
  statusCode?: string | number
}

function classify(error: ErrorLike | null | undefined): BackendError {
  const code = error?.code ?? ''
  // Missing table/column: a migration (Phase 3: #4, Phase 4: #5) has not been applied.
  if (code === 'PGRST205' || code === 'PGRST204' || code === '42P01' || code === '42703') return new BackendError('not-set-up')
  if (code === '42501' || code === 'PGRST301' || String(error?.statusCode ?? error?.status ?? '') === '403') {
    return new BackendError('denied')
  }
  if (!code && /fetch|network/i.test(error?.message ?? '')) return new BackendError('network')
  return new BackendError('generic')
}

const ENVELOPE_COLUMNS = 'vault_id, kind, format_version, kdf, kdf_params, salt, iv, wrapped_key, key_verifier, revision'
const MEDIA_COLUMNS =
  'id, vault_id, status, uploaded_by, format_version, object_path, wrapped_dek, encrypted_meta, ciphertext_size, created_at, ' +
  'folder_id, trashed_at, has_thumbnail, thumbnail_path'
const FOLDER_COLUMNS = 'id, vault_id, parent_id, depth, encrypted_meta, revision, created_at, updated_at'

/** Rows per listing request. Supabase caps responses (default 1000), so listing pages through. */
export const LIST_PAGE_SIZE = 500
/** Safety stop for listing (500 x 400 = 200,000 rows). */
const MAX_LIST_PAGES = 400
/** Ids per bulk update request (keeps the request URL short). */
export const BULK_CHUNK = 100

function chunks<T>(values: T[], size: number): T[][] {
  const out: T[][] = []
  for (let i = 0; i < values.length; i += size) out.push(values.slice(i, i + size))
  return out
}

function envelopeColumns(envelope: SealedEnvelope) {
  return {
    format_version: envelope.formatVersion,
    kdf: envelope.kdf,
    kdf_params: envelope.kdfParams,
    salt: toByteaHex(envelope.salt),
    iv: toByteaHex(envelope.iv),
    wrapped_key: toByteaHex(envelope.wrappedKey),
  }
}

export function createSupabaseVaultBackend(client: SupabaseClient): VaultBackend {
  async function run<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn()
    } catch (error) {
      if (error instanceof BackendError) throw error
      throw new BackendError('network')
    }
  }

  return {
    listEnvelopes: (vaultId) =>
      run(async () => {
        const { data, error } = await client.from('vault_key_envelopes').select(ENVELOPE_COLUMNS).eq('vault_id', vaultId)
        if (error) throw classify(error)
        const rows = data ?? []
        const parsed = rows.map((row) => parseEnvelopeRow(row, vaultId))
        // Any malformed key row is treated as an error, not silently skipped.
        if (parsed.some((env) => env === null)) throw new BackendError('generic')
        return parsed as StoredEnvelope[]
      }),

    insertEnvelope: (vaultId, envelope, keyVerifier, proof) =>
      run(async () => {
        if (proof.length !== PROOF_BYTES) throw new BackendError('generic')
        const { error } = await client.from('vault_key_envelopes').insert({
          vault_id: vaultId,
          kind: envelope.kind,
          ...envelopeColumns(envelope),
          key_verifier: toByteaHex(keyVerifier),
          key_proof: toByteaHex(proof),
        })
        if (error) throw error.code === '23505' ? new BackendError('conflict') : classify(error)
      }),

    updateEnvelope: (vaultId, envelope, proof, expectedRevision) =>
      run(async () => {
        if (proof.length !== PROOF_BYTES) throw new BackendError('generic')
        const { data, error } = await client
          .from('vault_key_envelopes')
          .update({ ...envelopeColumns(envelope), key_proof: toByteaHex(proof) })
          .eq('vault_id', vaultId)
          .eq('kind', envelope.kind)
          .eq('revision', expectedRevision)
          .select('revision')
        if (error) throw classify(error)
        if ((data ?? []).length !== 1) throw new BackendError('conflict')
      }),

    insertPendingMedia: (row) =>
      run(async () => {
        const { error } = await client.from('media_items').insert({
          id: row.id,
          vault_id: row.vaultId,
          format_version: 1,
          has_thumbnail: row.hasThumbnail,
          wrapped_dek: toByteaHex(row.wrappedDek),
          encrypted_meta: toByteaHex(row.encryptedMeta),
          ciphertext_size: row.ciphertextSize,
          folder_id: row.folderId,
        })
        if (error) throw classify(error)
      }),

    uploadObject: (path, ciphertext) =>
      run(async () => {
        const body = new Blob([ciphertext], { type: 'application/octet-stream' })
        const { error } = await client.storage.from(MEDIA_BUCKET).upload(path, body, {
          contentType: 'application/octet-stream',
          upsert: false, // write-once; the bucket has no UPDATE policy either
        })
        if (error) throw classify(error as ErrorLike)
      }),

    markReady: (id) =>
      run(async () => {
        const { data, error } = await client.from('media_items').update({ status: 'ready' }).eq('id', id).select('status')
        if (error) throw classify(error)
        if ((data ?? []).length !== 1 || (data?.[0] as { status?: unknown }).status !== 'ready') throw new BackendError('generic')
      }),

    listMedia: (vaultId) =>
      run(async () => {
        const records: MediaRecord[] = []
        const seen = new Set<string>()
        let damaged = 0
        for (let page = 0; page < MAX_LIST_PAGES; page++) {
          const from = page * LIST_PAGE_SIZE
          const { data, error } = await client
            .from('media_items')
            .select(MEDIA_COLUMNS)
            .eq('vault_id', vaultId)
            .order('created_at', { ascending: false })
            .order('id', { ascending: true }) // stable order across pages
            .range(from, from + LIST_PAGE_SIZE - 1)
          if (error) throw classify(error)
          const rows = data ?? []
          for (const row of rows) {
            const parsed = parseMediaRow(row, vaultId)
            if (!parsed) damaged++
            else if (!seen.has(parsed.id)) {
              seen.add(parsed.id)
              records.push(parsed)
            }
          }
          if (rows.length < LIST_PAGE_SIZE) break
        }
        return { records, damaged }
      }),

    downloadObject: (path, maxBytes = BUCKET_OBJECT_LIMIT) =>
      run(async () => {
        const { data, error } = await client.storage.from(MEDIA_BUCKET).download(path)
        if (error || !data) throw classify(error as ErrorLike)
        if (data.size > Math.min(maxBytes, BUCKET_OBJECT_LIMIT)) throw new BackendError('generic')
        return new Uint8Array(await data.arrayBuffer())
      }),

    deleteObject: (path) =>
      run(async () => {
        const { error } = await client.storage.from(MEDIA_BUCKET).remove([path])
        if (error) throw classify(error as ErrorLike)
      }),

    deleteObjects: (paths) =>
      run(async () => {
        if (paths.length === 0) return
        const { error } = await client.storage.from(MEDIA_BUCKET).remove(paths)
        if (error) throw classify(error as ErrorLike)
      }),

    deleteMedia: (id) =>
      run(async () => {
        const { error } = await client.from('media_items').delete().eq('id', id)
        if (error) throw classify(error)
      }),

    setMediaFolder: (vaultId, ids, folderId) =>
      run(async () => {
        if (folderId !== null && !isUuid(folderId)) throw new BackendError('generic')
        const updated: string[] = []
        for (const part of chunks(ids.filter(isUuid), BULK_CHUNK)) {
          const { data, error } = await client
            .from('media_items')
            .update({ folder_id: folderId })
            .eq('vault_id', vaultId)
            .eq('status', 'ready')
            .in('id', part)
            .select('id')
          if (error) throw classify(error)
          for (const row of data ?? []) if (isUuid((row as { id?: unknown }).id)) updated.push((row as { id: string }).id)
        }
        return updated
      }),

    setMediaTrashed: (vaultId, ids, trashed) =>
      run(async () => {
        const updated: string[] = []
        for (const part of chunks(ids.filter(isUuid), BULK_CHUNK)) {
          // Any non-null value means "trash"; the server replaces it with its own clock.
          const { data, error } = await client
            .from('media_items')
            .update({ trashed_at: trashed ? new Date().toISOString() : null })
            .eq('vault_id', vaultId)
            .eq('status', 'ready')
            .in('id', part)
            .select('id')
          if (error) throw classify(error)
          for (const row of data ?? []) if (isUuid((row as { id?: unknown }).id)) updated.push((row as { id: string }).id)
        }
        return updated
      }),

    listFolders: (vaultId) =>
      run(async () => {
        const records: FolderRecord[] = []
        let damaged = 0
        for (let page = 0; page < MAX_LIST_PAGES; page++) {
          const from = page * LIST_PAGE_SIZE
          const { data, error } = await client
            .from('media_folders')
            .select(FOLDER_COLUMNS)
            .eq('vault_id', vaultId)
            .order('created_at', { ascending: true })
            .order('id', { ascending: true })
            .range(from, from + LIST_PAGE_SIZE - 1)
          if (error) throw classify(error)
          const rows = data ?? []
          for (const row of rows) {
            const parsed = parseFolderRow(row, vaultId)
            if (parsed) records.push(parsed)
            else damaged++
          }
          if (rows.length < LIST_PAGE_SIZE) break
        }
        return { records, damaged }
      }),

    insertFolder: (row) =>
      run(async () => {
        const { error } = await client.from('media_folders').insert({
          id: row.id,
          vault_id: row.vaultId,
          parent_id: row.parentId,
          encrypted_meta: toByteaHex(row.encryptedMeta),
        })
        if (error) {
          if (error.code === '23514') throw new BackendError('conflict') // too deep
          if (error.code === '23503') throw new BackendError('conflict') // parent vanished
          throw classify(error)
        }
      }),

    updateFolderMeta: (vaultId, id, encryptedMeta, expectedRevision) =>
      run(async () => {
        const { data, error } = await client
          .from('media_folders')
          .update({ encrypted_meta: toByteaHex(encryptedMeta) })
          .eq('vault_id', vaultId)
          .eq('id', id)
          .eq('revision', expectedRevision)
          .select('id')
        if (error) throw classify(error)
        if ((data ?? []).length !== 1) throw new BackendError('conflict')
      }),

    deleteFolder: (vaultId, id) =>
      run(async () => {
        const { data, error } = await client.from('media_folders').delete().eq('vault_id', vaultId).eq('id', id).select('id')
        if (error) {
          // 23514: still holds active/pending items; 23503: still has subfolders.
          if (error.code === '23514' || error.code === '23503') throw new BackendError('not-empty')
          throw classify(error)
        }
        if ((data ?? []).length !== 1) throw new BackendError('conflict')
      }),
  }
}
