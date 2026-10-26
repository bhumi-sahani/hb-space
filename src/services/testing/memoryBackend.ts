/**
 * TEST-ONLY in-memory stand-in for Supabase, implementing the same rules the
 * real database enforces (migrations 1-5): key-proof checks on envelopes,
 * write-once objects, pending -> ready only when the stored object (and declared
 * thumbnail) exist with the right size, folders with immutable structure and
 * a depth limit, moving/trashing READY items only, folder deletion only when
 * empty. Rows are kept in the server's wire format (bytea as hex strings) and
 * read back through the real row parsers. Every request payload is logged so
 * tests can inspect exactly what would leave the browser.
 */
import { isUuid, toByteaHex } from '../../lib/crypto/bytes'
import type { SealedEnvelope } from '../../lib/crypto/envelope'
import {
  BackendError,
  MAX_FOLDER_DEPTH,
  parseEnvelopeRow,
  parseFolderRow,
  parseMediaRow,
  type FolderRecord,
  type MediaRecord,
  type NewFolderRow,
  type NewMediaRow,
  type VaultBackend,
} from '../vaultBackend'

export interface LoggedRequest {
  op: string
  /** JSON-serialisable request body, or raw bytes for uploads. */
  body: unknown
}

type Row = Record<string, unknown>

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toByteaHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes))))
}

export class MemoryBackend implements VaultBackend {
  envelopes = new Map<string, Row>() // key: kind
  media = new Map<string, Row>()
  folders = new Map<string, Row>()
  objects = new Map<string, Uint8Array<ArrayBuffer>>()
  log: LoggedRequest[] = []
  failNext: Partial<Record<keyof VaultBackend, BackendError>> = {}
  /** Fail an operation only for specific ids/paths (partial-failure tests). */
  failFor: Partial<Record<keyof VaultBackend, Set<string>>> = {}
  /** Optional artificial delay (ms) per call, for UI tests of loading states. */
  delay = 0
  private now = 0
  private readonly vaultId: string
  private readonly userId: string

  constructor(vaultId: string, userId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa') {
    this.vaultId = vaultId
    this.userId = userId
  }

  private async step(op: keyof VaultBackend, body: unknown, key?: string) {
    this.log.push({ op, body })
    if (this.delay > 0) await new Promise((resolve) => setTimeout(resolve, this.delay))
    const error = this.failNext[op]
    if (error) {
      delete this.failNext[op]
      throw error
    }
    if (key !== undefined && this.failFor[op]?.has(key)) throw new BackendError('network')
  }

  private stamp(): string {
    return new Date(Date.UTC(2026, 0, 1, 0, 0, this.now++)).toISOString()
  }

  private envelopeBody(env: SealedEnvelope): Row {
    return {
      format_version: env.formatVersion,
      kdf: env.kdf,
      kdf_params: env.kdfParams ? { ...env.kdfParams } : null,
      salt: toByteaHex(env.salt),
      iv: toByteaHex(env.iv),
      wrapped_key: toByteaHex(env.wrappedKey),
    }
  }

  async listEnvelopes(vaultId: string) {
    await this.step('listEnvelopes', { vaultId })
    return [...this.envelopes.values()].map((row) => {
      const parsed = parseEnvelopeRow(structuredClone(row), vaultId)
      if (!parsed) throw new BackendError('generic')
      return parsed
    })
  }

  async insertEnvelope(vaultId: string, env: SealedEnvelope, keyVerifier: Uint8Array, proof: Uint8Array) {
    const body = { vault_id: vaultId, kind: env.kind, ...this.envelopeBody(env), key_verifier: toByteaHex(keyVerifier), key_proof: toByteaHex(proof) }
    await this.step('insertEnvelope', body)
    if (vaultId !== this.vaultId) throw new BackendError('denied')
    const existing = [...this.envelopes.values()][0]
    const proofHash = await sha256Hex(proof)
    if (existing) {
      if (existing.key_verifier !== body.key_verifier || proofHash !== existing.key_verifier) throw new BackendError('denied')
    } else if (proofHash !== body.key_verifier) {
      throw new BackendError('denied')
    }
    if (this.envelopes.has(env.kind)) throw new BackendError('conflict')
    this.envelopes.set(env.kind, { ...body, key_proof: null, revision: 1 }) // proof is never stored
  }

  async updateEnvelope(vaultId: string, env: SealedEnvelope, proof: Uint8Array, expectedRevision: number) {
    const body = { ...this.envelopeBody(env), key_proof: toByteaHex(proof) }
    await this.step('updateEnvelope', { ...body, vaultId, kind: env.kind, expectedRevision })
    const row = this.envelopes.get(env.kind)
    if (!row || vaultId !== this.vaultId || row.revision !== expectedRevision) throw new BackendError('conflict')
    if ((await sha256Hex(proof)) !== row.key_verifier) throw new BackendError('denied')
    this.envelopes.set(env.kind, { ...row, ...body, key_proof: null, revision: (row.revision as number) + 1 })
  }

  async insertPendingMedia(row: NewMediaRow) {
    const body = {
      id: row.id,
      vault_id: row.vaultId,
      format_version: 1,
      has_thumbnail: row.hasThumbnail,
      wrapped_dek: toByteaHex(row.wrappedDek),
      encrypted_meta: toByteaHex(row.encryptedMeta),
      ciphertext_size: row.ciphertextSize,
      folder_id: row.folderId,
    }
    await this.step('insertPendingMedia', body, row.id)
    if (row.vaultId !== this.vaultId || this.media.has(row.id)) throw new BackendError('denied')
    if (row.folderId !== null && !this.folders.has(row.folderId)) throw new BackendError('generic')
    this.media.set(row.id, {
      ...body,
      status: 'pending',
      uploaded_by: this.userId,
      object_path: `${row.vaultId}/${row.id}`,
      thumbnail_path: `${row.vaultId}/${row.id}.t`,
      trashed_at: null,
      created_at: this.stamp(),
    })
  }

  async uploadObject(path: string, ciphertext: Uint8Array<ArrayBuffer>) {
    await this.step('uploadObject', { path, bytes: ciphertext.slice() }, path)
    const row = [...this.media.values()].find((r) => r.object_path === path || (r.has_thumbnail && r.thumbnail_path === path))
    if (!row || row.status !== 'pending' || row.uploaded_by !== this.userId || this.objects.has(path)) throw new BackendError('denied')
    this.objects.set(path, ciphertext.slice())
  }

  async markReady(id: string) {
    await this.step('markReady', { id }, id)
    const row = this.media.get(id)
    if (!row || row.status !== 'pending') throw new BackendError('generic')
    const object = this.objects.get(row.object_path as string)
    if (!object || object.length !== row.ciphertext_size) throw new BackendError('generic')
    if (row.has_thumbnail && !this.objects.has(row.thumbnail_path as string)) throw new BackendError('generic')
    row.status = 'ready'
  }

  async listMedia(vaultId: string) {
    await this.step('listMedia', { vaultId })
    const records: MediaRecord[] = []
    let damaged = 0
    for (const row of [...this.media.values()].reverse()) {
      const parsed = parseMediaRow(structuredClone(row), vaultId)
      if (parsed) records.push(parsed)
      else damaged++
    }
    return { records, damaged }
  }

  async downloadObject(path: string, maxBytes?: number) {
    await this.step('downloadObject', { path }, path)
    const object = this.objects.get(path)
    if (!object) throw new BackendError('generic')
    if (maxBytes !== undefined && object.length > maxBytes) throw new BackendError('generic')
    return object.slice()
  }

  /** Storage delete needs the row to still exist (same rule as reading). */
  private canDeleteObject(path: string): boolean {
    return [...this.media.values()].some((r) => r.object_path === path || (r.has_thumbnail && r.thumbnail_path === path))
  }

  async deleteObject(path: string) {
    await this.step('deleteObject', { path }, path)
    if (this.canDeleteObject(path)) this.objects.delete(path)
  }

  async deleteObjects(paths: string[]) {
    await this.step('deleteObjects', { paths }, paths[0])
    for (const path of paths) if (this.canDeleteObject(path)) this.objects.delete(path)
  }

  async deleteMedia(id: string) {
    await this.step('deleteMedia', { id }, id)
    this.media.delete(id)
  }

  async setMediaFolder(vaultId: string, ids: string[], folderId: string | null) {
    await this.step('setMediaFolder', { vaultId, ids: [...ids], folderId }, ids[0])
    if (folderId !== null && !this.folders.has(folderId)) throw new BackendError('generic')
    const updated: string[] = []
    for (const id of ids) {
      const row = this.media.get(id)
      if (!row || row.vault_id !== vaultId || row.status !== 'ready') continue
      row.folder_id = folderId
      updated.push(id)
    }
    return updated
  }

  async setMediaTrashed(vaultId: string, ids: string[], trashed: boolean) {
    await this.step('setMediaTrashed', { vaultId, ids: [...ids], trashed }, ids[0])
    const updated: string[] = []
    for (const id of ids) {
      const row = this.media.get(id)
      if (!row || row.vault_id !== vaultId || row.status !== 'ready') continue
      if (!trashed) row.trashed_at = null
      else if (row.trashed_at === null) row.trashed_at = this.stamp()
      updated.push(id)
    }
    return updated
  }

  async listFolders(vaultId: string) {
    await this.step('listFolders', { vaultId })
    const records: FolderRecord[] = []
    let damaged = 0
    for (const row of this.folders.values()) {
      const parsed = parseFolderRow(structuredClone(row), vaultId)
      if (parsed) records.push(parsed)
      else damaged++
    }
    return { records, damaged }
  }

  async insertFolder(row: NewFolderRow) {
    const body = { id: row.id, vault_id: row.vaultId, parent_id: row.parentId, encrypted_meta: toByteaHex(row.encryptedMeta) }
    await this.step('insertFolder', body, row.id)
    if (row.vaultId !== this.vaultId || !isUuid(row.id) || this.folders.has(row.id)) throw new BackendError('denied')
    let depth = 0
    if (row.parentId !== null) {
      const parent = this.folders.get(row.parentId)
      if (!parent) throw new BackendError('conflict')
      if ((parent.depth as number) >= MAX_FOLDER_DEPTH) throw new BackendError('conflict')
      depth = (parent.depth as number) + 1
    }
    const at = this.stamp()
    this.folders.set(row.id, { ...body, depth, revision: 1, created_by: this.userId, created_at: at, updated_by: this.userId, updated_at: at })
  }

  async updateFolderMeta(vaultId: string, id: string, encryptedMeta: Uint8Array, expectedRevision: number) {
    await this.step('updateFolderMeta', { vaultId, id, encrypted_meta: toByteaHex(encryptedMeta), expectedRevision }, id)
    const row = this.folders.get(id)
    if (!row || row.vault_id !== vaultId || row.revision !== expectedRevision) throw new BackendError('conflict')
    row.encrypted_meta = toByteaHex(encryptedMeta)
    row.revision = (row.revision as number) + 1
    row.updated_at = this.stamp()
  }

  async deleteFolder(vaultId: string, id: string) {
    await this.step('deleteFolder', { vaultId, id }, id)
    const row = this.folders.get(id)
    if (!row || row.vault_id !== vaultId) throw new BackendError('conflict')
    const items = [...this.media.values()].filter((m) => m.folder_id === id)
    if (items.some((m) => m.trashed_at === null || m.status !== 'ready')) throw new BackendError('not-empty')
    if ([...this.folders.values()].some((f) => f.parent_id === id)) throw new BackendError('not-empty')
    for (const item of items) item.folder_id = null // trashed items move to the root
    this.folders.delete(id)
  }

  /** Everything the "server" has persisted, as bytes, for leak scanning. */
  persistedBytes(): Uint8Array[] {
    const text = JSON.stringify({ envelopes: [...this.envelopes.values()], media: [...this.media.values()], folders: [...this.folders.values()] })
    return [new TextEncoder().encode(text), ...decodeHexFields(text), ...this.objects.values()]
  }

  /** Everything sent over the "network", as bytes, for leak scanning. */
  sentBytes(): Uint8Array[] {
    const out: Uint8Array[] = []
    for (const entry of this.log) {
      const body = entry.body as Record<string, unknown>
      if (body && body.bytes instanceof Uint8Array) out.push(body.bytes)
      const text = JSON.stringify(body, (_k, v) => (v instanceof Uint8Array ? undefined : v))
      out.push(new TextEncoder().encode(text), ...decodeHexFields(text))
    }
    return out
  }
}

/** Decodes every hex bytea string inside a JSON text, so scans see the raw bytes too. */
function decodeHexFields(text: string): Uint8Array[] {
  const out: Uint8Array[] = []
  for (const match of text.matchAll(/\\\\x([0-9a-f]*)/g)) {
    const hex = match[1]
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    out.push(bytes)
  }
  return out
}
