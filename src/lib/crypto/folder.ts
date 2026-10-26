import { concat, fromUtf8, isUuid, randomBytes, utf8, uuidToBytes, wipe } from './bytes'
import { GCM_IV_BYTES, GCM_TAG_BYTES, VaultCryptoError, failClosed, gcmDecrypt, gcmEncrypt } from './primitives'

/**
 * Encrypted folder metadata (Phase 4, SECURITY_ARCHITECTURE.md §6.10).
 *
 *   media_folders.encrypted_meta = iv(12) || AES-256-GCM(VMK, padded JSON) || tag(16)
 *   AAD = "hbspace/folder/v1" || vault_id(16) || folder_id(16)
 *   padded JSON = uint32 length || UTF-8 {"v":1,"name":...} || zeros, to a multiple of 256 bytes
 *
 * The server stores only this blob plus opaque ids. Binding vault_id and folder_id
 * into the AAD means a blob copied onto another folder row fails authentication.
 * Encrypting directly under the VMK (random 96-bit IV per write) is safe here: the
 * total number of VMK encryptions (item key wraps + folder writes) stays far below
 * the 2^32 random-IV limit for AES-GCM.
 */

export const FOLDER_META_BLOCK = 256
export const FOLDER_META_MAX_PADDED = 4096
export const MAX_FOLDER_NAME_LENGTH = 100

const LABEL_FOLDER = utf8('hbspace/folder/v1')

export interface FolderMetadata {
  v: 1
  name: string
}

/** Display-safe folder name: no control/bidi characters or slashes, trimmed, capped. */
export function cleanFolderName(name: unknown): string {
  if (typeof name !== 'string') return ''
  // eslint-disable-next-line no-control-regex
  const cleaned = name.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069/\\]/g, '').trim()
  return cleaned.slice(0, MAX_FOLDER_NAME_LENGTH).trim()
}

function aad(vaultId: string, folderId: string): Uint8Array<ArrayBuffer> {
  return concat(LABEL_FOLDER, uuidToBytes(vaultId), uuidToBytes(folderId))
}

function pad(meta: FolderMetadata): Uint8Array<ArrayBuffer> {
  const json = utf8(JSON.stringify(meta))
  const total = Math.max(FOLDER_META_BLOCK, Math.ceil((4 + json.length) / FOLDER_META_BLOCK) * FOLDER_META_BLOCK)
  if (total > FOLDER_META_MAX_PADDED) throw new VaultCryptoError()
  const out = new Uint8Array(total)
  new DataView(out.buffer).setUint32(0, json.length)
  out.set(json, 4)
  return out
}

function unpad(padded: Uint8Array): FolderMetadata {
  if (padded.length < FOLDER_META_BLOCK || padded.length % FOLDER_META_BLOCK !== 0) throw new VaultCryptoError()
  const length = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0)
  if (length > padded.length - 4) throw new VaultCryptoError()
  for (let i = 4 + length; i < padded.length; i++) if (padded[i] !== 0) throw new VaultCryptoError()
  let parsed: unknown
  try {
    parsed = JSON.parse(fromUtf8(padded.subarray(4, 4 + length)))
  } catch {
    throw new VaultCryptoError()
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new VaultCryptoError()
  const record = parsed as Record<string, unknown>
  if (record.v !== 1) throw new VaultCryptoError()
  const name = cleanFolderName(record.name)
  if (!name) throw new VaultCryptoError()
  return { v: 1, name }
}

export function isValidFolderMetaLength(length: number): boolean {
  const body = length - GCM_IV_BYTES - GCM_TAG_BYTES
  return body >= FOLDER_META_BLOCK && body <= FOLDER_META_MAX_PADDED && body % FOLDER_META_BLOCK === 0
}

/** Encrypts a folder name for storage. A fresh IV every time (create and each rename). */
export async function encryptFolderMeta(vmk: CryptoKey, vaultId: string, folderId: string, name: string): Promise<Uint8Array<ArrayBuffer>> {
  if (!isUuid(vaultId) || !isUuid(folderId)) throw new VaultCryptoError()
  const clean = cleanFolderName(name)
  if (!clean) throw new VaultCryptoError()
  const padded = pad({ v: 1, name: clean })
  try {
    return await failClosed(async () => {
      const iv = randomBytes(GCM_IV_BYTES)
      return concat(iv, await gcmEncrypt(vmk, iv, padded, aad(vaultId, folderId)))
    })
  } finally {
    wipe(padded)
  }
}

export async function decryptFolderMeta(
  vmk: CryptoKey,
  vaultId: string,
  folderId: string,
  encrypted: Uint8Array<ArrayBuffer>,
): Promise<FolderMetadata> {
  if (!isUuid(vaultId) || !isUuid(folderId) || !isValidFolderMetaLength(encrypted.length)) throw new VaultCryptoError()
  const padded = await gcmDecrypt(vmk, encrypted.slice(0, GCM_IV_BYTES), encrypted.slice(GCM_IV_BYTES), aad(vaultId, folderId))
  try {
    return unpad(padded)
  } finally {
    wipe(padded)
  }
}
