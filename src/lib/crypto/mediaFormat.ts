import { equalBytes, randomBytes, uuidToBytes, wipe } from './bytes'
import { GCM_TAG_BYTES, VaultCryptoError, failClosed } from './primitives'

/**
 * Encrypted object format v1 (SECURITY_ARCHITECTURE.md §6.3). All integers big-endian.
 *
 *   header (40 bytes, also the AAD of every chunk):
 *     magic      4  "HBS\x01"
 *     version    1  0x01
 *     kind       1  0x01 content | 0x02 thumbnail
 *     reserved   2  zero
 *     chunk_size 4  plaintext bytes per chunk (v1: exactly 1 MiB)
 *     nonce_pfx  7  random per object
 *     reserved   5  zero
 *     item_id   16  UUID bytes; must equal the database row id
 *   body: chunk_0 || ... || chunk_n-1, each = AES-256-GCM ciphertext || 16-byte tag
 *     nonce_i = nonce_pfx(7) || uint32(i) || last_flag(1)    (last_flag = 1 only on the final chunk)
 *
 * This is the STREAM construction: reordering fails (counter in nonce), truncation
 * fails (final flag), appending fails (length must be canonical), swapping objects
 * between rows fails (item id in AAD, and each item has its own key). An empty file
 * is one final chunk with no plaintext. Chunk keys are per-item (HKDF from the
 * item's random DEK), so the counter nonces never repeat under one key.
 */

export const FORMAT_MAGIC = Uint8Array.of(0x48, 0x42, 0x53, 0x01) // "HBS\x01"
export const FORMAT_VERSION = 1
export const HEADER_BYTES = 40
export const CHUNK_SIZE = 1024 * 1024
export const NONCE_PREFIX_BYTES = 7

export const OBJECT_KIND = { content: 1, thumbnail: 2 } as const
export type ObjectKind = keyof typeof OBJECT_KIND

export function chunkCount(plaintextLength: number): number {
  return plaintextLength === 0 ? 1 : Math.ceil(plaintextLength / CHUNK_SIZE)
}

export function ciphertextLength(plaintextLength: number): number {
  return HEADER_BYTES + chunkCount(plaintextLength) * GCM_TAG_BYTES + plaintextLength
}

function buildHeader(kind: ObjectKind, itemId: string, noncePrefix: Uint8Array): Uint8Array<ArrayBuffer> {
  const header = new Uint8Array(HEADER_BYTES)
  const view = new DataView(header.buffer)
  header.set(FORMAT_MAGIC, 0)
  header[4] = FORMAT_VERSION
  header[5] = OBJECT_KIND[kind]
  // [6..8) reserved = 0
  view.setUint32(8, CHUNK_SIZE)
  header.set(noncePrefix, 12)
  // [19..24) reserved = 0
  header.set(uuidToBytes(itemId), 24)
  return header
}

function chunkNonce(noncePrefix: Uint8Array, index: number, last: boolean): Uint8Array<ArrayBuffer> {
  const nonce = new Uint8Array(12)
  nonce.set(noncePrefix, 0)
  new DataView(nonce.buffer).setUint32(7, index)
  nonce[11] = last ? 1 : 0
  return nonce
}

/** Encrypts a whole object in memory. Returns header || chunks. */
export async function encryptObject(
  key: CryptoKey,
  kind: ObjectKind,
  itemId: string,
  plaintext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  return failClosed(async () => {
    const noncePrefix = randomBytes(NONCE_PREFIX_BYTES)
    const header = buildHeader(kind, itemId, noncePrefix)
    const n = chunkCount(plaintext.length)
    const out = new Uint8Array(ciphertextLength(plaintext.length))
    out.set(header, 0)
    let offset = HEADER_BYTES
    for (let i = 0; i < n; i++) {
      const chunk = plaintext.subarray(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, plaintext.length))
      const sealed = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: chunkNonce(noncePrefix, i, i === n - 1), additionalData: header, tagLength: 128 },
          key,
          chunk,
        ),
      )
      out.set(sealed, offset)
      offset += sealed.length
    }
    if (offset !== out.length) throw new VaultCryptoError()
    return out
  })
}

/**
 * Parses and checks the header and overall length BEFORE any decryption.
 * Returns the nonce prefix and chunk count, or throws VaultCryptoError.
 */
export function validateObject(data: Uint8Array, kind: ObjectKind, itemId: string): { noncePrefix: Uint8Array; chunks: number } {
  if (data.length < HEADER_BYTES + GCM_TAG_BYTES) throw new VaultCryptoError()
  if (!equalBytes(data.subarray(0, 4), FORMAT_MAGIC)) throw new VaultCryptoError()
  if (data[4] !== FORMAT_VERSION || data[5] !== OBJECT_KIND[kind]) throw new VaultCryptoError()
  if (data[6] !== 0 || data[7] !== 0) throw new VaultCryptoError()
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  if (view.getUint32(8) !== CHUNK_SIZE) throw new VaultCryptoError()
  for (let i = 19; i < 24; i++) if (data[i] !== 0) throw new VaultCryptoError()
  if (!equalBytes(data.subarray(24, 40), uuidToBytes(itemId))) throw new VaultCryptoError()

  // The body length must be exactly what the encoder would produce for some plaintext length.
  const body = data.length - HEADER_BYTES
  const sealedChunk = CHUNK_SIZE + GCM_TAG_BYTES
  const chunks = Math.ceil(body / sealedChunk)
  const lastSealed = body - (chunks - 1) * sealedChunk
  if (lastSealed < GCM_TAG_BYTES || lastSealed > sealedChunk) throw new VaultCryptoError()
  if (chunks > 1 && lastSealed === GCM_TAG_BYTES) throw new VaultCryptoError() // empty trailing chunk is non-canonical
  return { noncePrefix: data.slice(12, 19), chunks }
}

/** Authenticated decryption of a whole object. Never returns partially decrypted data. */
export async function decryptObject(
  key: CryptoKey,
  kind: ObjectKind,
  itemId: string,
  data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const { noncePrefix, chunks } = validateObject(data, kind, itemId)
  const header = data.slice(0, HEADER_BYTES)
  const out = new Uint8Array(data.length - HEADER_BYTES - chunks * GCM_TAG_BYTES)
  const sealedChunk = CHUNK_SIZE + GCM_TAG_BYTES
  try {
    let offset = 0
    for (let i = 0; i < chunks; i++) {
      const start = HEADER_BYTES + i * sealedChunk
      const sealed = data.subarray(start, Math.min(start + sealedChunk, data.length))
      const plain = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: chunkNonce(noncePrefix, i, i === chunks - 1), additionalData: header, tagLength: 128 },
          key,
          sealed,
        ),
      )
      out.set(plain, offset)
      wipe(plain)
      offset += plain.length
    }
    return out
  } catch {
    wipe(out)
    throw new VaultCryptoError()
  }
}
