import { concat, fromUtf8, isUuid, randomBytes, utf8, uuidToBytes, wipe } from './bytes'
import { decryptObject, encryptObject } from './mediaFormat'
import { AES_KEY_BYTES, GCM_IV_BYTES, GCM_TAG_BYTES, VaultCryptoError, failClosed, gcmDecrypt, gcmEncrypt, hkdfAesKey, importHkdfKey } from './primitives'
import { sniffType, type SniffedType } from './sniff'

/**
 * Per-item keys and metadata (SECURITY_ARCHITECTURE.md §6.2-6.3).
 *
 *   VMK --AES-GCM(AAD = "hbspace/dek/v1" || item_id)--> wrapped DEK (iv 12 || ct 32 || tag 16 = 60 bytes)
 *   DEK --HKDF-SHA-256(info = purpose || item_id)--> content key, metadata key
 *
 * encrypted_meta = iv(12) || AES-GCM(meta key, padded JSON) with AAD "hbspace/meta/v1" || item_id.
 * Padded JSON = uint32 length || UTF-8 JSON || zeros, to a multiple of 256 bytes, which hides
 * the exact filename length.
 */

export const WRAPPED_DEK_BYTES = GCM_IV_BYTES + AES_KEY_BYTES + GCM_TAG_BYTES // 60
export const META_BLOCK = 256
export const META_MAX_PADDED = 65536
export const MAX_NAME_LENGTH = 255

const LABEL_DEK = utf8('hbspace/dek/v1')
const LABEL_CONTENT = utf8('hbspace/content/v1')
const LABEL_META = utf8('hbspace/meta/v1')
// Phase 4: separate key for the encrypted thumbnail object (<vault>/<item>.t).
const LABEL_THUMBNAIL = utf8('hbspace/thumbnail/v1')

/** Largest thumbnail plaintext accepted (the app produces ~10-60 KB JPEGs). */
export const MAX_THUMBNAIL_BYTES = 512 * 1024
/** Upper bound for media dimensions / duration stored in metadata (sanity only). */
const MAX_DIMENSION = 100_000
const MAX_DURATION_SECONDS = 7 * 24 * 3600

/** Everything descriptive about an item. Lives only inside encrypted_meta. */
export interface ItemMetadata {
  v: 1
  name: string
  /** Sniffed from the bytes at upload time. Re-sniffed after decryption before display. */
  mime: SniffedType
  size: number
  /** File's last-modified time (ms since epoch) if the browser supplied one. */
  modified: number | null
  /** Phase 4, optional: pixel size of an image or video, if the browser could read it. */
  width?: number
  height?: number
  /** Phase 4, optional: video length in seconds. */
  duration?: number
}

/** Optional facts measured locally at upload time. */
export interface MediaFacts {
  width?: number
  height?: number
  duration?: number
}

interface ItemKeys {
  content: CryptoKey
  meta: CryptoKey
  thumbnail: CryptoKey
}

async function deriveItemKeys(rawDek: Uint8Array<ArrayBuffer>, itemId: string): Promise<ItemKeys> {
  const base = await importHkdfKey(rawDek)
  const id = uuidToBytes(itemId)
  const empty = new Uint8Array(0)
  const [content, meta, thumbnail] = await Promise.all([
    hkdfAesKey(base, empty, concat(LABEL_CONTENT, id)),
    hkdfAesKey(base, empty, concat(LABEL_META, id)),
    hkdfAesKey(base, empty, concat(LABEL_THUMBNAIL, id)),
  ])
  return { content, meta, thumbnail }
}

function validDimension(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0 && (value as number) <= MAX_DIMENSION
}

function validDuration(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= MAX_DURATION_SECONDS
}

/** Keeps only well-formed optional facts. */
export function cleanFacts(facts: unknown): MediaFacts {
  const out: MediaFacts = {}
  if (!facts || typeof facts !== 'object') return out
  const f = facts as Record<string, unknown>
  if (validDimension(f.width) && validDimension(f.height)) {
    out.width = f.width
    out.height = f.height
  }
  if (validDuration(f.duration)) out.duration = Math.round(f.duration * 1000) / 1000
  return out
}

async function unwrapItemKeys(vmk: CryptoKey, itemId: string, wrappedDek: Uint8Array<ArrayBuffer>): Promise<ItemKeys> {
  if (!isUuid(itemId) || wrappedDek.length !== WRAPPED_DEK_BYTES) throw new VaultCryptoError()
  const rawDek = await gcmDecrypt(
    vmk,
    wrappedDek.slice(0, GCM_IV_BYTES),
    wrappedDek.slice(GCM_IV_BYTES),
    concat(LABEL_DEK, uuidToBytes(itemId)),
  )
  try {
    if (rawDek.length !== AES_KEY_BYTES) throw new VaultCryptoError()
    return await failClosed(() => deriveItemKeys(rawDek, itemId))
  } finally {
    wipe(rawDek)
  }
}

/** Display-safe filename: strips control and bidi-override characters, path parts, and caps length. */
export function cleanFileName(name: unknown): string {
  if (typeof name !== 'string') return 'Untitled'
  const base = name.split(/[\\/]/).pop() ?? ''
  // eslint-disable-next-line no-control-regex
  const cleaned = base.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '').trim()
  return cleaned.slice(0, MAX_NAME_LENGTH) || 'Untitled'
}

function padMetadata(meta: ItemMetadata): Uint8Array<ArrayBuffer> {
  const json = utf8(JSON.stringify(meta))
  const total = Math.max(META_BLOCK, Math.ceil((4 + json.length) / META_BLOCK) * META_BLOCK)
  if (total > META_MAX_PADDED) throw new VaultCryptoError()
  const out = new Uint8Array(total)
  new DataView(out.buffer).setUint32(0, json.length)
  out.set(json, 4)
  return out
}

function unpadMetadata(padded: Uint8Array): ItemMetadata {
  if (padded.length < META_BLOCK || padded.length % META_BLOCK !== 0) throw new VaultCryptoError()
  const length = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0)
  if (length > padded.length - 4) throw new VaultCryptoError()
  for (let i = 4 + length; i < padded.length; i++) if (padded[i] !== 0) throw new VaultCryptoError()
  let parsed: unknown
  try {
    parsed = JSON.parse(fromUtf8(padded.subarray(4, 4 + length)))
  } catch {
    throw new VaultCryptoError()
  }
  // Authenticated, but still validated: only the fields and shapes we expect.
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new VaultCryptoError()
  const record = parsed as Record<string, unknown>
  if (record.v !== 1) throw new VaultCryptoError()
  if (!Number.isSafeInteger(record.size) || (record.size as number) < 0) throw new VaultCryptoError()
  if (record.modified !== null && !Number.isSafeInteger(record.modified)) throw new VaultCryptoError()
  return {
    v: 1,
    name: cleanFileName(record.name),
    mime: typeof record.mime === 'string' ? sniffTypeName(record.mime) : 'application/octet-stream',
    size: record.size as number,
    modified: record.modified as number | null,
    // Phase 4 optional fields; absent in Phase 3 items. Malformed values are dropped, not trusted.
    ...cleanFacts(record),
  }
}

function sniffTypeName(value: string): SniffedType {
  const known: SniffedType[] = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif', 'image/heic',
    'video/mp4', 'video/quicktime', 'video/webm', 'application/pdf',
  ]
  return (known as string[]).includes(value) ? (value as SniffedType) : 'application/octet-stream'
}

export interface EncryptedItem {
  wrappedDek: Uint8Array<ArrayBuffer>
  encryptedMeta: Uint8Array<ArrayBuffer>
  content: Uint8Array<ArrayBuffer>
  /** Encrypted thumbnail object (kind 0x02), present only if a thumbnail was supplied. */
  thumbnail: Uint8Array<ArrayBuffer> | null
}

/** Only these thumbnail encodings are accepted, produced, or displayed. */
export function isAcceptableThumbnail(bytes: Uint8Array): boolean {
  if (bytes.length === 0 || bytes.length > MAX_THUMBNAIL_BYTES) return false
  const type = sniffType(bytes.subarray(0, 64))
  return type === 'image/jpeg' || type === 'image/webp' || type === 'image/png'
}

/**
 * Encrypts one file locally. Generates a fresh random DEK, wraps it under the VMK,
 * encrypts the metadata, the entire content, and (if given) a locally generated
 * thumbnail. Nothing here touches the network.
 */
export async function encryptItem(
  vmk: CryptoKey,
  itemId: string,
  plaintext: Uint8Array<ArrayBuffer>,
  info: { name: string; modified: number | null; facts?: MediaFacts },
  thumbnail: Uint8Array<ArrayBuffer> | null = null,
): Promise<EncryptedItem> {
  if (!isUuid(itemId)) throw new VaultCryptoError()
  if (thumbnail && !isAcceptableThumbnail(thumbnail)) throw new VaultCryptoError()
  const rawDek = randomBytes(AES_KEY_BYTES)
  try {
    return await failClosed(async () => {
      const dekIv = randomBytes(GCM_IV_BYTES)
      const wrappedDek = concat(dekIv, await gcmEncrypt(vmk, dekIv, rawDek, concat(LABEL_DEK, uuidToBytes(itemId))))
      const keys = await deriveItemKeys(rawDek, itemId)

      const meta: ItemMetadata = {
        v: 1,
        name: cleanFileName(info.name),
        mime: sniffType(plaintext.subarray(0, 64)),
        size: plaintext.length,
        modified: Number.isSafeInteger(info.modified) ? info.modified : null,
        ...cleanFacts(info.facts),
      }
      const padded = padMetadata(meta)
      const metaIv = randomBytes(GCM_IV_BYTES)
      const encryptedMeta = concat(metaIv, await gcmEncrypt(keys.meta, metaIv, padded, concat(LABEL_META, uuidToBytes(itemId))))
      wipe(padded)

      const content = await encryptObject(keys.content, 'content', itemId, plaintext)
      const sealedThumbnail = thumbnail ? await encryptObject(keys.thumbnail, 'thumbnail', itemId, thumbnail) : null
      if (wrappedDek.length !== WRAPPED_DEK_BYTES) throw new VaultCryptoError()
      return { wrappedDek, encryptedMeta, content, thumbnail: sealedThumbnail }
    })
  } finally {
    wipe(rawDek)
  }
}

/** Decrypts a thumbnail object and checks it is a small raster image. Fails closed. */
export async function decryptItemThumbnail(
  vmk: CryptoKey,
  itemId: string,
  wrappedDek: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const keys = await unwrapItemKeys(vmk, itemId, wrappedDek)
  const plain = await decryptObject(keys.thumbnail, 'thumbnail', itemId, ciphertext)
  if (!isAcceptableThumbnail(plain)) {
    wipe(plain)
    throw new VaultCryptoError()
  }
  return plain
}

export async function decryptItemMetadata(
  vmk: CryptoKey,
  itemId: string,
  wrappedDek: Uint8Array<ArrayBuffer>,
  encryptedMeta: Uint8Array<ArrayBuffer>,
): Promise<ItemMetadata> {
  if (encryptedMeta.length < GCM_IV_BYTES + META_BLOCK + GCM_TAG_BYTES) throw new VaultCryptoError()
  const keys = await unwrapItemKeys(vmk, itemId, wrappedDek)
  const padded = await gcmDecrypt(
    keys.meta,
    encryptedMeta.slice(0, GCM_IV_BYTES),
    encryptedMeta.slice(GCM_IV_BYTES),
    concat(LABEL_META, uuidToBytes(itemId)),
  )
  try {
    return unpadMetadata(padded)
  } finally {
    wipe(padded)
  }
}

export async function decryptItemContent(
  vmk: CryptoKey,
  itemId: string,
  wrappedDek: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const keys = await unwrapItemKeys(vmk, itemId, wrappedDek)
  return decryptObject(keys.content, 'content', itemId, ciphertext)
}
