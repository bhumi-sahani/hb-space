/**
 * Byte helpers for the crypto layer. No secrets are logged or stringified here.
 */

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(text) as Uint8Array<ArrayBuffer>
}

/** Strict UTF-8 decode: throws on invalid sequences instead of substituting. */
export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes)
}

export function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

/** CSPRNG bytes. getRandomValues is limited to 65,536 bytes per call, so larger requests are filled in slices. */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(length)
  for (let offset = 0; offset < length; offset += 65536) {
    crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65536, length)))
  }
  return out
}

/** Best-effort wipe. JavaScript cannot guarantee that no other copy exists. */
export function wipe(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const buffer of buffers) buffer?.fill(0)
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_RE.test(value)
}

export function uuidToBytes(uuid: string): Uint8Array<ArrayBuffer> {
  if (!isUuid(uuid)) throw new Error('invalid uuid')
  const hex = uuid.replace(/-/g, '')
  const out = new Uint8Array(16)
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** Postgres bytea hex input/output format ("\x0a1b..."), as used by PostgREST. */
export function toByteaHex(bytes: Uint8Array): string {
  let hex = '\\x'
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0')
  return hex
}

const BYTEA_RE = /^\\x(?:[0-9a-f]{2})*$/

/** Strict parser for server-supplied bytea. Returns null for anything malformed. */
export function fromByteaHex(value: unknown): Uint8Array<ArrayBuffer> | null {
  if (typeof value !== 'string' || !BYTEA_RE.test(value)) return null
  const out = new Uint8Array((value.length - 2) / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(value.slice(2 + i * 2, 4 + i * 2), 16)
  return out
}

/** Reads a Blob without relying on Blob.arrayBuffer (missing in some test DOMs). */
export async function readBlob(blob: Blob): Promise<Uint8Array<ArrayBuffer>> {
  if (typeof blob.arrayBuffer === 'function') return new Uint8Array(await blob.arrayBuffer())
  return new Uint8Array(await new Response(blob).arrayBuffer())
}

// ---------------------------------------------------------------------------
// Crockford Base32, used only for displaying the one-time recovery code.
// ---------------------------------------------------------------------------
const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

export function toBase32(bytes: Uint8Array): string {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  return out
}

/** Accepts lowercase, spaces and dashes; maps the usual look-alikes (O→0, I/L→1). */
export function fromBase32(text: string, expectedBytes: number): Uint8Array<ArrayBuffer> | null {
  const clean = text.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1')
  if (clean.length !== Math.ceil((expectedBytes * 8) / 5)) return null
  const out = new Uint8Array(expectedBytes)
  let bits = 0
  let value = 0
  let index = 0
  for (const char of clean) {
    const digit = B32.indexOf(char)
    if (digit < 0) return null
    value = ((value << 5) | digit) & 0xffff
    bits += 5
    if (bits >= 8) {
      if (index < expectedBytes) out[index++] = (value >>> (bits - 8)) & 0xff
      bits -= 8
    }
  }
  // Trailing pad bits must be zero, so every code has exactly one valid spelling.
  if ((value & ((1 << bits) - 1)) !== 0) return null
  return index === expectedBytes ? out : null
}
