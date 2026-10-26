/**
 * Thin wrappers over Web Crypto. AES-256-GCM (96-bit IV, 128-bit tag) and
 * HKDF-SHA-256 only; nothing here implements a cipher by hand.
 */

export const AES_KEY_BYTES = 32
export const GCM_IV_BYTES = 12
export const GCM_TAG_BYTES = 16

/**
 * Every failure in the crypto layer surfaces as this one error with a fixed
 * message, so callers (and the UI) cannot tell a wrong key from tampered or
 * malformed data. The underlying exception is deliberately dropped.
 */
export class VaultCryptoError extends Error {
  constructor() {
    super('vault crypto operation failed')
    this.name = 'VaultCryptoError'
  }
}

/** Runs `fn`, converting any exception into the generic VaultCryptoError. */
export async function failClosed<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch {
    throw new VaultCryptoError()
  }
}

/** Imports 32 raw bytes as a non-extractable AES-256-GCM key. */
export async function importAesKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  if (raw.length !== AES_KEY_BYTES) throw new VaultCryptoError()
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

/** Imports raw input keying material as a non-extractable HKDF key. */
export async function importHkdfKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey', 'deriveBits'])
}

export async function hkdfAesKey(base: CryptoKey, salt: Uint8Array<ArrayBuffer>, info: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info }, base, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ])
}

export async function hkdfBytes(base: CryptoKey, salt: Uint8Array<ArrayBuffer>, info: Uint8Array<ArrayBuffer>, length: number) {
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, base, length * 8))
}

export async function sha256(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data))
}

export async function gcmEncrypt(
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (iv.length !== GCM_IV_BYTES) throw new VaultCryptoError()
  return new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plaintext),
  )
}

/** Authenticated decryption. Throws VaultCryptoError on any failure; never returns unverified bytes. */
export async function gcmDecrypt(
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (iv.length !== GCM_IV_BYTES || ciphertext.length < GCM_TAG_BYTES) throw new VaultCryptoError()
  return failClosed(
    async () =>
      new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, ciphertext)),
  )
}
