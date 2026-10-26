// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { equalBytes, fromBase32, randomBytes, toBase32, utf8, wipe } from './bytes'
import {
  deriveKeyProof,
  formatRecoveryCode,
  generateRawVmk,
  importVmk,
  openEnvelope,
  parseRecoveryCode,
  sealPassphraseEnvelope,
  sealRecoveryEnvelope,
  type SealedEnvelope,
  type StoredEnvelope,
} from './envelope'
import { decryptItemContent, decryptItemMetadata, encryptItem, cleanFileName } from './item'
import { checkNewPassphrase, deriveKekBytes, parseArgon2Params, DEFAULT_ARGON2_PARAMS } from './kdf'
import { CHUNK_SIZE, ciphertextLength, decryptObject, encryptObject, FORMAT_MAGIC, HEADER_BYTES } from './mediaFormat'
import { VaultCryptoError } from './primitives'
import { sniffType } from './sniff'

const VAULT = '0f0e0d0c-0b0a-4908-8706-050403020100'
const OTHER_VAULT = '1f0e0d0c-0b0a-4908-8706-050403020100'
// Fast but in-bounds Argon2id parameters for tests. Production uses DEFAULT_ARGON2_PARAMS.
const TEST_PARAMS = { m: 16384, t: 1, p: 1 }

async function aesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

function flip(bytes: Uint8Array<ArrayBuffer>, index: number): Uint8Array<ArrayBuffer> {
  const copy = bytes.slice()
  copy[index] ^= 0x01
  return copy
}

/** True if `needle` occurs anywhere in `haystack`. */
function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return true
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer
    return true
  }
  return false
}

async function stored(env: SealedEnvelope, vaultId: string, rawVmk: Uint8Array<ArrayBuffer>): Promise<StoredEnvelope> {
  const { verifier } = await deriveKeyProof(rawVmk, vaultId)
  return { ...env, vaultId, keyVerifier: verifier, revision: 1 }
}

// ---------------------------------------------------------------------------
describe('media encryption (AES-256-GCM, STREAM format)', () => {
  const item = crypto.randomUUID()

  it('1. encrypt -> decrypt returns the exact original bytes', async () => {
    const key = await aesKey()
    const plain = randomBytes(5000)
    const sealed = await encryptObject(key, 'content', item, plain)
    expect(equalBytes(await decryptObject(key, 'content', item, sealed), plain)).toBe(true)
  })

  it('2. every encryption uses fresh randomness: same input never gives the same ciphertext or nonce prefix', async () => {
    const key = await aesKey()
    const plain = utf8('same plaintext')
    const seen = new Set<string>()
    for (let i = 0; i < 50; i++) {
      const sealed = await encryptObject(key, 'content', item, plain)
      seen.add(toBase32(sealed.subarray(12, 19))) // nonce prefix
    }
    expect(seen.size).toBe(50)
  })

  it('3. tampered ciphertext fails closed (body, tag, and header bytes)', async () => {
    const key = await aesKey()
    const sealed = await encryptObject(key, 'content', item, randomBytes(300))
    for (const index of [HEADER_BYTES, HEADER_BYTES + 150, sealed.length - 1, 13 /* nonce prefix */]) {
      await expect(decryptObject(key, 'content', item, flip(sealed, index))).rejects.toBeInstanceOf(VaultCryptoError)
    }
  })

  it('4. tampered IV / nonce material fails, and per-item IVs in wrapped keys are checked', async () => {
    const vmk = await aesKey()
    const plain = randomBytes(100)
    const enc = await encryptItem(vmk, item, plain, { name: 'a.bin', modified: null })
    // wrapped DEK IV is its first 12 bytes; metadata IV is the first 12 bytes of encrypted_meta
    await expect(decryptItemContent(vmk, item, flip(enc.wrappedDek, 0), enc.content)).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(decryptItemMetadata(vmk, item, enc.wrappedDek, flip(enc.encryptedMeta, 3))).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(decryptItemContent(vmk, item, enc.wrappedDek, flip(enc.content, 15))).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('5. wrong key fails closed', async () => {
    const sealed = await encryptObject(await aesKey(), 'content', item, randomBytes(64))
    await expect(decryptObject(await aesKey(), 'content', item, sealed)).rejects.toBeInstanceOf(VaultCryptoError)
    const enc = await encryptItem(await aesKey(), item, randomBytes(64), { name: 'x', modified: null })
    await expect(decryptItemContent(await aesKey(), item, enc.wrappedDek, enc.content)).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('6. an empty file round-trips (one final chunk, 56 bytes total)', async () => {
    const key = await aesKey()
    const sealed = await encryptObject(key, 'content', item, new Uint8Array(0))
    expect(sealed.length).toBe(56)
    expect((await decryptObject(key, 'content', item, sealed)).length).toBe(0)
  })

  it('7. arbitrary binary data (all byte values) round-trips', async () => {
    const key = await aesKey()
    const plain = new Uint8Array(256 * 4).map((_, i) => i % 256)
    expect(equalBytes(await decryptObject(key, 'content', item, await encryptObject(key, 'content', item, plain)), plain)).toBe(true)
  })

  it('8. large multi-chunk files round-trip at the chunk boundaries and at the upload limit', async () => {
    const key = await aesKey()
    for (const size of [CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE, 49 * 1024 * 1024]) {
      const plain = new Uint8Array(size)
      for (let off = 0; off < size; off += 65536) crypto.getRandomValues(plain.subarray(off, Math.min(off + 65536, size)))
      const sealed = await encryptObject(key, 'content', item, plain)
      expect(sealed.length).toBe(ciphertextLength(size))
      expect(equalBytes(await decryptObject(key, 'content', item, sealed), plain)).toBe(true)
    }
  }, 120_000)

  it('rejects truncation, appended data, chunk reordering, a different item id, and the wrong object kind', async () => {
    const key = await aesKey()
    const sealed = await encryptObject(key, 'content', item, randomBytes(2 * CHUNK_SIZE + 10))
    const chunk = CHUNK_SIZE + 16
    // Drop the final chunk: remaining chunks lack the "last" flag.
    await expect(decryptObject(key, 'content', item, sealed.slice(0, HEADER_BYTES + 2 * chunk))).rejects.toBeInstanceOf(VaultCryptoError)
    // Append a byte.
    const appended = new Uint8Array(sealed.length + 1)
    appended.set(sealed)
    await expect(decryptObject(key, 'content', item, appended)).rejects.toBeInstanceOf(VaultCryptoError)
    // Swap the first two chunks.
    const swapped = sealed.slice()
    swapped.set(sealed.subarray(HEADER_BYTES + chunk, HEADER_BYTES + 2 * chunk), HEADER_BYTES)
    swapped.set(sealed.subarray(HEADER_BYTES, HEADER_BYTES + chunk), HEADER_BYTES + chunk)
    await expect(decryptObject(key, 'content', item, swapped)).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(decryptObject(key, 'content', crypto.randomUUID(), sealed)).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(decryptObject(key, 'thumbnail', item, sealed)).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('rejects malformed input before decrypting (bad magic, version, reserved bytes, too short)', async () => {
    const key = await aesKey()
    const sealed = await encryptObject(key, 'content', item, randomBytes(10))
    for (const index of [0, 4, 6, 9, 20]) {
      await expect(decryptObject(key, 'content', item, flip(sealed, index))).rejects.toBeInstanceOf(VaultCryptoError)
    }
    await expect(decryptObject(key, 'content', item, sealed.slice(0, 50))).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(decryptObject(key, 'content', item, new Uint8Array(0))).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('errors carry no detail about why decryption failed', async () => {
    const error = await decryptObject(await aesKey(), 'content', item, new Uint8Array(100)).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(VaultCryptoError)
    expect((error as Error).message).toBe('vault crypto operation failed')
  })
})

// ---------------------------------------------------------------------------
describe('vault master key and envelopes', () => {
  it('9. the generated master key is 256 bits, random, and imported non-extractable', async () => {
    const a = generateRawVmk()
    const b = generateRawVmk()
    expect(a.length).toBe(32)
    expect(equalBytes(a, b)).toBe(false)
    const key = await importVmk(a)
    expect(key.extractable).toBe(false)
    expect((key.algorithm as AesKeyAlgorithm).length).toBe(256)
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow()
  })

  it('14. the correct passphrase unwraps the exact master key', async () => {
    const raw = generateRawVmk()
    const env = await stored(await sealPassphraseEnvelope(raw, 'correct horse battery staple', VAULT, TEST_PARAMS), VAULT, raw)
    const opened = await openEnvelope(env, 'correct horse battery staple')
    expect(equalBytes(opened, raw)).toBe(true)
  })

  it('13. a wrong passphrase cannot unwrap the master key', async () => {
    const raw = generateRawVmk()
    const env = await stored(await sealPassphraseEnvelope(raw, 'correct horse battery staple', VAULT, TEST_PARAMS), VAULT, raw)
    await expect(openEnvelope(env, 'correct horse battery stapl')).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(openEnvelope(env, '')).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('envelopes are bound to their vault, kind, salt, and parameters', async () => {
    const raw = generateRawVmk()
    const pass = 'correct horse battery staple'
    const env = await stored(await sealPassphraseEnvelope(raw, pass, VAULT, TEST_PARAMS), VAULT, raw)
    await expect(openEnvelope({ ...env, vaultId: OTHER_VAULT }, pass)).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(openEnvelope({ ...env, salt: flip(env.salt, 0) }, pass)).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(openEnvelope({ ...env, iv: flip(env.iv, 0) }, pass)).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(openEnvelope({ ...env, wrappedKey: flip(env.wrappedKey, 47) }, pass)).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(openEnvelope({ ...env, kdfParams: { m: 16384, t: 2, p: 1 } }, pass)).rejects.toBeInstanceOf(VaultCryptoError)
    // A verifier that does not belong to this key is refused even though the passphrase is right.
    await expect(openEnvelope({ ...env, keyVerifier: randomBytes(32) }, pass)).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('every wrap uses a fresh salt and IV', async () => {
    const raw = generateRawVmk()
    const a = await sealPassphraseEnvelope(raw, 'same passphrase here', VAULT, TEST_PARAMS)
    const b = await sealPassphraseEnvelope(raw, 'same passphrase here', VAULT, TEST_PARAMS)
    expect(equalBytes(a.salt, b.salt)).toBe(false)
    expect(equalBytes(a.iv, b.iv)).toBe(false)
    expect(equalBytes(a.wrappedKey, b.wrappedKey)).toBe(false)
  })

  it('the recovery code opens the same master key; a wrong code does not', async () => {
    const raw = generateRawVmk()
    const { envelope, recoveryCode } = await sealRecoveryEnvelope(raw, VAULT)
    const env = await stored(envelope, VAULT, raw)
    expect(recoveryCode).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{1,4}){6}$/)
    expect(equalBytes(await openEnvelope(env, recoveryCode.toLowerCase().replace(/-/g, ' ')), raw)).toBe(true)
    const wrong = formatRecoveryCode(randomBytes(16))
    await expect(openEnvelope(env, wrong)).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(openEnvelope(env, 'not a code')).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('the key proof is deterministic per key and vault, and the verifier is its SHA-256', async () => {
    const raw = generateRawVmk()
    const a = await deriveKeyProof(raw, VAULT)
    const b = await deriveKeyProof(raw, VAULT)
    const c = await deriveKeyProof(raw, OTHER_VAULT)
    const d = await deriveKeyProof(generateRawVmk(), VAULT)
    expect(equalBytes(a.proof, b.proof)).toBe(true)
    expect(equalBytes(a.proof, c.proof)).toBe(false)
    expect(equalBytes(a.proof, d.proof)).toBe(false)
    expect(equalBytes(a.verifier, new Uint8Array(await crypto.subtle.digest('SHA-256', a.proof)))).toBe(true)
    // Neither value is (or contains) the key itself.
    expect(contains(a.proof, raw.subarray(0, 8))).toBe(false)
    expect(contains(a.verifier, raw.subarray(0, 8))).toBe(false)
  })

  it('hash-wasm Argon2id matches the reference implementation known-answer vector', async () => {
    // phc-winner-argon2 src/test.c: argon2id v=19, t=2, m=2^16, p=1, "password", "somesalt".
    const { argon2id } = await import('hash-wasm')
    const hex = await argon2id({
      password: 'password',
      salt: utf8('somesalt'),
      iterations: 2,
      memorySize: 65536,
      parallelism: 1,
      hashLength: 32,
      outputType: 'hex',
    })
    expect(hex).toBe('09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7')
  }, 30_000)

  it('Argon2id derivation is deterministic, 32 bytes, and Unicode-normalised', async () => {
    const salt = new Uint8Array(16).fill(2)
    const a = await deriveKekBytes('passphrase', salt, TEST_PARAMS)
    const b = await deriveKekBytes('passphrase', salt, TEST_PARAMS)
    expect(a.length).toBe(32)
    expect(equalBytes(a, b)).toBe(true)
    // NFC normalisation: precomposed and decomposed "é" derive the same key.
    const c = await deriveKekBytes('caf\u00e9 passphrase', salt, TEST_PARAMS)
    const d = await deriveKekBytes('cafe\u0301 passphrase', salt, TEST_PARAMS)
    expect(equalBytes(c, d)).toBe(true)
    wipe(a, b, c, d)
  })

  it('the production parameters are 64 MiB, 3 passes, 1 lane, and are accepted', async () => {
    expect(DEFAULT_ARGON2_PARAMS).toEqual({ m: 65536, t: 3, p: 1 })
    expect(parseArgon2Params({ ...DEFAULT_ARGON2_PARAMS })).toEqual(DEFAULT_ARGON2_PARAMS)
    const out = await deriveKekBytes('passphrase', new Uint8Array(16), DEFAULT_ARGON2_PARAMS)
    expect(out.length).toBe(32)
  }, 30_000)

  it.each([
    ['memory too low', { m: 1024, t: 3, p: 1 }],
    ['memory too high', { m: 2 ** 21, t: 3, p: 1 }],
    ['zero passes', { m: 65536, t: 0, p: 1 }],
    ['too many passes', { m: 65536, t: 11, p: 1 }],
    ['parallelism', { m: 65536, t: 3, p: 2 }],
    ['extra key', { m: 65536, t: 3, p: 1, x: 1 }],
    ['missing key', { m: 65536, t: 3 }],
    ['string', { m: '65536', t: 3, p: 1 }],
    ['fraction', { m: 65536.5, t: 3, p: 1 }],
    ['array', [65536, 3, 1]],
    ['null', null],
  ])('KDF parameters are rejected, never weakened: %s', async (_label, params) => {
    expect(parseArgon2Params(params)).toBeNull()
    await expect(deriveKekBytes('passphrase', new Uint8Array(16), params as never)).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('passphrase policy requires a reasonable length', () => {
    // Owner decision: any non-empty passphrase is accepted (no length or strength rule).
    expect(checkNewPassphrase('')).not.toBeNull()
    expect(checkNewPassphrase('a')).toBeNull()
    expect(checkNewPassphrase('1234')).toBeNull()
    expect(checkNewPassphrase(' spaces at the ends ')).toBeNull()
    expect(checkNewPassphrase('four random words here')).toBeNull()
    expect(checkNewPassphrase('x'.repeat(1025))).not.toBeNull()
  })

  it('recovery-code text encoding is strict and round-trips', () => {
    const bytes = randomBytes(16)
    const text = formatRecoveryCode(bytes)
    expect(equalBytes(parseRecoveryCode(text) as Uint8Array, bytes)).toBe(true)
    expect(parseRecoveryCode(text.slice(0, -1))).toBeNull()
    expect(fromBase32(toBase32(bytes).slice(0, -1) + 'U', 16)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
describe('metadata protection', () => {
  const item = crypto.randomUUID()

  it('16/17. metadata is encrypted, padded, and contains no plaintext name or type', async () => {
    const vmk = await aesKey()
    const name = 'HB_SPACE_PHASE3_secret_birthday_photo.jpg'
    const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, ...randomBytes(500)])
    const enc = await encryptItem(vmk, item, jpeg, { name, modified: 1700000000000 })
    expect((enc.encryptedMeta.length - 28) % 256).toBe(0)
    for (const needle of [name, 'birthday', 'image/jpeg', 'jpeg', '1700000000000', '"name"']) {
      expect(contains(enc.encryptedMeta, utf8(needle))).toBe(false)
      expect(contains(enc.content, utf8(needle))).toBe(false)
      expect(contains(enc.wrappedDek, utf8(needle))).toBe(false)
    }
    const meta = await decryptItemMetadata(vmk, item, enc.wrappedDek, enc.encryptedMeta)
    expect(meta).toEqual({ v: 1, name, mime: 'image/jpeg', size: jpeg.length, modified: 1700000000000 })
  })

  it('padding hides small differences in filename length', async () => {
    const vmk = await aesKey()
    const a = await encryptItem(vmk, item, new Uint8Array(1), { name: 'a', modified: null })
    const b = await encryptItem(vmk, item, new Uint8Array(1), { name: 'a much longer file name.mov', modified: null })
    expect(a.encryptedMeta.length).toBe(b.encryptedMeta.length)
  })

  it('metadata from one item cannot be attached to another item', async () => {
    const vmk = await aesKey()
    const other = crypto.randomUUID()
    const enc = await encryptItem(vmk, item, new Uint8Array(1), { name: 'a', modified: null })
    await expect(decryptItemMetadata(vmk, other, enc.wrappedDek, enc.encryptedMeta)).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('MIME type comes from the bytes, never the name', async () => {
    const vmk = await aesKey()
    const enc = await encryptItem(vmk, item, utf8('<svg onload=alert(1)>'), { name: 'innocent.jpg', modified: null })
    const meta = await decryptItemMetadata(vmk, item, enc.wrappedDek, enc.encryptedMeta)
    expect(meta.mime).toBe('application/octet-stream')
    expect(sniffType(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))).toBe('image/png')
  })

  it('filenames are cleaned of paths and control/bidi characters', () => {
    expect(cleanFileName('../../etc/passwd')).toBe('passwd')
    expect(cleanFileName('C:\\Users\\x\\photo.jpg')).toBe('photo.jpg')
    expect(cleanFileName('evil\u202Egpj.exe')).toBe('evilgpj.exe')
    expect(cleanFileName('')).toBe('Untitled')
    expect(cleanFileName(42)).toBe('Untitled')
  })
})

// ---------------------------------------------------------------------------
describe('critical ciphertext fixture: HB_SPACE_PHASE3_TEST_FILE', () => {
  it('23. what would be uploaded differs from the original and decrypts to the exact original', async () => {
    const original = utf8('HB_SPACE_PHASE3_TEST_FILE\n' + 'synthetic test content, not a real photo\n'.repeat(100))
    const vmk = await importVmk(generateRawVmk())
    const item = crypto.randomUUID()
    const enc = await encryptItem(vmk, item, original, { name: 'HB_SPACE_PHASE3_TEST_FILE.bin', modified: null })
    const uploaded = enc.content

    expect(equalBytes(uploaded, original)).toBe(false)
    expect(contains(uploaded, utf8('HB_SPACE_PHASE3_TEST_FILE'))).toBe(false)
    expect(contains(uploaded, utf8('synthetic test content'))).toBe(false)
    expect(equalBytes(uploaded.subarray(0, 4), FORMAT_MAGIC)).toBe(true)
    expect(uploaded.length).toBe(ciphertextLength(original.length))

    const downloaded = uploaded.slice() // what Storage would return
    expect(equalBytes(await decryptItemContent(vmk, item, enc.wrappedDek, downloaded), original)).toBe(true)
  })
})
