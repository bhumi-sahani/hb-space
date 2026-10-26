import { concat, equalBytes, fromBase32, isUuid, randomBytes, toBase32, utf8, uuidToBytes, wipe } from './bytes'
import { deriveKekBytes, KDF_ID, KDF_SALT_BYTES, parseArgon2Params, type Argon2Params } from './kdf'
import {
  AES_KEY_BYTES,
  GCM_IV_BYTES,
  GCM_TAG_BYTES,
  VaultCryptoError,
  failClosed,
  gcmDecrypt,
  gcmEncrypt,
  hkdfAesKey,
  hkdfBytes,
  importAesKey,
  importHkdfKey,
  sha256,
} from './primitives'

/**
 * Key hierarchy (SECURITY_ARCHITECTURE.md §6.2):
 *
 *   vault passphrase --Argon2id--> KEK ----AES-GCM unwrap--+
 *   recovery code ----HKDF-------> RK  ----AES-GCM unwrap--+--> Vault Master Key (VMK, 256-bit random)
 *
 * Both envelopes wrap the SAME VMK; the VMK itself is never stored or sent.
 *
 * Key-possession proof (finding F2): proof = HKDF(VMK, "hbspace/key-proof/v1" || vault_id),
 * verifier = SHA-256(proof). The server stores only the verifier and accepts an
 * envelope write only when it is accompanied by the matching proof, so a
 * signed-in session that has NOT unlocked the vault cannot replace key material.
 * The proof is never stored (the database nulls it), and neither value reveals the VMK.
 */

export const ENVELOPE_FORMAT_VERSION = 1
export const RECOVERY_KDF_ID = 'hkdf-sha256-v1'
export const WRAPPED_KEY_BYTES = AES_KEY_BYTES + GCM_TAG_BYTES // 48
export const PROOF_BYTES = 32
export const RECOVERY_CODE_BYTES = 16 // 128 bits

export type EnvelopeKind = 'passphrase' | 'recovery'

/** The non-secret, storable fields of one envelope. */
export interface SealedEnvelope {
  kind: EnvelopeKind
  formatVersion: 1
  kdf: typeof KDF_ID | typeof RECOVERY_KDF_ID
  kdfParams: Argon2Params | null
  salt: Uint8Array<ArrayBuffer>
  iv: Uint8Array<ArrayBuffer>
  wrappedKey: Uint8Array<ArrayBuffer>
}

/** An envelope as read back from the server, after strict validation. */
export interface StoredEnvelope extends SealedEnvelope {
  vaultId: string
  keyVerifier: Uint8Array<ArrayBuffer>
  revision: number
}

const LABEL_VMK = utf8('hbspace/vmk/v1')
const LABEL_PROOF = utf8('hbspace/key-proof/v1')
const LABEL_RECOVERY = utf8('hbspace/recovery/v1')

function envelopeAad(vaultId: string, kind: EnvelopeKind): Uint8Array<ArrayBuffer> {
  const kindBytes = utf8(kind)
  return concat(LABEL_VMK, uuidToBytes(vaultId), Uint8Array.of(kindBytes.length), kindBytes, Uint8Array.of(ENVELOPE_FORMAT_VERSION))
}

/** Structural validation of an envelope's non-secret fields (server data is untrusted). */
export function isWellFormedEnvelope(env: SealedEnvelope): boolean {
  if (env.formatVersion !== ENVELOPE_FORMAT_VERSION) return false
  if (env.salt.length !== KDF_SALT_BYTES || env.iv.length !== GCM_IV_BYTES || env.wrappedKey.length !== WRAPPED_KEY_BYTES) {
    return false
  }
  if (env.kind === 'passphrase') return env.kdf === KDF_ID && parseArgon2Params(env.kdfParams) !== null
  if (env.kind === 'recovery') return env.kdf === RECOVERY_KDF_ID && env.kdfParams === null
  return false
}

// ---------------------------------------------------------------------------
// Key-encryption keys
// ---------------------------------------------------------------------------

async function passphraseKek(passphrase: string, salt: Uint8Array<ArrayBuffer>, params: Argon2Params): Promise<CryptoKey> {
  const raw = await deriveKekBytes(passphrase, salt, params)
  try {
    return await importAesKey(raw)
  } finally {
    wipe(raw)
  }
}

async function recoveryKek(code: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>, vaultId: string): Promise<CryptoKey> {
  if (code.length !== RECOVERY_CODE_BYTES) throw new VaultCryptoError()
  const base = await importHkdfKey(code)
  return hkdfAesKey(base, salt, concat(LABEL_RECOVERY, uuidToBytes(vaultId)))
}

// ---------------------------------------------------------------------------
// VMK generation, wrapping, unwrapping
// ---------------------------------------------------------------------------

/** 256 bits from the platform CSPRNG. Caller must wipe after use. */
export function generateRawVmk(): Uint8Array<ArrayBuffer> {
  return randomBytes(AES_KEY_BYTES)
}

/** Imports the VMK for use while unlocked: non-extractable, encrypt/decrypt only (wraps per-item keys). */
export function importVmk(rawVmk: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return failClosed(() => importAesKey(rawVmk))
}

async function seal(rawVmk: Uint8Array<ArrayBuffer>, kek: CryptoKey, vaultId: string, kind: EnvelopeKind) {
  if (rawVmk.length !== AES_KEY_BYTES) throw new VaultCryptoError()
  const iv = randomBytes(GCM_IV_BYTES) // fresh random IV for every wrap
  const wrappedKey = await gcmEncrypt(kek, iv, rawVmk, envelopeAad(vaultId, kind))
  return { iv, wrappedKey }
}

export async function sealPassphraseEnvelope(
  rawVmk: Uint8Array<ArrayBuffer>,
  passphrase: string,
  vaultId: string,
  params: Argon2Params,
): Promise<SealedEnvelope> {
  return failClosed(async () => {
    const salt = randomBytes(KDF_SALT_BYTES) // fresh salt on every (re)wrap
    const kek = await passphraseKek(passphrase, salt, params)
    const { iv, wrappedKey } = await seal(rawVmk, kek, vaultId, 'passphrase')
    return { kind: 'passphrase', formatVersion: 1, kdf: KDF_ID, kdfParams: { ...params }, salt, iv, wrappedKey }
  })
}

/** Creates a new recovery code and the envelope it opens. The code is returned for one-time display. */
export async function sealRecoveryEnvelope(
  rawVmk: Uint8Array<ArrayBuffer>,
  vaultId: string,
): Promise<{ envelope: SealedEnvelope; recoveryCode: string }> {
  return failClosed(async () => {
    const code = randomBytes(RECOVERY_CODE_BYTES)
    try {
      const salt = randomBytes(KDF_SALT_BYTES)
      const kek = await recoveryKek(code, salt, vaultId)
      const { iv, wrappedKey } = await seal(rawVmk, kek, vaultId, 'recovery')
      return {
        envelope: { kind: 'recovery', formatVersion: 1, kdf: RECOVERY_KDF_ID, kdfParams: null, salt, iv, wrappedKey },
        recoveryCode: formatRecoveryCode(code),
      }
    } finally {
      wipe(code)
    }
  })
}

/**
 * Opens an envelope and returns the raw VMK. The caller MUST wipe it.
 * Wrong secret, tampered envelope, or malformed input all throw the same
 * VaultCryptoError; there is no partial result.
 */
export async function openEnvelope(env: StoredEnvelope, secret: string): Promise<Uint8Array<ArrayBuffer>> {
  if (!isUuid(env.vaultId) || !isWellFormedEnvelope(env)) throw new VaultCryptoError()
  let kek: CryptoKey
  if (env.kind === 'passphrase') {
    kek = await passphraseKek(secret, env.salt, env.kdfParams as Argon2Params)
  } else {
    const code = parseRecoveryCode(secret)
    if (!code) throw new VaultCryptoError()
    try {
      kek = await failClosed(() => recoveryKek(code, env.salt, env.vaultId))
    } finally {
      wipe(code)
    }
  }
  const raw = await gcmDecrypt(kek, env.iv, env.wrappedKey, envelopeAad(env.vaultId, env.kind))
  if (raw.length !== AES_KEY_BYTES) {
    wipe(raw)
    throw new VaultCryptoError()
  }
  // The stored verifier must belong to this VMK. A mismatch means the server data is inconsistent: fail closed.
  const { proof, verifier } = await deriveKeyProof(raw, env.vaultId)
  wipe(proof)
  if (!equalBytes(verifier, env.keyVerifier)) {
    wipe(raw)
    throw new VaultCryptoError()
  }
  return raw
}

// ---------------------------------------------------------------------------
// Key-possession proof (F2)
// ---------------------------------------------------------------------------

export async function deriveKeyProof(rawVmk: Uint8Array<ArrayBuffer>, vaultId: string) {
  return failClosed(async () => {
    const base = await importHkdfKey(rawVmk)
    const proof = await hkdfBytes(base, new Uint8Array(0), concat(LABEL_PROOF, uuidToBytes(vaultId)), PROOF_BYTES)
    const verifier = await sha256(proof)
    return { proof, verifier }
  })
}

// ---------------------------------------------------------------------------
// Recovery code text format: 128 bits as 26 Crockford Base32 characters, grouped in fours.
// ---------------------------------------------------------------------------

export function formatRecoveryCode(code: Uint8Array): string {
  return (toBase32(code).match(/.{1,4}/g) ?? []).join('-')
}

export function parseRecoveryCode(text: string): Uint8Array<ArrayBuffer> | null {
  if (typeof text !== 'string' || text.length > 64) return null
  return fromBase32(text, RECOVERY_CODE_BYTES)
}
