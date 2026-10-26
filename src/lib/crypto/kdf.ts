import { argon2id } from 'hash-wasm'
import { VaultCryptoError } from './primitives'

/**
 * Passphrase -> key-encryption key (KEK) with Argon2id (hash-wasm, WebAssembly).
 *
 * Parameters are stored per envelope and validated before use. Anything outside
 * the accepted range is rejected, never clamped or replaced, so a tampered row
 * can neither lower the cost nor exhaust memory. The same bounds are enforced
 * by the database (private.argon2id_params_valid).
 */

export interface Argon2Params {
  /** Memory in KiB. */
  m: number
  /** Iterations (passes). */
  t: number
  /** Parallelism (lanes). Browsers run single-threaded, so this must be 1. */
  p: number
}

export const KDF_ID = 'argon2id-v1'

/** v1 defaults: 64 MiB, 3 passes, 1 lane (RFC 9106 second recommendation with p = 1). */
export const DEFAULT_ARGON2_PARAMS: Readonly<Argon2Params> = Object.freeze({ m: 65536, t: 3, p: 1 })

export const ARGON2_BOUNDS = Object.freeze({ minM: 16384, maxM: 1048576, minT: 1, maxT: 10 })

export const KDF_SALT_BYTES = 16
export const MAX_PASSPHRASE_LENGTH = 1024

/** Returns validated params or null. Rejects extra keys, non-integers, and out-of-range values. */
export function parseArgon2Params(value: unknown): Argon2Params | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const keys = Object.keys(value).sort()
  if (keys.length !== 3 || keys[0] !== 'm' || keys[1] !== 'p' || keys[2] !== 't') return null
  const { m, t, p } = value as Record<string, unknown>
  if (!Number.isSafeInteger(m) || !Number.isSafeInteger(t) || !Number.isSafeInteger(p)) return null
  const params = { m: m as number, t: t as number, p: p as number }
  if (params.m < ARGON2_BOUNDS.minM || params.m > ARGON2_BOUNDS.maxM) return null
  if (params.t < ARGON2_BOUNDS.minT || params.t > ARGON2_BOUNDS.maxT) return null
  if (params.p !== 1) return null
  return params
}

/**
 * Passphrase policy (owner decision, 2026-10-26): any non-empty passphrase is
 * accepted; there is no minimum length or strength rule. Only an empty value
 * and the technical maximum are refused. Returns a user-facing problem, or null.
 *
 * Trade-off: the passphrase is the only thing protecting the vault key if the
 * database is ever copied. A short or guessable passphrase can be brute-forced
 * offline despite Argon2id (see SECURITY_ARCHITECTURE.md §13).
 */
export function checkNewPassphrase(passphrase: string): string | null {
  if (passphrase.length === 0) return 'Enter a vault passphrase.'
  if (passphrase.length > MAX_PASSPHRASE_LENGTH) return 'That passphrase is too long.'
  return null
}

/**
 * Derives 32 raw KEK bytes. The caller must import and then wipe them.
 * Unicode is normalised (NFC) so the same passphrase typed on different
 * devices produces the same key.
 */
export async function deriveKekBytes(passphrase: string, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array<ArrayBuffer>> {
  const valid = parseArgon2Params(params)
  if (!valid || salt.length !== KDF_SALT_BYTES || passphrase.length === 0 || passphrase.length > MAX_PASSPHRASE_LENGTH) {
    throw new VaultCryptoError()
  }
  try {
    const out = await argon2id({
      password: passphrase.normalize('NFC'),
      salt,
      parallelism: valid.p,
      iterations: valid.t,
      memorySize: valid.m,
      hashLength: 32,
      outputType: 'binary',
    })
    // Return hash-wasm's buffer itself (no extra copy) so the caller's wipe reaches it.
    return out as Uint8Array<ArrayBuffer>
  } catch {
    throw new VaultCryptoError()
  }
}
