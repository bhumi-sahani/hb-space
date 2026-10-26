import { equalBytes, wipe } from '../lib/crypto/bytes'
import {
  deriveKeyProof,
  generateRawVmk,
  importVmk,
  openEnvelope,
  sealPassphraseEnvelope,
  sealRecoveryEnvelope,
  type SealedEnvelope,
  type StoredEnvelope,
} from '../lib/crypto/envelope'
import { checkNewPassphrase, DEFAULT_ARGON2_PARAMS, type Argon2Params } from '../lib/crypto/kdf'
import { VaultCryptoError } from '../lib/crypto/primitives'
import { BackendError, type VaultBackend } from './vaultBackend'
import { lockVault, setUnlockedKey } from './vaultSession'

/**
 * Vault key management. Every operation that writes key material first opens
 * an existing envelope with the user's secret (passphrase or recovery code),
 * which yields the raw VMK only briefly. From it we derive the key-possession
 * proof the server requires for the write (finding F2), then wipe it.
 */

export const KEY_MESSAGES = {
  unlockFailed: 'Unable to unlock the vault.',
  recoveryFailed: 'Unable to use that recovery code.',
  wrongCurrent: 'Unable to confirm your current vault passphrase.',
  conflict: 'The vault keys were changed on another device. Reload and try again.',
  notSetUp: 'The vault database needs the Phase 3 update. Apply the new migration, then try again.',
  network: 'Cannot reach the server. Check your connection and try again.',
  generic: 'Something went wrong. Nothing was changed. Please try again.',
  mismatch: 'The two passphrases do not match.',
} as const

export class VaultKeyError extends Error {
  readonly userMessage: string
  constructor(userMessage: string) {
    super(userMessage)
    this.name = 'VaultKeyError'
    this.userMessage = userMessage
  }
}

function backendMessage(error: unknown): string {
  if (error instanceof BackendError) {
    if (error.kind === 'not-set-up') return KEY_MESSAGES.notSetUp
    if (error.kind === 'network') return KEY_MESSAGES.network
    if (error.kind === 'conflict') return KEY_MESSAGES.conflict
  }
  return KEY_MESSAGES.generic
}

/** Runs fn; crypto failures become `cryptoMessage`, backend failures their own fixed message. */
async function guarded<T>(cryptoMessage: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (error) {
    if (error instanceof VaultKeyError) throw error
    if (error instanceof VaultCryptoError) throw new VaultKeyError(cryptoMessage)
    throw new VaultKeyError(backendMessage(error))
  }
}

export type KeyState =
  | { status: 'uninitialized' }
  | { status: 'ready'; passphrase: StoredEnvelope; recovery: StoredEnvelope | null }
  | { status: 'inconsistent' }

export async function loadKeyState(backend: VaultBackend, vaultId: string): Promise<KeyState> {
  const envelopes = await guarded(KEY_MESSAGES.generic, () => backend.listEnvelopes(vaultId))
  if (envelopes.length === 0) return { status: 'uninitialized' }
  const passphrase = envelopes.find((e) => e.kind === 'passphrase')
  const recovery = envelopes.find((e) => e.kind === 'recovery') ?? null
  if (!passphrase) return { status: 'inconsistent' }
  // All envelopes of one vault must commit to the same VMK.
  if (recovery && !equalBytes(recovery.keyVerifier, passphrase.keyVerifier)) return { status: 'inconsistent' }
  return { status: 'ready', passphrase, recovery }
}

async function requireReady(backend: VaultBackend, vaultId: string) {
  const state = await loadKeyState(backend, vaultId)
  if (state.status !== 'ready') throw new VaultKeyError(KEY_MESSAGES.generic)
  return state
}

async function unlockSessionWith(vaultId: string, rawVmk: Uint8Array<ArrayBuffer>) {
  const vmk = await importVmk(rawVmk)
  setUnlockedKey(vaultId, vmk)
}

// ---------------------------------------------------------------------------
// First-time setup
// ---------------------------------------------------------------------------

export interface PreparedVault {
  /** Show once; the user must write it down before committing. */
  recoveryCode: string
  /** Stores both envelopes and unlocks this device. */
  commit(): Promise<void>
  /** Abandons setup; nothing was stored. */
  discard(): void
}

/**
 * Generates the VMK and both envelopes locally. Nothing is sent until commit().
 * The raw VMK is wiped before this returns; only a non-extractable key and the
 * one-time proof are kept until commit/discard.
 */
export async function prepareNewVault(
  backend: VaultBackend,
  vaultId: string,
  passphrase: string,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS,
): Promise<PreparedVault> {
  const problem = checkNewPassphrase(passphrase)
  if (problem) throw new VaultKeyError(problem)
  return guarded(KEY_MESSAGES.generic, async () => {
    const existing = await loadKeyState(backend, vaultId)
    if (existing.status !== 'uninitialized') throw new VaultKeyError(KEY_MESSAGES.conflict)

    const raw = generateRawVmk()
    let passphraseEnv: SealedEnvelope
    let recovery: { envelope: SealedEnvelope; recoveryCode: string }
    let proof: Uint8Array<ArrayBuffer>
    let verifier: Uint8Array<ArrayBuffer>
    let vmk: CryptoKey
    try {
      passphraseEnv = await sealPassphraseEnvelope(raw, passphrase, vaultId, params)
      recovery = await sealRecoveryEnvelope(raw, vaultId)
      ;({ proof, verifier } = await deriveKeyProof(raw, vaultId))
      vmk = await importVmk(raw)
    } finally {
      wipe(raw)
    }

    let done = false
    return {
      recoveryCode: recovery.recoveryCode,
      async commit() {
        if (done) throw new VaultKeyError(KEY_MESSAGES.generic)
        done = true
        try {
          await guarded(KEY_MESSAGES.generic, async () => {
            // The passphrase envelope establishes the verifier; the recovery envelope must match it.
            await backend.insertEnvelope(vaultId, passphraseEnv, verifier, proof)
            await backend.insertEnvelope(vaultId, recovery.envelope, verifier, proof)
          })
          setUnlockedKey(vaultId, vmk)
        } finally {
          wipe(proof)
        }
      },
      discard() {
        done = true
        wipe(proof)
      },
    }
  })
}

// ---------------------------------------------------------------------------
// Unlock
// ---------------------------------------------------------------------------

export async function unlockWithPassphrase(backend: VaultBackend, vaultId: string, passphrase: string): Promise<void> {
  lockVault()
  await guarded(KEY_MESSAGES.unlockFailed, async () => {
    const state = await requireReady(backend, vaultId)
    const raw = await openEnvelope(state.passphrase, passphrase)
    try {
      await unlockSessionWith(vaultId, raw)
    } finally {
      wipe(raw)
    }
  })
}

// ---------------------------------------------------------------------------
// Re-wrapping (same VMK, new secret: no media is re-encrypted)
// ---------------------------------------------------------------------------

/** Changes the shared vault passphrase. Requires the current one. */
export async function changePassphrase(
  backend: VaultBackend,
  vaultId: string,
  currentPassphrase: string,
  newPassphrase: string,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS,
): Promise<void> {
  const problem = checkNewPassphrase(newPassphrase)
  if (problem) throw new VaultKeyError(problem)
  await guarded(KEY_MESSAGES.wrongCurrent, async () => {
    const state = await requireReady(backend, vaultId)
    const raw = await openEnvelope(state.passphrase, currentPassphrase)
    try {
      await rewrapPassphrase(backend, vaultId, raw, newPassphrase, params, state.passphrase.revision)
    } finally {
      wipe(raw)
    }
  })
}

/** Opens the recovery envelope, sets a new passphrase, and unlocks this device. */
export async function resetPassphraseWithRecoveryCode(
  backend: VaultBackend,
  vaultId: string,
  recoveryCode: string,
  newPassphrase: string,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS,
): Promise<void> {
  const problem = checkNewPassphrase(newPassphrase)
  if (problem) throw new VaultKeyError(problem)
  lockVault()
  await guarded(KEY_MESSAGES.recoveryFailed, async () => {
    const state = await requireReady(backend, vaultId)
    if (!state.recovery) throw new VaultCryptoError()
    const raw = await openEnvelope(state.recovery, recoveryCode)
    try {
      await rewrapPassphrase(backend, vaultId, raw, newPassphrase, params, state.passphrase.revision)
      await unlockSessionWith(vaultId, raw)
    } finally {
      wipe(raw)
    }
  })
}

async function rewrapPassphrase(
  backend: VaultBackend,
  vaultId: string,
  raw: Uint8Array<ArrayBuffer>,
  newPassphrase: string,
  params: Argon2Params,
  revision: number,
) {
  const sealed = await sealPassphraseEnvelope(raw, newPassphrase, vaultId, params)
  const { proof } = await deriveKeyProof(raw, vaultId)
  try {
    await backend.updateEnvelope(vaultId, sealed, proof, revision)
  } finally {
    wipe(proof)
  }
}

/**
 * Creates a replacement recovery code (also used if the recovery envelope is
 * missing). Requires the passphrase. The old code stops working on commit().
 */
export async function prepareNewRecoveryCode(
  backend: VaultBackend,
  vaultId: string,
  passphrase: string,
): Promise<{ recoveryCode: string; commit(): Promise<void>; discard(): void }> {
  return guarded(KEY_MESSAGES.wrongCurrent, async () => {
    const state = await requireReady(backend, vaultId)
    const raw = await openEnvelope(state.passphrase, passphrase)
    let sealed: { envelope: SealedEnvelope; recoveryCode: string }
    let proof: Uint8Array<ArrayBuffer>
    try {
      sealed = await sealRecoveryEnvelope(raw, vaultId)
      ;({ proof } = await deriveKeyProof(raw, vaultId))
    } finally {
      wipe(raw)
    }
    let done = false
    return {
      recoveryCode: sealed.recoveryCode,
      async commit() {
        if (done) throw new VaultKeyError(KEY_MESSAGES.generic)
        done = true
        try {
          await guarded(KEY_MESSAGES.generic, () =>
            state.recovery
              ? backend.updateEnvelope(vaultId, sealed.envelope, proof, state.recovery.revision)
              : backend.insertEnvelope(vaultId, sealed.envelope, state.passphrase.keyVerifier, proof),
          )
        } finally {
          wipe(proof)
        }
      },
      discard() {
        done = true
        wipe(proof)
      },
    }
  })
}
