/**
 * The in-memory crypto session: the ONLY place the unlocked vault key lives.
 *
 * - Holds a non-extractable AES-GCM CryptoKey for the VMK in a module-level
 *   variable. It is never put into React state, context, localStorage,
 *   sessionStorage, IndexedDB, URLs, or logs.
 * - React components see only the boolean status (via subscribe/getStatus).
 * - lockVault() drops the key reference, revokes every blob: URL created for
 *   decrypted media, and notifies listeners so the UI unmounts decrypted state.
 *
 * Logged in != vault unlocked. Signing in never sets a key here.
 *
 * Limitation: JavaScript cannot force memory to be erased. Dropping the
 * reference lets the browser free the key; it does not guarantee when.
 */

export type VaultStatus = 'locked' | 'unlocked'

interface Unlocked {
  vaultId: string
  vmk: CryptoKey
}

let current: Unlocked | null = null
const listeners = new Set<() => void>()
const objectUrls = new Set<string>()

function notify() {
  for (const listener of listeners) listener()
}

export function getVaultStatus(): VaultStatus {
  return current ? 'unlocked' : 'locked'
}

export function subscribeVaultStatus(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** Installs an unlocked key. Only callable with a non-extractable key. */
export function setUnlockedKey(vaultId: string, vmk: CryptoKey): void {
  if (vmk.extractable || vmk.type !== 'secret') throw new Error('refusing to hold an extractable vault key')
  current = { vaultId, vmk }
  notify()
}

/**
 * Returns the key for the given vault, or null if locked or the vault differs.
 * Callers must not store the returned key anywhere long-lived.
 */
export function getUnlockedKey(vaultId: string): CryptoKey | null {
  return current && current.vaultId === vaultId ? current.vmk : null
}

export function lockVault(): void {
  const wasUnlocked = current !== null
  current = null
  revokeAllObjectUrls()
  if (wasUnlocked) notify()
}

// ---------------------------------------------------------------------------
// blob: URLs for decrypted media. Tracked so locking can revoke all of them.
// ---------------------------------------------------------------------------

export function createTrackedObjectUrl(blob: Blob): string {
  if (!current) throw new Error('vault is locked')
  const url = URL.createObjectURL(blob)
  objectUrls.add(url)
  return url
}

export function revokeTrackedObjectUrl(url: string): void {
  if (objectUrls.delete(url)) URL.revokeObjectURL(url)
}

export function revokeAllObjectUrls(): void {
  for (const url of objectUrls) URL.revokeObjectURL(url)
  objectUrls.clear()
}

export function activeObjectUrlCount(): number {
  return objectUrls.size
}
