import { useSyncExternalStore } from 'react'
import { getVaultStatus, subscribeVaultStatus, type VaultStatus } from '../services/vaultSession'

/** Locked/unlocked only. The key itself never enters React. */
export function useVaultStatus(): VaultStatus {
  return useSyncExternalStore(subscribeVaultStatus, getVaultStatus, getVaultStatus)
}
