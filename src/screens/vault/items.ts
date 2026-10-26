import type { VaultItem } from '../../services/media'

/** Display title for any item state. Names are decrypted locally; nothing here comes from the server in plaintext. */
export function itemTitle(item: VaultItem): string {
  if (item.state === 'ready') return item.meta.name
  if (item.state === 'incomplete') return 'Unfinished upload'
  return 'Unreadable item'
}

export function isVideo(item: VaultItem): boolean {
  return item.state === 'ready' && item.meta.mime.startsWith('video/')
}

/**
 * Finished items directly inside `folderId` (null = vault root). There is no
 * trash any more: items trashed by an earlier version show up again here.
 */
export function activeItemsIn(items: VaultItem[], folderId: string | null): VaultItem[] {
  return items.filter((i) => i.record.status === 'ready' && i.record.folderId === folderId)
}

/** Total encrypted bytes of every item record in the vault (finished and unfinished uploads). */
export function vaultUsedBytes(items: { record: { ciphertextSize: number } }[]): number {
  let total = 0
  for (const item of items) total += item.record.ciphertextSize
  return total
}
