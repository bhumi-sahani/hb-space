import { cleanFolderName, decryptFolderMeta, encryptFolderMeta } from '../lib/crypto/folder'
import { backendAware, MediaError, requireKey } from './media'
import { BackendError, MAX_FOLDER_DEPTH, type FolderRecord, type VaultBackend } from './vaultBackend'

/**
 * Private folders. The server sees only opaque ids, a parent id, and an encrypted
 * name blob; names are encrypted/decrypted here with the unlocked vault key.
 */

export const FOLDER_MESSAGES = {
  nameRequired: 'Enter a folder name.',
  createFailed: 'Could not create the folder. Please try again.',
  tooDeep: `Folders can be nested at most ${MAX_FOLDER_DEPTH + 1} levels deep.`,
  renameFailed: 'Could not rename the folder. Please try again.',
  renameConflict: 'The folder changed on another device. Reload and try again.',
  notEmpty: 'This folder is not empty. Move or delete its photos and videos, and remove its subfolders first.',
  deleteFailed: 'Could not delete the folder. Please try again.',
  listFailed: 'Could not load folders. Please try again.',
} as const

export interface VaultFolder {
  id: string
  parentId: string | null
  /** Decrypted name, or null if the name could not be decrypted with this vault key. */
  name: string | null
  depth: number
  revision: number
  createdAt: string
  record: FolderRecord
}

export async function listVaultFolders(backend: VaultBackend, vaultId: string): Promise<{ folders: VaultFolder[]; damaged: number }> {
  const vmk = requireKey(vaultId)
  let listing: Awaited<ReturnType<VaultBackend['listFolders']>>
  try {
    listing = await backend.listFolders(vaultId)
  } catch (error) {
    throw backendAware(error, FOLDER_MESSAGES.listFailed)
  }
  const folders = await Promise.all(
    listing.records.map(async (record): Promise<VaultFolder> => {
      let name: string | null = null
      try {
        name = (await decryptFolderMeta(vmk, vaultId, record.id, record.encryptedMeta)).name
      } catch {
        name = null
      }
      return { id: record.id, parentId: record.parentId, name, depth: record.depth, revision: record.revision, createdAt: record.createdAt, record }
    }),
  )
  requireKey(vaultId)
  return { folders, damaged: listing.damaged }
}

export async function createFolder(backend: VaultBackend, vaultId: string, parent: VaultFolder | null, name: string): Promise<string> {
  const vmk = requireKey(vaultId)
  const clean = cleanFolderName(name)
  if (!clean) throw new MediaError(FOLDER_MESSAGES.nameRequired)
  if (parent && parent.depth >= MAX_FOLDER_DEPTH) throw new MediaError(FOLDER_MESSAGES.tooDeep)
  const id = crypto.randomUUID()
  const encryptedMeta = await encryptFolderMeta(vmk, vaultId, id, clean)
  requireKey(vaultId)
  try {
    await backend.insertFolder({ id, vaultId, parentId: parent?.id ?? null, encryptedMeta })
    return id
  } catch (error) {
    throw backendAware(error, FOLDER_MESSAGES.createFailed)
  }
}

export async function renameFolder(backend: VaultBackend, vaultId: string, folder: VaultFolder, name: string): Promise<void> {
  const vmk = requireKey(vaultId)
  const clean = cleanFolderName(name)
  if (!clean) throw new MediaError(FOLDER_MESSAGES.nameRequired)
  const encryptedMeta = await encryptFolderMeta(vmk, vaultId, folder.id, clean)
  requireKey(vaultId)
  try {
    await backend.updateFolderMeta(vaultId, folder.id, encryptedMeta, folder.revision)
  } catch (error) {
    if (error instanceof BackendError && error.kind === 'conflict') throw new MediaError(FOLDER_MESSAGES.renameConflict)
    throw backendAware(error, FOLDER_MESSAGES.renameFailed)
  }
}

/** Deletes an EMPTY folder. The server refuses folders with active items or subfolders. */
export async function deleteFolder(backend: VaultBackend, vaultId: string, folder: VaultFolder): Promise<void> {
  requireKey(vaultId)
  try {
    await backend.deleteFolder(vaultId, folder.id)
  } catch (error) {
    if (error instanceof BackendError && error.kind === 'not-empty') throw new MediaError(FOLDER_MESSAGES.notEmpty)
    throw backendAware(error, FOLDER_MESSAGES.deleteFailed)
  }
}

// ---------------------------------------------------------------------------
// Tree helpers (pure)
// ---------------------------------------------------------------------------

export function folderLabel(folder: VaultFolder | null): string {
  if (!folder) return 'Vault'
  return folder.name ?? 'Unreadable folder'
}

/** Root-to-folder chain. Stops on unknown ids or cycles (the server prevents both). */
export function folderPath(folders: Map<string, VaultFolder>, folderId: string | null): VaultFolder[] {
  const chain: VaultFolder[] = []
  const seen = new Set<string>()
  let current = folderId ? folders.get(folderId) : undefined
  while (current && !seen.has(current.id)) {
    seen.add(current.id)
    chain.unshift(current)
    current = current.parentId ? folders.get(current.parentId) : undefined
  }
  return chain
}

/** The folder and all of its descendants. */
export function descendantIds(folders: VaultFolder[], rootId: string): Set<string> {
  const out = new Set<string>([rootId])
  let grew = true
  while (grew) {
    grew = false
    for (const f of folders) {
      if (f.parentId && out.has(f.parentId) && !out.has(f.id)) {
        out.add(f.id)
        grew = true
      }
    }
  }
  return out
}

export function sortFolders(folders: VaultFolder[]): VaultFolder[] {
  return [...folders].sort((a, b) => {
    if (a.name === null && b.name === null) return a.id.localeCompare(b.id)
    if (a.name === null || b.name === null) return a.name === null ? 1 : -1
    return a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true })
  })
}
