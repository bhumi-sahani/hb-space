// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { equalBytes, utf8 } from './bytes'
import { generateRawVmk, importVmk } from './envelope'
import { cleanFolderName, decryptFolderMeta, encryptFolderMeta, MAX_FOLDER_NAME_LENGTH } from './folder'
import { decryptItemContent, decryptItemMetadata, decryptItemThumbnail, encryptItem, MAX_THUMBNAIL_BYTES } from './item'
import { FORMAT_MAGIC, OBJECT_KIND } from './mediaFormat'
import { VaultCryptoError } from './primitives'

const VAULT = '5a5a5a5a-1111-4222-8333-444444444444'
const FOLDER = '7d7d7d7d-1111-4222-8333-444444444444'
const OTHER_FOLDER = '8e8e8e8e-1111-4222-8333-444444444444'
const ITEM = '6b6b6b6b-1111-4222-8333-444444444444'

const JPEG = (payload: string) => new Uint8Array([0xff, 0xd8, 0xff, 0xe0, ...utf8(payload)])
const MP4 = (payload: Uint8Array) => new Uint8Array([0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d, ...payload])

async function key() {
  return importVmk(generateRawVmk())
}

function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer
    return true
  }
  return false
}

describe('folder-name encryption', () => {
  it('round-trips a folder name; the ciphertext does not contain it', async () => {
    const vmk = await key()
    const blob = await encryptFolderMeta(vmk, VAULT, FOLDER, 'HB_SPACE_TEST Bali 2026')
    expect(contains(blob, utf8('Bali'))).toBe(false)
    expect(await decryptFolderMeta(vmk, VAULT, FOLDER, blob)).toEqual({ v: 1, name: 'HB_SPACE_TEST Bali 2026' })
  })

  it('pads names so short names have identical ciphertext length', async () => {
    const vmk = await key()
    const a = await encryptFolderMeta(vmk, VAULT, FOLDER, 'A')
    const b = await encryptFolderMeta(vmk, VAULT, FOLDER, 'A much longer folder name, still short')
    expect(a.length).toBe(b.length)
    expect(a.length).toBe(12 + 256 + 16)
  })

  it('uses a fresh IV every time (renaming to the same name gives a different blob)', async () => {
    const vmk = await key()
    const a = await encryptFolderMeta(vmk, VAULT, FOLDER, 'Same')
    const b = await encryptFolderMeta(vmk, VAULT, FOLDER, 'Same')
    expect(equalBytes(a, b)).toBe(false)
  })

  it('fails with the wrong key', async () => {
    const blob = await encryptFolderMeta(await key(), VAULT, FOLDER, 'Private')
    await expect(decryptFolderMeta(await key(), VAULT, FOLDER, blob)).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('fails if the blob is modified', async () => {
    const vmk = await key()
    const blob = await encryptFolderMeta(vmk, VAULT, FOLDER, 'Private')
    for (const index of [0, 20, blob.length - 1]) {
      const tampered = blob.slice()
      tampered[index] ^= 1
      await expect(decryptFolderMeta(vmk, VAULT, FOLDER, tampered)).rejects.toBeInstanceOf(VaultCryptoError)
    }
  })

  it('is bound to its folder id and vault id (a blob copied onto another folder row fails)', async () => {
    const vmk = await key()
    const blob = await encryptFolderMeta(vmk, VAULT, FOLDER, 'Private')
    await expect(decryptFolderMeta(vmk, VAULT, OTHER_FOLDER, blob)).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(decryptFolderMeta(vmk, '9f9f9f9f-1111-4222-8333-444444444444', FOLDER, blob)).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('cleans names: no slashes, control or bidi characters; capped; empty refused', async () => {
    expect(cleanFolderName('  a/b\\c  ')).toBe('abc')
    expect(cleanFolderName('x' + String.fromCharCode(0x202e) + 'gpj.exe')).toBe('xgpj.exe')
    expect(cleanFolderName('y'.repeat(500))).toHaveLength(MAX_FOLDER_NAME_LENGTH)
    await expect(encryptFolderMeta(await key(), VAULT, FOLDER, '   ')).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('rejects malformed lengths before decrypting', async () => {
    await expect(decryptFolderMeta(await key(), VAULT, FOLDER, new Uint8Array(300))).rejects.toBeInstanceOf(VaultCryptoError)
  })
})

describe('thumbnails and media metadata', () => {
  it('encrypts a thumbnail as a separate kind-0x02 object that decrypts to the exact preview', async () => {
    const vmk = await key()
    const thumb = JPEG('HB_SPACE_TEST thumbnail pixels')
    const item = await encryptItem(vmk, ITEM, JPEG('HB_SPACE_TEST original'), { name: 'p.jpg', modified: null }, thumb.slice())
    expect(item.thumbnail).not.toBeNull()
    expect(equalBytes(item.thumbnail!.subarray(0, 4), FORMAT_MAGIC)).toBe(true)
    expect(item.thumbnail![5]).toBe(OBJECT_KIND.thumbnail)
    expect(contains(item.thumbnail!, utf8('thumbnail pixels'))).toBe(false)
    const plain = await decryptItemThumbnail(vmk, ITEM, item.wrappedDek, item.thumbnail!)
    expect(equalBytes(plain, thumb)).toBe(true)
  })

  it('a modified thumbnail fails authentication', async () => {
    const vmk = await key()
    const item = await encryptItem(vmk, ITEM, JPEG('o'), { name: 'p.jpg', modified: null }, JPEG('t'))
    const tampered = item.thumbnail!.slice()
    tampered[tampered.length - 2] ^= 1
    await expect(decryptItemThumbnail(vmk, ITEM, item.wrappedDek, tampered)).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('thumbnail and content use different keys and kinds: they cannot be swapped', async () => {
    const vmk = await key()
    const item = await encryptItem(vmk, ITEM, JPEG('o'), { name: 'p.jpg', modified: null }, JPEG('t'))
    await expect(decryptItemThumbnail(vmk, ITEM, item.wrappedDek, item.content)).rejects.toBeInstanceOf(VaultCryptoError)
    await expect(decryptItemContent(vmk, ITEM, item.wrappedDek, item.thumbnail!)).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('only small raster previews are accepted as thumbnails', async () => {
    const vmk = await key()
    await expect(encryptItem(vmk, ITEM, JPEG('o'), { name: 'p.jpg', modified: null }, utf8('<svg onload=x>'))).rejects.toBeInstanceOf(
      VaultCryptoError,
    )
    const huge = new Uint8Array(MAX_THUMBNAIL_BYTES + 1)
    huge.set([0xff, 0xd8, 0xff])
    await expect(encryptItem(vmk, ITEM, JPEG('o'), { name: 'p.jpg', modified: null }, huge)).rejects.toBeInstanceOf(VaultCryptoError)
  })

  it('video: a synthetic MP4 round-trips and records its measured facts inside encrypted metadata', async () => {
    const vmk = await key()
    const payload = new Uint8Array(2 * 1024 * 1024 + 5)
    for (let i = 0; i < payload.length; i += 65536) crypto.getRandomValues(payload.subarray(i, i + 65536))
    const video = MP4(payload)
    const item = await encryptItem(vmk, ITEM, video, { name: 'HB_SPACE_TEST clip.mp4', modified: 1767225600000, facts: { width: 1920, height: 1080, duration: 12.3456 } })
    const meta = await decryptItemMetadata(vmk, ITEM, item.wrappedDek, item.encryptedMeta)
    expect(meta).toMatchObject({ name: 'HB_SPACE_TEST clip.mp4', mime: 'video/mp4', size: video.length, width: 1920, height: 1080, duration: 12.346 })
    expect(contains(item.encryptedMeta, utf8('clip.mp4'))).toBe(false)
    expect(equalBytes(await decryptItemContent(vmk, ITEM, item.wrappedDek, item.content), video)).toBe(true)
  })

  it('malformed facts are dropped, never trusted', async () => {
    const vmk = await key()
    const item = await encryptItem(vmk, ITEM, JPEG('o'), {
      name: 'p.jpg',
      modified: null,
      facts: { width: -5, height: 10, duration: Number.POSITIVE_INFINITY } as never,
    })
    const meta = await decryptItemMetadata(vmk, ITEM, item.wrappedDek, item.encryptedMeta)
    expect(meta.width).toBeUndefined()
    expect(meta.height).toBeUndefined()
    expect(meta.duration).toBeUndefined()
  })

  it('Phase 3 items (no thumbnail, no facts) still decrypt unchanged', async () => {
    const vmk = await key()
    const item = await encryptItem(vmk, ITEM, JPEG('phase 3'), { name: 'old.jpg', modified: null })
    expect(item.thumbnail).toBeNull()
    const meta = await decryptItemMetadata(vmk, ITEM, item.wrappedDek, item.encryptedMeta)
    expect(meta).toEqual({ v: 1, name: 'old.jpg', mime: 'image/jpeg', size: 4 + 7, modified: null })
  })

  it('a modified filename (metadata) fails authentication', async () => {
    const vmk = await key()
    const item = await encryptItem(vmk, ITEM, JPEG('o'), { name: 'secret-name.jpg', modified: null })
    const tampered = item.encryptedMeta.slice()
    tampered[30] ^= 1
    await expect(decryptItemMetadata(vmk, ITEM, item.wrappedDek, tampered)).rejects.toBeInstanceOf(VaultCryptoError)
  })
})
