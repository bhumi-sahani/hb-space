// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { equalBytes, readBlob, utf8 } from '../lib/crypto/bytes'
import { FORMAT_MAGIC } from '../lib/crypto/mediaFormat'
import { MemoryBackend } from './testing/memoryBackend'
import { BackendError } from './vaultBackend'
import { deleteVaultItem, listVaultItems, MAX_UPLOAD_BYTES, MEDIA_MESSAGES, openVaultItem, uploadFile } from './media'
import {
  changePassphrase,
  KEY_MESSAGES,
  loadKeyState,
  prepareNewRecoveryCode,
  prepareNewVault,
  resetPassphraseWithRecoveryCode,
  unlockWithPassphrase,
} from './vaultKeys'
import { activeObjectUrlCount, getUnlockedKey, getVaultStatus, lockVault } from './vaultSession'

const VAULT = '5a5a5a5a-1111-4222-8333-444444444444'
const PASSPHRASE = 'HB_SPACE_TEST_PASSPHRASE river otter lantern'
const NEW_PASSPHRASE = 'HB_SPACE_TEST_NEW_PASSPHRASE quiet maple'
const FAST = { m: 16384, t: 1, p: 1 }

class MemoryStorage {
  private data = new Map<string, string>()
  getItem(k: string) {
    return this.data.get(k) ?? null
  }
  setItem(k: string, v: string) {
    this.data.set(k, String(v))
  }
  removeItem(k: string) {
    this.data.delete(k)
  }
  clear() {
    this.data.clear()
  }
  dump() {
    return JSON.stringify([...this.data.entries()])
  }
}

function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer
    return true
  }
  return false
}

/** Synthetic media: a JPEG start-of-image marker in front of the test payload (Phase 4 accepts photos/videos only). */
const JPEG_MAGIC = Uint8Array.of(0xff, 0xd8, 0xff, 0xe0)
/** Synthetic MP4: an ftyp box header in front of the payload. */
const MP4_MAGIC = Uint8Array.of(0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d)

function withMagic(magic: Uint8Array, payload: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(magic.length + payload.length)
  out.set(magic, 0)
  out.set(payload, magic.length)
  return out
}

/** Exactly these bytes. */
function rawFile(name: string, bytes: Uint8Array<ArrayBuffer>) {
  return Object.assign(new Blob([bytes]), { name, lastModified: 1767225600000 })
}

/** The payload as a synthetic JPEG (never a real photo). */
function fixtureFile(name: string, payload: Uint8Array<ArrayBuffer>) {
  return rawFile(name, withMagic(JPEG_MAGIC, payload))
}

let backend: MemoryBackend
let local: MemoryStorage
let session: MemoryStorage
let createdUrls: string[]
let revokedUrls: string[]

beforeEach(() => {
  lockVault()
  backend = new MemoryBackend(VAULT)
  local = new MemoryStorage()
  session = new MemoryStorage()
  vi.stubGlobal('localStorage', local)
  vi.stubGlobal('sessionStorage', session)
  createdUrls = []
  revokedUrls = []
  let n = 0
  vi.spyOn(URL, 'createObjectURL').mockImplementation(() => {
    const url = `blob:test/${n++}`
    createdUrls.push(url)
    return url
  })
  vi.spyOn(URL, 'revokeObjectURL').mockImplementation((url: string) => {
    revokedUrls.push(url)
  })
})

afterEach(() => {
  lockVault()
  vi.unstubAllGlobals()
})

async function setUpVault(): Promise<string> {
  const prepared = await prepareNewVault(backend, VAULT, PASSPHRASE, FAST)
  await prepared.commit()
  return prepared.recoveryCode
}

describe('vault setup and unlock', () => {
  it('nothing is sent until the user confirms the recovery code; then the vault is unlocked', async () => {
    const prepared = await prepareNewVault(backend, VAULT, PASSPHRASE, FAST)
    expect(backend.log.filter((r) => r.op !== 'listEnvelopes')).toHaveLength(0)
    expect(getVaultStatus()).toBe('locked')
    await prepared.commit()
    expect(getVaultStatus()).toBe('unlocked')
    expect([...backend.envelopes.keys()].sort()).toEqual(['passphrase', 'recovery'])
    expect((await loadKeyState(backend, VAULT)).status).toBe('ready')
  })

  it('a discarded setup stores nothing', async () => {
    const prepared = await prepareNewVault(backend, VAULT, PASSPHRASE, FAST)
    prepared.discard()
    await expect(prepared.commit()).rejects.toThrow()
    expect(backend.envelopes.size).toBe(0)
  })

  it('setup refuses to overwrite an existing vault key', async () => {
    await setUpVault()
    await expect(prepareNewVault(backend, VAULT, PASSPHRASE, FAST)).rejects.toMatchObject({ userMessage: KEY_MESSAGES.conflict })
  })

  it('the correct passphrase unlocks; a wrong one fails with a generic message and stays locked', async () => {
    await setUpVault()
    lockVault()
    await expect(unlockWithPassphrase(backend, VAULT, 'wrong passphrase entirely')).rejects.toMatchObject({
      userMessage: KEY_MESSAGES.unlockFailed,
    })
    expect(getVaultStatus()).toBe('locked')
    await unlockWithPassphrase(backend, VAULT, PASSPHRASE)
    expect(getVaultStatus()).toBe('unlocked')
  })

  it('a tampered envelope fails with the same generic message', async () => {
    await setUpVault()
    lockVault()
    const row = backend.envelopes.get('passphrase')!
    const hex = row.wrapped_key as string
    row.wrapped_key = hex.slice(0, -1) + (hex.endsWith('0') ? '1' : '0') // flip one bit of the GCM tag
    await expect(unlockWithPassphrase(backend, VAULT, PASSPHRASE)).rejects.toMatchObject({ userMessage: KEY_MESSAGES.unlockFailed })
    expect(getVaultStatus()).toBe('locked')
  })

  it('a malformed key row fails closed', async () => {
    await setUpVault()
    lockVault()
    backend.envelopes.get('passphrase')!.wrapped_key = '\\x00'
    await expect(unlockWithPassphrase(backend, VAULT, PASSPHRASE)).rejects.toMatchObject({ userMessage: KEY_MESSAGES.generic })
    expect(getVaultStatus()).toBe('locked')
  })

  it('weakened KDF parameters on the server are refused, not used', async () => {
    await setUpVault()
    lockVault()
    backend.envelopes.get('passphrase')!.kdf_params = { m: 1024, t: 1, p: 1 }
    await expect(unlockWithPassphrase(backend, VAULT, PASSPHRASE)).rejects.toBeTruthy()
    expect(getVaultStatus()).toBe('locked')
  })
})

describe('key persistence (tests 10-12)', () => {
  it('passphrase, master key, KEKs and DEKs never reach browser storage or the server', async () => {
    const rawKeys: Uint8Array[] = []
    const realImport = crypto.subtle.importKey.bind(crypto.subtle)
    vi.spyOn(crypto.subtle, 'importKey').mockImplementation(((format: KeyFormat, data: BufferSource, ...rest: unknown[]) => {
      if (format === 'raw') rawKeys.push(new Uint8Array(data as Uint8Array).slice()) // copy before the code wipes it
      return (realImport as (...a: unknown[]) => Promise<CryptoKey>)(format, data, ...rest)
    }) as typeof crypto.subtle.importKey)

    const recoveryCode = await setUpVault()
    await uploadFile(backend, VAULT, fixtureFile('synthetic.bin', utf8('HB_SPACE_PHASE3_TEST_FILE payload')))
    lockVault()
    await unlockWithPassphrase(backend, VAULT, PASSPHRASE)
    await changePassphrase(backend, VAULT, PASSPHRASE, NEW_PASSPHRASE, FAST)
    const { items } = await listVaultItems(backend, VAULT)
    await openVaultItem(backend, VAULT, items[0].record)

    // VMK + passphrase KEKs + recovery KEK base + DEKs (HKDF bases) were all captured.
    expect(rawKeys.length).toBeGreaterThan(6)
    const secrets: [string, Uint8Array][] = [
      ['passphrase', utf8(PASSPHRASE)],
      ['new passphrase', utf8(NEW_PASSPHRASE)],
      ['recovery code', utf8(recoveryCode)],
      ...rawKeys.map((k, i) => [`raw key #${i}`, k] as [string, Uint8Array]),
    ]
    const browserStorage = utf8(local.dump() + session.dump())
    for (const [label, secret] of secrets) {
      expect(contains(browserStorage, secret), `${label} in web storage`).toBe(false)
      for (const blob of backend.persistedBytes()) expect(contains(blob, secret), `${label} persisted on server`).toBe(false)
      for (const blob of backend.sentBytes()) expect(contains(blob, secret), `${label} sent to server`).toBe(false)
    }
    // And no key proof is persisted (it is sent, checked, and dropped).
    for (const row of backend.envelopes.values()) expect(row.key_proof).toBeNull()
  })

  it('the unlocked key held in memory is non-extractable', async () => {
    await setUpVault()
    const key = getUnlockedKey(VAULT)!
    expect(key.extractable).toBe(false)
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow()
  })
})

describe('re-wrapping and recovery', () => {
  it('changing the passphrase re-wraps the same key: existing media still opens, the old passphrase stops working', async () => {
    await setUpVault()
    const original = utf8('HB_SPACE_PHASE3_TEST_FILE before rewrap')
    await uploadFile(backend, VAULT, fixtureFile('a.bin', original))
    const objectBefore = [...backend.objects.values()][0].slice()

    await changePassphrase(backend, VAULT, PASSPHRASE, NEW_PASSPHRASE, FAST)
    expect(equalBytes([...backend.objects.values()][0], objectBefore)).toBe(true) // media untouched
    lockVault()
    await expect(unlockWithPassphrase(backend, VAULT, PASSPHRASE)).rejects.toBeTruthy()
    await unlockWithPassphrase(backend, VAULT, NEW_PASSPHRASE)
    const { items } = await listVaultItems(backend, VAULT)
    const opened = await openVaultItem(backend, VAULT, items[0].record)
    expect(opened).toMatchObject({ inline: true, type: 'image/jpeg' })
  })

  it('changing the passphrase requires the current passphrase', async () => {
    await setUpVault()
    await expect(changePassphrase(backend, VAULT, 'not the passphrase', NEW_PASSPHRASE, FAST)).rejects.toMatchObject({
      userMessage: KEY_MESSAGES.wrongCurrent,
    })
    expect(backend.log.some((r) => r.op === 'updateEnvelope')).toBe(false)
  })

  it('the recovery code resets the passphrase and unlocks', async () => {
    const code = await setUpVault()
    lockVault()
    await expect(resetPassphraseWithRecoveryCode(backend, VAULT, 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA', NEW_PASSPHRASE, FAST)).rejects.toMatchObject({
      userMessage: KEY_MESSAGES.recoveryFailed,
    })
    await resetPassphraseWithRecoveryCode(backend, VAULT, code, NEW_PASSPHRASE, FAST)
    expect(getVaultStatus()).toBe('unlocked')
    lockVault()
    await unlockWithPassphrase(backend, VAULT, NEW_PASSPHRASE)
  })

  it('a new recovery code replaces the old one only after confirmation', async () => {
    const oldCode = await setUpVault()
    const next = await prepareNewRecoveryCode(backend, VAULT, PASSPHRASE)
    expect(next.recoveryCode).not.toBe(oldCode)
    await next.commit()
    lockVault()
    await expect(resetPassphraseWithRecoveryCode(backend, VAULT, oldCode, NEW_PASSPHRASE, FAST)).rejects.toBeTruthy()
    await resetPassphraseWithRecoveryCode(backend, VAULT, next.recoveryCode, NEW_PASSPHRASE, FAST)
  })

  it('a server that rejects the proof (e.g. stale data) changes nothing and reports a generic error', async () => {
    await setUpVault()
    backend.failNext.updateEnvelope = new BackendError('denied')
    await expect(changePassphrase(backend, VAULT, PASSPHRASE, NEW_PASSPHRASE, FAST)).rejects.toMatchObject({
      userMessage: KEY_MESSAGES.generic,
    })
    lockVault()
    await unlockWithPassphrase(backend, VAULT, PASSPHRASE)
  })
})

describe('upload (tests 15, 18-20)', () => {
  it('uploads ciphertext only, in the order pending -> upload -> ready, under a random filename-free path', async () => {
    await setUpVault()
    const original = withMagic(JPEG_MAGIC, utf8('HB_SPACE_PHASE3_TEST_FILE ' + 'x'.repeat(2000)))
    const id = await uploadFile(backend, VAULT, rawFile('HB_SPACE_PHASE3_TEST_FILE-private-name.jpg', original))

    const ops = backend.log.map((r) => r.op).filter((op) => !op.includes('Envelope'))
    expect(ops).toEqual(['insertPendingMedia', 'uploadObject', 'markReady'])

    const upload = backend.log.find((r) => r.op === 'uploadObject')!.body as { path: string; bytes: Uint8Array }
    expect(upload.path).toBe(`${VAULT}/${id}`)
    expect(upload.path).not.toMatch(/private-name|\.jpg|HB_SPACE/)
    expect(equalBytes(upload.bytes, original)).toBe(false)
    expect(equalBytes(upload.bytes.subarray(0, 4), FORMAT_MAGIC)).toBe(true)
    for (const sent of backend.sentBytes()) {
      expect(contains(sent, utf8('HB_SPACE_PHASE3_TEST_FILE'))).toBe(false)
      expect(contains(sent, utf8('private-name'))).toBe(false)
      expect(contains(sent, original.subarray(0, 64))).toBe(false)
    }
    expect(backend.media.get(id)!.status).toBe('ready')
  })

  it('round trip: downloaded ciphertext decrypts to the exact original bytes', async () => {
    await setUpVault()
    const random = new Uint8Array(3 * 1024 * 1024 + 17)
    for (let i = 0; i < random.length; i += 65536) crypto.getRandomValues(random.subarray(i, i + 65536))
    const original = withMagic(MP4_MAGIC, random)
    await uploadFile(backend, VAULT, rawFile('test-video.mp4', original))
    const { items } = await listVaultItems(backend, VAULT)
    expect(items[0]).toMatchObject({ state: 'ready', meta: { name: 'test-video.mp4', size: original.length, mime: 'video/mp4' } })

    let captured: Blob | null = null
    vi.mocked(URL.createObjectURL).mockImplementation((blob) => {
      captured = blob as Blob
      return 'blob:test/captured'
    })
    await openVaultItem(backend, VAULT, items[0].record)
    expect(equalBytes(await readBlob(captured!), original)).toBe(true)
    expect(captured!.type).toBe('video/mp4') // typed from the decrypted bytes, not the name
  })

  it('a failed storage upload leaves no record behind and never marks ready', async () => {
    await setUpVault()
    backend.failNext.uploadObject = new BackendError('network')
    await expect(uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('data')))).rejects.toMatchObject({ userMessage: MEDIA_MESSAGES.network })
    expect(backend.media.size).toBe(0)
    expect(backend.log.some((r) => r.op === 'markReady')).toBe(false)
  })

  it('if finalising fails, both the object and the record are removed', async () => {
    await setUpVault()
    backend.failNext.markReady = new BackendError('generic')
    await expect(uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('data')))).rejects.toMatchObject({
      userMessage: MEDIA_MESSAGES.uploadFailed,
    })
    expect(backend.media.size).toBe(0)
    expect(backend.objects.size).toBe(0)
  })

  it('the server refuses to mark ready if the stored object size differs', async () => {
    await setUpVault()
    const original = backend.uploadObject.bind(backend)
    backend.uploadObject = (path, bytes) => original(path, bytes.slice(0, bytes.length - 1))
    await expect(uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('data')))).rejects.toBeTruthy()
    expect(backend.media.size).toBe(0)
  })

  it('refuses files over the limit and refuses while locked, before anything is sent', async () => {
    await setUpVault()
    const huge = { name: 'big.bin', size: MAX_UPLOAD_BYTES + 1 } as unknown as Blob & { name: string }
    await expect(uploadFile(backend, VAULT, huge)).rejects.toMatchObject({ userMessage: MEDIA_MESSAGES.tooLarge })
    lockVault()
    await expect(uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('data')))).rejects.toMatchObject({ userMessage: MEDIA_MESSAGES.locked })
    expect(backend.log.some((r) => r.op === 'insertPendingMedia')).toBe(false)
  })

  it('an empty file is refused (not a photo or video) before anything is sent', async () => {
    await setUpVault()
    await expect(uploadFile(backend, VAULT, rawFile('empty.jpg', new Uint8Array(0)))).rejects.toMatchObject({
      userMessage: MEDIA_MESSAGES.unsupported,
    })
    expect(backend.log.some((r) => r.op === 'insertPendingMedia')).toBe(false)
  })

  it('images are rendered inline only when the decrypted bytes are a known image type', async () => {
    await setUpVault()
    await uploadFile(backend, VAULT, rawFile('looks-like.gif', new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3])))
    const { items } = await listVaultItems(backend, VAULT)
    expect((await openVaultItem(backend, VAULT, items[0].record)).type).toBe('image/png') // bytes win over the name
    // Script-capable content is refused before encryption, whatever its name says.
    await expect(
      uploadFile(backend, VAULT, rawFile('evil.png', utf8('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'))),
    ).rejects.toMatchObject({ userMessage: MEDIA_MESSAGES.unsupported })
    await expect(uploadFile(backend, VAULT, rawFile('page.jpg', utf8('<html><script>alert(1)</script></html>')))).rejects.toMatchObject({
      userMessage: MEDIA_MESSAGES.unsupported,
    })
    expect(backend.media.size).toBe(1)
  })
})

describe('download integrity', () => {
  it('a tampered stored object is refused with one generic error and no URL is created', async () => {
    await setUpVault()
    await uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('HB_SPACE_PHASE3_TEST_FILE')))
    const [path, bytes] = [...backend.objects.entries()][0]
    bytes[bytes.length - 3] ^= 1
    backend.objects.set(path, bytes)
    const { items } = await listVaultItems(backend, VAULT)
    const before = createdUrls.length
    await expect(openVaultItem(backend, VAULT, items[0].record)).rejects.toMatchObject({ userMessage: MEDIA_MESSAGES.openFailed })
    expect(createdUrls.length).toBe(before)
  })

  it('an object swapped from another item is refused', async () => {
    await setUpVault()
    await uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('first')))
    await uploadFile(backend, VAULT, fixtureFile('b.bin', utf8('other')))
    const [[pathA, a], [pathB, b]] = [...backend.objects.entries()]
    backend.objects.set(pathA, b)
    backend.objects.set(pathB, a)
    const { items } = await listVaultItems(backend, VAULT)
    for (const item of items) await expect(openVaultItem(backend, VAULT, item.record)).rejects.toBeTruthy()
  })

  it('tampered metadata marks the item unreadable instead of showing anything', async () => {
    await setUpVault()
    await uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('x')))
    const row = [...backend.media.values()][0]
    const hex = row.encrypted_meta as string
    row.encrypted_meta = hex.slice(0, 40) + (hex[40] === '0' ? '1' : '0') + hex.slice(41)
    const { items } = await listVaultItems(backend, VAULT)
    expect(items[0].state).toBe('unreadable')
  })

  it('malformed server rows are counted as damaged, not trusted', async () => {
    await setUpVault()
    await uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('x')))
    const row = [...backend.media.values()][0]
    row.object_path = `${VAULT}/../../somewhere-else`
    const { items, damaged } = await listVaultItems(backend, VAULT)
    expect(items).toHaveLength(0)
    expect(damaged).toBe(1)
  })
})

describe('locking (tests 21-23)', () => {
  it('a locked vault cannot list or decrypt media, and lock drops the key', async () => {
    await setUpVault()
    await uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('x')))
    const { items } = await listVaultItems(backend, VAULT)
    lockVault()
    expect(getVaultStatus()).toBe('locked')
    expect(getUnlockedKey(VAULT)).toBeNull()
    await expect(openVaultItem(backend, VAULT, items[0].record)).rejects.toMatchObject({ userMessage: MEDIA_MESSAGES.locked })
    await expect(listVaultItems(backend, VAULT)).rejects.toMatchObject({ userMessage: MEDIA_MESSAGES.locked })
  })

  it('the key is bound to its vault id', async () => {
    await setUpVault()
    expect(getUnlockedKey('5a5a5a5a-1111-4222-8333-000000000000')).toBeNull()
  })

  it('locking revokes every object URL created for decrypted media', async () => {
    await setUpVault()
    await uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('x')))
    await uploadFile(backend, VAULT, fixtureFile('b.bin', utf8('y')))
    const { items } = await listVaultItems(backend, VAULT)
    const urls = [(await openVaultItem(backend, VAULT, items[0].record)).url, (await openVaultItem(backend, VAULT, items[1].record)).url]
    expect(activeObjectUrlCount()).toBe(2)
    lockVault()
    expect(revokedUrls).toEqual(expect.arrayContaining(urls))
    expect(activeObjectUrlCount()).toBe(0)
  })

  it('locking during a download prevents the decrypted item from being shown', async () => {
    await setUpVault()
    await uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('x')))
    const { items } = await listVaultItems(backend, VAULT)
    const realDownload = backend.downloadObject.bind(backend)
    backend.downloadObject = async (path) => {
      const bytes = await realDownload(path)
      lockVault()
      return bytes
    }
    const before = createdUrls.length
    await expect(openVaultItem(backend, VAULT, items[0].record)).rejects.toBeTruthy()
    expect(createdUrls.length).toBe(before)
  })
})

describe('delete', () => {
  it('permanently removes the object, then the record (there is no trash step)', async () => {
    await setUpVault()
    await uploadFile(backend, VAULT, fixtureFile('a.bin', utf8('x')))
    const { items } = await listVaultItems(backend, VAULT)
    expect(backend.objects.size).toBe(1)
    await deleteVaultItem(backend, VAULT, items[0].record)
    expect(backend.objects.size).toBe(0)
    expect(backend.media.size).toBe(0)
    const ops = backend.log.map((r) => r.op)
    expect(ops.indexOf('deleteObjects')).toBeLessThan(ops.indexOf('deleteMedia'))
  })
})
