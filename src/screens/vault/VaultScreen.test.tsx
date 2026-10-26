import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { MemoryBackend } from '../../services/testing/memoryBackend'
import { prepareNewVault } from '../../services/vaultKeys'
import { getVaultStatus, lockVault } from '../../services/vaultSession'
import { VaultScreen } from './VaultScreen'

const VAULT = '5a5a5a5a-1111-4222-8333-444444444444'
const PASSPHRASE = 'HB_SPACE_TEST_PASSPHRASE river otter lantern'

async function provisionedBackend() {
  const backend = new MemoryBackend(VAULT)
  const prepared = await prepareNewVault(backend, VAULT, PASSPHRASE, { m: 16384, t: 1, p: 1 })
  await prepared.commit()
  lockVault()
  return backend
}

afterEach(() => {
  cleanup()
  lockVault()
})

describe('VaultScreen', () => {
  it('a signed-in member sees the locked screen; a wrong passphrase shows only a generic error', async () => {
    const backend = await provisionedBackend()
    const user = userEvent.setup()
    render(<VaultScreen vaultId={VAULT} backend={backend} />)

    expect(await screen.findByRole('heading', { name: 'Vault locked' })).toBeTruthy()
    await user.type(screen.getByLabelText('Vault passphrase'), 'definitely the wrong one')
    await user.click(screen.getByRole('button', { name: 'Unlock Vault' }))
    expect(await screen.findByText('Unable to unlock the vault.', {}, { timeout: 10_000 })).toBeTruthy()
    expect(getVaultStatus()).toBe('locked')
    // The field is cleared after submit; the passphrase is not kept in the form.
    expect((screen.getByLabelText('Vault passphrase') as HTMLInputElement).value).toBe('')
  }, 20_000)

  it('the right passphrase unlocks; locking returns to the locked screen without signing out', async () => {
    const backend = await provisionedBackend()
    const user = userEvent.setup()
    render(<VaultScreen vaultId={VAULT} backend={backend} />)

    await user.type(await screen.findByLabelText('Vault passphrase'), PASSPHRASE)
    await user.click(screen.getByRole('button', { name: 'Unlock Vault' }))
    expect(await screen.findByRole('button', { name: 'Upload' }, { timeout: 10_000 })).toBeTruthy()

    act(() => lockVault()) // the Lock Vault button lives in the app's top bar (see App.routing.test)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Vault locked' })).toBeTruthy())
    expect(getVaultStatus()).toBe('locked')
    expect(screen.queryByRole('button', { name: 'Upload' })).toBeNull()
    expect(screen.queryByRole('button', { name: /sign out/i })).toBeNull() // locking never signs out; no sign-out here
  }, 20_000)

  it('an empty vault offers setup, and nothing is stored before the recovery code is confirmed', async () => {
    const backend = new MemoryBackend(VAULT)
    render(<VaultScreen vaultId={VAULT} backend={backend} />)
    expect(await screen.findByRole('heading', { name: 'Set up vault encryption' })).toBeTruthy()
    expect(backend.envelopes.size).toBe(0)
  })
})
