import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { PasskeyManager, type PasskeyService } from './PasskeyManager'

afterEach(cleanup)

const user = { id: 'user-1', email: 'me@example.com' }

function makeService(overrides: Partial<PasskeyService> = {}): PasskeyService {
  return {
    list: vi.fn().mockResolvedValue({
      ok: true,
      passkeys: [{ id: 'pk1', name: 'iPhone', createdAt: '2026-10-01T10:00:00Z', lastUsedAt: null }],
    }),
    add: vi.fn().mockResolvedValue({ ok: true }),
    rename: vi.fn().mockResolvedValue({ ok: true }),
    remove: vi.fn().mockResolvedValue({ ok: true }),
    ...overrides,
  }
}

describe('PasskeyManager', () => {
  it('explains when passkeys are unavailable and calls nothing', () => {
    const service = makeService()
    render(<PasskeyManager user={user} supported={false} service={service} />)
    expect(screen.getByText(/not available here/i)).toBeTruthy()
    expect(service.list).not.toHaveBeenCalled()
  })

  it('lists passkeys', async () => {
    render(<PasskeyManager user={user} supported service={makeService()} />)
    const list = await screen.findByRole('list', { name: 'Your passkeys' })
    expect(within(list).getByText('iPhone')).toBeTruthy()
  })

  it('requires the account password before registering a passkey', async () => {
    const u = userEvent.setup()
    const service = makeService()
    render(<PasskeyManager user={user} supported service={service} />)
    await u.click(await screen.findByRole('button', { name: /add a passkey/i }))
    await u.click(screen.getByRole('button', { name: /create passkey/i }))
    expect(service.add).not.toHaveBeenCalled()
    expect(screen.getByRole('alert').textContent).toMatch(/password/i)

    await u.type(screen.getByLabelText('Account password'), 'hunter2-long')
    await u.click(screen.getByRole('button', { name: /create passkey/i }))
    expect(service.add).toHaveBeenCalledWith(user, 'hunter2-long', expect.any(AbortSignal))
    expect(await screen.findByText(/passkey added/i)).toBeTruthy()
  })

  it('shows a wrong-password error and clears the password field', async () => {
    const u = userEvent.setup()
    const service = makeService({ add: vi.fn().mockResolvedValue({ ok: false, message: 'That password is not correct.' }) })
    render(<PasskeyManager user={user} supported service={service} />)
    await u.click(await screen.findByRole('button', { name: /add a passkey/i }))
    await u.type(screen.getByLabelText('Account password'), 'wrong')
    await u.click(screen.getByRole('button', { name: /create passkey/i }))
    expect((await screen.findByRole('alert')).textContent).toBe('That password is not correct.')
    expect((screen.getByLabelText('Account password') as HTMLInputElement).value).toBe('')
  })

  it('asks for confirmation before removing, and can cancel', async () => {
    const u = userEvent.setup()
    const service = makeService()
    render(<PasskeyManager user={user} supported service={service} />)
    await u.click(await screen.findByRole('button', { name: 'Remove iPhone' }))
    expect(service.remove).not.toHaveBeenCalled()
    await u.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(service.remove).not.toHaveBeenCalled()

    await u.click(screen.getByRole('button', { name: 'Remove iPhone' }))
    await u.click(screen.getByRole('button', { name: 'Remove' }))
    expect(service.remove).toHaveBeenCalledWith('pk1')
  })

  it('renames a passkey', async () => {
    const u = userEvent.setup()
    const service = makeService()
    render(<PasskeyManager user={user} supported service={service} />)
    await u.click(await screen.findByRole('button', { name: 'Rename iPhone' }))
    const input = screen.getByLabelText('Passkey name')
    await u.clear(input)
    await u.type(input, 'My phone')
    await u.click(screen.getByRole('button', { name: 'Save' }))
    expect(service.rename).toHaveBeenCalledWith('pk1', 'My phone')
  })
})
