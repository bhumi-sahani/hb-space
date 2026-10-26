import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { LoginScreen } from './LoginScreen'

afterEach(cleanup)

function setup(overrides: Partial<Parameters<typeof LoginScreen>[0]> = {}) {
  const props = {
    passkeyAvailable: true,
    onPasswordSignIn: vi.fn().mockResolvedValue({ ok: true }),
    onPasskeySignIn: vi.fn().mockResolvedValue({ ok: true }),
    ...overrides,
  }
  render(<LoginScreen {...props} />)
  return props
}

async function openRecovery(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: /account recovery/i }))
}

describe('Sign-in needed (no valid session on this device)', () => {
  it('is a minimal screen: no email/password login form by default, and no vault passphrase field', () => {
    setup()
    expect(screen.getByRole('heading', { level: 1 }).textContent).toContain('HB Space')
    expect(screen.getByText(/Sign-in needed on this device/)).toBeTruthy()
    expect(screen.queryByLabelText(/email/i)).toBeNull()
    expect(screen.queryByLabelText(/password/i)).toBeNull()
    // Never a passphrase-only path to the vault.
    expect(screen.queryByLabelText(/passphrase/i)).toBeNull()
    expect(screen.queryByRole('button', { name: /unlock/i })).toBeNull()
  })

  it('offers no account creation', () => {
    setup()
    expect(screen.queryByRole('button', { name: /sign up|create account|register/i })).toBeNull()
    expect(screen.queryByRole('link', { name: /sign up|create account|register/i })).toBeNull()
  })

  it('passkey is the primary way back in', async () => {
    const user = userEvent.setup()
    const props = setup()
    await user.click(screen.getByRole('button', { name: /sign in with passkey/i }))
    expect(props.onPasskeySignIn).toHaveBeenCalledOnce()
  })

  it('reports passkey cancellation', async () => {
    const user = userEvent.setup()
    setup({ onPasskeySignIn: vi.fn().mockResolvedValue({ ok: false, message: 'Passkey sign-in was cancelled or timed out.' }) })
    await user.click(screen.getByRole('button', { name: /sign in with passkey/i }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/cancelled/)
  })

  it('without passkey support, only the account recovery option is offered', () => {
    setup({ passkeyAvailable: false })
    expect(screen.queryByRole('button', { name: /passkey/i })).toBeNull()
    expect(screen.getByRole('button', { name: 'Account recovery' }).getAttribute('aria-expanded')).toBe('false')
  })

  it('account recovery reveals the password form and signs in with it', async () => {
    const user = userEvent.setup()
    const props = setup()
    await openRecovery(user)
    expect(screen.getByRole('button', { name: /hide account recovery/i }).getAttribute('aria-expanded')).toBe('true')
    await user.type(screen.getByLabelText('Account email'), 'me@example.com')
    await user.type(screen.getByLabelText('Account password'), 'correct horse')
    await user.click(screen.getByRole('button', { name: 'Sign in to this device' }))
    expect(props.onPasswordSignIn).toHaveBeenCalledWith('me@example.com', 'correct horse')
  }, 20_000)

  it('validates empty recovery fields without calling the server', async () => {
    const user = userEvent.setup()
    const props = setup()
    await openRecovery(user)
    await user.click(screen.getByRole('button', { name: 'Sign in to this device' }))
    expect(props.onPasswordSignIn).not.toHaveBeenCalled()
    expect(screen.getByRole('alert').textContent).toMatch(/enter your account email/i)
  })

  it('shows the server error and re-enables the form on failure', async () => {
    const user = userEvent.setup()
    setup({ onPasswordSignIn: vi.fn().mockResolvedValue({ ok: false, message: 'Email or password is incorrect.' }) })
    await openRecovery(user)
    await user.type(screen.getByLabelText('Account email'), 'me@example.com')
    await user.type(screen.getByLabelText('Account password'), 'wrong')
    await user.click(screen.getByRole('button', { name: 'Sign in to this device' }))
    expect((await screen.findByRole('alert')).textContent).toBe('Email or password is incorrect.')
    expect((screen.getByLabelText('Account email') as HTMLInputElement).disabled).toBe(false)
  }, 20_000)

  it('accepts any account the server accepts: there is no email allowlist in the page', async () => {
    const user = userEvent.setup()
    const props = setup()
    await openRecovery(user)
    await user.type(screen.getByLabelText('Account email'), 'someone-else@example.org')
    await user.type(screen.getByLabelText('Account password'), 'pw')
    await user.click(screen.getByRole('button', { name: 'Sign in to this device' }))
    // The page decides nothing: Supabase Auth checks the credentials, and RLS membership decides vault access.
    expect(props.onPasswordSignIn).toHaveBeenCalledWith('someone-else@example.org', 'pw')
  }, 20_000)

  it('toggles password visibility', async () => {
    const user = userEvent.setup()
    setup()
    await openRecovery(user)
    const input = screen.getByLabelText('Account password') as HTMLInputElement
    expect(input.type).toBe('password')
    await user.click(screen.getByRole('button', { name: /show account password/i }))
    expect(input.type).toBe('text')
  })
})
