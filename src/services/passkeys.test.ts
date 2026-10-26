import { describe, expect, it } from 'vitest'
import { normalisePasskeyName, PASSKEY_NAME_MAX } from './passkeys'
import { describeDataError, MEMBERSHIP_MESSAGES } from './vault'

describe('normalisePasskeyName', () => {
  it('trims and collapses whitespace', () => {
    expect(normalisePasskeyName('  My   phone ')).toBe('My phone')
  })

  it('rejects empty and over-long names', () => {
    expect(normalisePasskeyName('   ')).toBeNull()
    expect(normalisePasskeyName('x'.repeat(PASSKEY_NAME_MAX + 1))).toBeNull()
    expect(normalisePasskeyName('x'.repeat(PASSKEY_NAME_MAX))).toHaveLength(PASSKEY_NAME_MAX)
  })
})

describe('describeDataError', () => {
  it('explains missing migrations without leaking details', () => {
    expect(describeDataError({ code: 'PGRST205', message: 'Could not find the table public.vault_members' })).toBe(
      MEMBERSHIP_MESSAGES.notSetUp,
    )
  })

  it('maps network failures', () => {
    expect(describeDataError({ message: 'TypeError: Failed to fetch' })).toBe(MEMBERSHIP_MESSAGES.network)
  })

  it('never surfaces raw database messages', () => {
    expect(describeDataError({ code: '42501', message: 'permission denied for table vault_members' })).toBe(
      MEMBERSHIP_MESSAGES.generic,
    )
  })
})
