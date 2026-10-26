import { describe, expect, it } from 'vitest'
import { formatRelative } from './formFields'

const NOW = Date.UTC(2026, 9, 23, 12, 0, 0)
const ago = (seconds: number) => new Date(NOW - seconds * 1000).toISOString()

describe('formatRelative', () => {
  it('reads naturally', () => {
    expect(formatRelative(ago(10), NOW)).toBe('just now')
    expect(formatRelative(ago(5 * 60), NOW)).toMatch(/5 minutes ago/)
    expect(formatRelative(ago(2 * 86400), NOW)).toMatch(/2 days ago/)
    expect(formatRelative(ago(86400), NOW)).toMatch(/yesterday/)
    expect(formatRelative('not a date', NOW)).toBe('')
  })
})
