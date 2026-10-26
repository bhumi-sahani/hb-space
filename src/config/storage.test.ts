import { describe, expect, it } from 'vitest'
import { formatBytes } from '../screens/vault/formFields'
import { parseStorageLimitBytes } from './storage'

const GIB = 1024 ** 3

describe('storage limit setting', () => {
  it('defaults to 1 GB (Supabase Free plan)', () => {
    expect(parseStorageLimitBytes({})).toBe(GIB)
    expect(parseStorageLimitBytes({ VITE_STORAGE_LIMIT_GB: '' })).toBe(GIB)
  })

  it('accepts whole and decimal GB values', () => {
    expect(parseStorageLimitBytes({ VITE_STORAGE_LIMIT_GB: '5' })).toBe(5 * GIB)
    expect(parseStorageLimitBytes({ VITE_STORAGE_LIMIT_GB: ' 100 ' })).toBe(100 * GIB)
    expect(parseStorageLimitBytes({ VITE_STORAGE_LIMIT_GB: '0.5' })).toBe(GIB / 2)
  })

  it('falls back to the default for nonsense', () => {
    for (const bad of ['abc', '0', '-3', 'Infinity', '1e9']) expect(parseStorageLimitBytes({ VITE_STORAGE_LIMIT_GB: bad })).toBe(GIB)
  })

  it('formats sizes up to GB', () => {
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MB')
    expect(formatBytes(GIB)).toBe('1 GB')
    expect(formatBytes(5 * GIB)).toBe('5 GB')
    expect(formatBytes(1.25 * GIB)).toBe('1.25 GB')
  })
})
