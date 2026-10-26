/**
 * Storage quota shown in the gallery ("12.4 MB of 1 GB").
 *
 * The browser cannot ask Supabase for the project's plan quota (that needs an
 * admin key, which must never be in the app). So the limit is configured:
 * VITE_STORAGE_LIMIT_GB, default 1 GB (the Supabase Free plan's file storage).
 * It is a display value only; it grants and enforces nothing.
 */
export const DEFAULT_STORAGE_LIMIT_GB = 1
const GIB = 1024 * 1024 * 1024

export function parseStorageLimitBytes(raw: Record<string, unknown>): number {
  const value = raw.VITE_STORAGE_LIMIT_GB
  const gb = typeof value === 'string' && value.trim() !== '' ? Number(value.trim()) : DEFAULT_STORAGE_LIMIT_GB
  if (!Number.isFinite(gb) || gb <= 0 || gb > 1_000_000) return DEFAULT_STORAGE_LIMIT_GB * GIB
  return Math.round(gb * GIB)
}

export const storageLimitBytes: number = parseStorageLimitBytes(import.meta.env)
