import type { FormEvent } from 'react'

/**
 * Secrets are read from uncontrolled inputs at submit time instead of being
 * mirrored into React state on every keystroke, then the form is reset. This
 * keeps fewer copies of the passphrase around (JS still cannot wipe strings).
 */
export function takeSecrets<K extends string>(event: FormEvent<HTMLFormElement>, names: readonly K[]): Record<K, string> {
  event.preventDefault()
  const form = event.currentTarget
  const data = new FormData(form)
  const out = {} as Record<K, string>
  for (const name of names) {
    const value = data.get(name)
    out[name] = typeof value === 'string' ? value : ''
  }
  form.reset()
  return out
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  const gb = bytes / (1024 * 1024 * 1024)
  // Whole numbers without a decimal ("1 GB", "5 GB"), otherwise two decimals ("1.25 GB").
  return `${Number.isInteger(gb) ? gb : gb.toFixed(2)} GB`
}

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

export function formatDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '' : dateFormat.format(date)
}

export function formatDuration(seconds: number): string {
  const total = Math.max(0, Math.round(seconds))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = String(total % 60).padStart(2, '0')
  return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${s}` : `${m}:${s}`
}

export function formatMillis(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return ''
  return formatDate(new Date(ms).toISOString())
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}

const relativeFormat = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
const RELATIVE_STEPS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['second', 60],
  ['minute', 60],
  ['hour', 24],
  ['day', 7],
  ['week', 4.345],
  ['month', 12],
  ['year', Infinity],
]

/** "2 days ago", "yesterday", "just now". Local, no network. */
export function formatRelative(value: string, now: number = Date.now()): string {
  const time = new Date(value).getTime()
  if (Number.isNaN(time)) return ''
  let amount = (time - now) / 1000
  if (Math.abs(amount) < 45) return 'just now'
  for (const [unit, size] of RELATIVE_STEPS) {
    if (Math.abs(amount) < size) return relativeFormat.format(Math.round(amount), unit)
    amount /= size
  }
  return ''
}
