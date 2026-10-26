import { formatBytes } from './formFields'

/**
 * "12.4 MB of 1 GB" with a thin bar. `used` is the size of the vault's
 * encrypted files (what is actually stored; slightly larger than the
 * originals). The limit is the configured plan quota (display only).
 */
export function StorageMeter({ used, limit }: { used: number; limit: number }) {
  const ratio = limit > 0 ? Math.min(1, used / limit) : 0
  const percent = Math.round(ratio * 100)
  const tone = ratio >= 0.95 ? ' storage--full' : ratio >= 0.8 ? ' storage--high' : ''
  const text = `${formatBytes(used)} / ${formatBytes(limit)}`
  return (
    <div className={`storage${tone}`} title={`${text} used (${percent}%). Encrypted size of all photos and videos in the vault.`}>
      <span className="storage__text">
        <span className="visually-hidden">Storage used: </span>
        {text}
      </span>
      <span
        className="storage__bar"
        role="meter"
        aria-label="Storage used"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
        aria-valuetext={`${text} (${percent}%)`}
      >
        <span className="storage__fill" style={{ width: `${Math.max(ratio > 0 ? 2 : 0, percent)}%` }} />
      </span>
    </div>
  )
}

