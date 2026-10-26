import { useSyncExternalStore } from 'react'
import { Button, Icon, IconButton, Spinner } from '../../components/ui'
import type { EntryStatus, UploadQueue } from '../../services/uploadQueue'
import { formatBytes } from './formFields'

const STATUS_TEXT: Record<EntryStatus, string> = {
  queued: 'Waiting',
  checking: 'Checking file',
  encrypting: 'Encrypting on this device',
  uploading: 'Uploading encrypted data',
  finishing: 'Finishing',
  done: 'Encrypted and uploaded',
  failed: 'Failed',
  cancelled: 'Cancelled',
}

const ACTIVE: EntryStatus[] = ['checking', 'encrypting', 'uploading', 'finishing']

export function UploadPanel({ queue }: { queue: UploadQueue }) {
  const entries = useSyncExternalStore(queue.subscribe, queue.getSnapshot)
  if (entries.length === 0) return null

  const done = entries.filter((e) => e.status === 'done').length
  const failed = entries.filter((e) => e.status === 'failed').length
  const pending = entries.filter((e) => e.status === 'queued' || ACTIVE.includes(e.status)).length

  return (
    <section className="panel stack upload-panel" aria-labelledby="upload-panel-title">
      <div className="vault-head">
        <h2 id="upload-panel-title" className="panel__title vault-head__title upload-panel__title">
          Uploads
        </h2>
        <span className="muted small" role="status">
          {done} done{failed > 0 ? ` · ${failed} failed` : ''}
          {pending > 0 ? ` · ${pending} to go` : ''}
        </span>
      </div>
      <ul className="queue" aria-label="Upload queue">
        {entries.map((entry) => {
          const active = ACTIVE.includes(entry.status)
          return (
            <li key={entry.key} className={`queue__row queue__row--${entry.status}`}>
              <span className="queue__icon" aria-hidden="true">
                {active ? <Spinner /> : entry.status === 'done' ? <Icon name="check" size={18} /> : entry.status === 'failed' ? <Icon name="close" size={18} /> : <Icon name="upload" size={18} />}
              </span>
              <span className="queue__body">
                <span className="queue__name">{entry.name}</span>
                <span className="queue__status">
                  {STATUS_TEXT[entry.status]}
                  {entry.status === 'failed' && entry.error ? `: ${entry.error}` : ''} · {formatBytes(entry.size)}
                </span>
              </span>
              {entry.status === 'failed' && entry.retryable !== false && (
                <Button variant="ghost" onClick={() => queue.retry(entry.key)}>
                  Retry
                </Button>
              )}
              {(entry.status === 'queued' || active) && (
                <IconButton icon="close" label={`Cancel upload of ${entry.name}`} onClick={() => queue.cancel(entry.key)} />
              )}
            </li>
          )
        })}
      </ul>
      {pending === 0 && (
        <Button variant="ghost" onClick={() => queue.clearFinished()}>
          Clear list
        </Button>
      )}
    </section>
  )
}
