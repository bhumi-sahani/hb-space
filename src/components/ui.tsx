import { useId, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type Ref } from 'react'

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  busy?: boolean
  icon?: ReactNode
  block?: boolean
}

export function Button({ variant = 'primary', busy = false, icon, block = false, className, children, disabled, ...rest }: ButtonProps) {
  const classes = ['btn', `btn--${variant}`, block ? 'btn--block' : '', className ?? ''].filter(Boolean).join(' ')
  return (
    <button type="button" className={classes} disabled={disabled || busy} aria-busy={busy || undefined} {...rest}>
      {busy ? <Spinner /> : icon}
      <span>{children}</span>
    </button>
  )
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="spinner" role={label ? 'status' : undefined} aria-label={label} aria-hidden={label ? undefined : true} />
  )
}

interface TextFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'id'> {
  label: string
  hint?: string
}

export function TextField({ label, hint, ...rest }: TextFieldProps) {
  const id = useId()
  const hintId = `${id}-hint`
  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>
        {label}
      </label>
      <input id={id} className="field__input" aria-describedby={hint ? hintId : undefined} {...rest} />
      {hint && (
        <p id={hintId} className="field__hint">
          {hint}
        </p>
      )}
    </div>
  )
}

export function SecretField({ label, hint, ...rest }: Omit<TextFieldProps, 'type'>) {
  const id = useId()
  const hintId = `${id}-hint`
  const [visible, setVisible] = useState(false)
  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>
        {label}
      </label>
      <div className="field__row">
        <input
          id={id}
          className="field__input field__input--with-action"
          type={visible ? 'text' : 'password'}
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          aria-describedby={hint ? hintId : undefined}
          {...rest}
        />
        <button
          type="button"
          className="field__action"
          onClick={() => setVisible((v) => !v)}
          aria-pressed={visible}
          aria-controls={id}
          aria-label={visible ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`}
        >
          {visible ? <EyeOffIcon /> : <EyeIcon />}
        </button>
      </div>
      {hint && (
        <p id={hintId} className="field__hint">
          {hint}
        </p>
      )}
    </div>
  )
}

export function Alert({ tone = 'error', children }: { tone?: 'error' | 'info' | 'warning'; children: ReactNode }) {
  return (
    <div className={`alert alert--${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      {children}
    </div>
  )
}

export function HeartMark({ size = 56 }: { size?: number }) {
  return (
    <svg className="heart-mark" width={size} height={size} viewBox="0 0 64 64" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="hb-heart" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#f4c4d1" />
          <stop offset="1" stopColor="#b9668a" />
        </linearGradient>
      </defs>
      <path
        d="M32 54s-19-11.6-19-26.2C13 20.7 18.4 15 25.2 15c3 0 5.4 1.3 6.8 3.4C33.4 16.3 35.8 15 38.8 15 45.6 15 51 20.7 51 27.8 51 42.4 32 54 32 54z"
        fill="url(#hb-heart)"
      />
    </svg>
  )
}

export function PasskeyIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="9" cy="8" r="4" />
      <path d="M2 20c0-3.3 3.1-6 7-6 1.2 0 2.3.2 3.3.7" />
      <circle cx="18" cy="13" r="2.5" />
      <path d="M18 15.5V21l1.5-1.2M18 18.5l1.5-1" />
    </svg>
  )
}

export function LockIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4.5" y="10.5" width="15" height="10" rx="2.5" />
      <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    </svg>
  )
}

export function GalleryIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.8" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.8" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.8" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.8" />
    </svg>
  )
}

export function SettingsIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3l1.6 2.3 2.8-.4.6 2.7 2.5 1.3-1.1 2.6 1.1 2.6-2.5 1.3-.6 2.7-2.8-.4L12 21l-1.6-2.3-2.8.4-.6-2.7-2.5-1.3 1.1-2.6L4.5 9.9 7 8.6l.6-2.7 2.8.4z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  )
}

function EyeIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  )
}

function EyeOffIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 3l18 18" />
      <path d="M10.6 5.1A10.9 10.9 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-3.2 4.1M6.6 6.6C3.8 8.4 2 12 2 12s3.6 7 10 7c1.8 0 3.3-.5 4.6-1.2" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
    </svg>
  )
}

// ---------------------------------------------------------------------------
// Phase 4 icons (inline SVG; no icon font or external requests)
// ---------------------------------------------------------------------------

const ICON_PATHS = {
  folder: 'M3.5 7.5a2 2 0 0 1 2-2h4l2 2.5h7a2 2 0 0 1 2 2v7.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z',
  folderPlus: 'M3.5 7.5a2 2 0 0 1 2-2h4l2 2.5h7a2 2 0 0 1 2 2v7.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2zM12 11v6M9 14h6',
  play: 'M8 5.5v13l11-6.5z',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  trash: 'M4.5 7h15M10 11v6M14 11v6M6 7l1 12.5a1.5 1.5 0 0 0 1.5 1.5h7a1.5 1.5 0 0 0 1.5-1.5L18 7M9 7V4.5h6V7',
  download: 'M12 4v11M7 10.5l5 5 5-5M5 19.5h14',
  upload: 'M12 20V9M7 13.5l5-5 5 5M5 4.5h14',
  plus: 'M12 5v14M5 12h14',
  chevronLeft: 'M15 5l-7 7 7 7',
  chevronRight: 'M9 5l7 7-7 7',
  close: 'M6 6l12 12M18 6L6 18',
  move: 'M3.5 7.5a2 2 0 0 1 2-2h4l2 2.5h7a2 2 0 0 1 2 2v7.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2zM10 14h6M13.5 11.5L16 14l-2.5 2.5',
  restore: 'M4 12a8 8 0 1 0 2.4-5.7M4 4.5V9h4.5',
  edit: 'M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4',
  image: 'M4 5.5h16v13H4zM4 15.5l4.5-4.5 4 4 2.5-2.5 5 5M15.5 9.5h.01',
  search: 'M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13zM15.5 15.5L20 20',
  select: 'M4.5 4.5h6v6h-6zM13.5 4.5h6v6h-6zM4.5 13.5h6v6h-6zM14 16.5l2 2 4-4',
  zoomIn: 'M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13zM15.5 15.5L20 20M10.5 8v5M8 10.5h5',
  camera: 'M4 8.5a2 2 0 0 1 2-2h2l1.5-2h5l1.5 2h2a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zM12 16a3.25 3.25 0 1 0 0-6.5 3.25 3.25 0 0 0 0 6.5z',
  switchCamera: 'M4 8.5a2 2 0 0 1 2-2h2l1.5-2h5l1.5 2h2a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zM9 12.5a3 3 0 0 1 5.2-2M15 12.5a3 3 0 0 1-5.2 2M14.2 8.5v2h-2M9.8 16.5v-2h2',
  more: 'M4.75 12a1.25 1.25 0 1 0 2.5 0a1.25 1.25 0 1 0-2.5 0zM10.75 12a1.25 1.25 0 1 0 2.5 0a1.25 1.25 0 1 0-2.5 0zM16.75 12a1.25 1.25 0 1 0 2.5 0a1.25 1.25 0 1 0-2.5 0z',
  grid: 'M4.5 4.5h6v6h-6zM13.5 4.5h6v6h-6zM4.5 13.5h6v6h-6zM13.5 13.5h6v6h-6z',
  list: 'M9 6.5h10.5M9 12h10.5M9 17.5h10.5M4.75 6.5h.5M4.75 12h.5M4.75 17.5h.5',
  zoomOut: 'M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13zM15.5 15.5L20 20M8 10.5h5',
} as const

export type IconName = keyof typeof ICON_PATHS

export function Icon({ name, size = 20 }: { name: IconName; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      aria-hidden="true"
      focusable="false"
      fill={name === 'play' || name === 'more' ? 'currentColor' : 'none'}
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={ICON_PATHS[name]} />
    </svg>
  )
}

/** Icon-only button with an accessible name and a >= 44px touch target. */
export function IconButton({
  icon,
  label,
  className,
  ...rest
}: { icon: IconName; label: string; ref?: Ref<HTMLButtonElement> } & Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children' | 'aria-label'>) {
  return (
    <button type="button" className={['icon-btn', className ?? ''].filter(Boolean).join(' ')} aria-label={label} title={label} {...rest}>
      <Icon name={icon} />
    </button>
  )
}
