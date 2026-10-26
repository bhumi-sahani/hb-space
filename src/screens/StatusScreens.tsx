import { Alert, HeartMark, Spinner } from '../components/ui'

export function LoadingScreen() {
  return (
    <main className="auth-page">
      <div className="center-stack">
        <HeartMark size={48} />
        <Spinner label="Loading HB Space" />
      </div>
    </main>
  )
}

/** Shown when configuration is missing or unsafe. Never prints configured values. */
export function ConfigErrorScreen({ problems }: { problems: string[] }) {
  return (
    <main className="auth-page">
      <div className="auth-card">
        <header className="auth-card__header">
          <HeartMark />
          <h1 className="brand-title">HB Space</h1>
          <p className="auth-card__lede">This build is not configured yet, so sign-in is disabled.</p>
        </header>
        <Alert tone="warning">
          <ul className="plain-list">
            {problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        </Alert>
        <p className="muted small">
          Copy <code>.env.example</code> to <code>.env.local</code> and fill in the values, or set them in your Netlify
          site settings. See README.md for details.
        </p>
      </div>
    </main>
  )
}