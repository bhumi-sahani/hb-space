/// <reference types="vite/client" />

// Every VITE_* value is compiled into the public bundle. Never put secrets here.
interface ImportMetaEnv {
  readonly VITE_SUPABASE_URL?: string
  readonly VITE_SUPABASE_PUBLISHABLE_KEY?: string
  readonly VITE_ENABLE_PASSKEYS?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
