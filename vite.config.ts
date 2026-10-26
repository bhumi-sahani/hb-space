import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    // No source maps in production: they are public and would expose full source unnecessarily.
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}', 'supabase/tests/**/*.test.ts'],
    restoreMocks: true,
  },
})
