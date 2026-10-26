import { createClient, type SupabaseClient } from '@supabase/supabase-js'
import { configResult } from '../config/env'

/**
 * The single browser Supabase client.
 *
 * It is created only from a validated publishable/anon key (see config/env.ts).
 * That key grants nothing by itself: every table and storage object must be
 * protected by Row Level Security. Null when configuration is missing or unsafe.
 */
export const supabase: SupabaseClient | null = configResult.ok
  ? createClient(configResult.config.supabaseUrl, configResult.config.supabasePublishableKey, {
      auth: {
        // Session tokens persist in localStorage so phones stay signed in.
        // The vault encryption key is never persisted (see SECURITY_ARCHITECTURE.md §6).
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
        flowType: 'pkce',
        experimental: { passkey: configResult.config.passkeysEnabled },
      },
    })
  : null

export const passkeysEnabled = configResult.ok && configResult.config.passkeysEnabled
