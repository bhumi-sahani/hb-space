import { createSupabaseVaultBackend, type VaultBackend } from '../services/vaultBackend'
import { supabase } from './supabase'

/** The app's backend for vault data: the RLS-protected Supabase project. */
export const vaultBackend: VaultBackend | null = supabase ? createSupabaseVaultBackend(supabase) : null
