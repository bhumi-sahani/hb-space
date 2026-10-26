import { isAuthError, isAuthRetryableFetchError } from '@supabase/supabase-js'

/**
 * Maps any authentication failure to a short, user-safe message.
 *
 * Raw backend or browser error messages are never shown: they can reveal
 * internals or whether an account exists. Messages here are fixed strings.
 */

export const AUTH_MESSAGES = {
  invalidCredentials: 'Email or password is incorrect.',
  notActivated: 'This account has not been activated yet. Ask the vault owner to confirm it.',
  blocked: 'This account cannot sign in right now.',
  rateLimited: 'Too many attempts. Wait a few minutes and try again.',
  invitationOnly: 'HB Space is invitation-only. New accounts cannot be created here.',
  network: 'Cannot reach the server. Check your connection and try again.',
  sessionExpired: 'Your session has expired. Please sign in again.',
  passkeyCancelled: 'Passkey sign-in was cancelled or timed out.',
  passkeyDisabled: 'Passkey sign-in is not enabled yet. Use email and password.',
  passkeyNotRegistered: 'That passkey is not registered for HB Space. Sign in with email, then add a passkey in Settings.',
  passkeyDomain: 'Passkeys are not configured for this web address.',
  passkeyAlreadyRegistered: 'This device already has a passkey for your account.',
  passkeyUnavailable: 'No usable passkey was found on this device. Try email and password.',
  passkeyFailed: 'Your passkey could not be verified. Try again or use email and password.',
  generic: 'Something went wrong. Please try again.',
} as const

interface WebAuthnLikeError {
  code: string
  cause?: unknown
}

function isWebAuthnLikeError(error: unknown): error is WebAuthnLikeError {
  if (!(error instanceof Error)) return false
  const code: unknown = (error as { code?: unknown }).code
  return typeof code === 'string' && code.startsWith('ERROR_')
}

function causeName(error: WebAuthnLikeError): string | null {
  const cause = error.cause
  if (cause && typeof cause === 'object' && 'name' in cause && typeof cause.name === 'string') {
    return cause.name
  }
  return null
}

function describeWebAuthnError(error: WebAuthnLikeError): string {
  switch (error.code) {
    case 'ERROR_CEREMONY_ABORTED':
      return AUTH_MESSAGES.passkeyCancelled
    case 'ERROR_INVALID_DOMAIN':
    case 'ERROR_INVALID_RP_ID':
      return AUTH_MESSAGES.passkeyDomain
    case 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED':
      return AUTH_MESSAGES.passkeyAlreadyRegistered
    case 'ERROR_AUTHENTICATOR_MISSING_DISCOVERABLE_CREDENTIAL_SUPPORT':
    case 'ERROR_AUTHENTICATOR_MISSING_USER_VERIFICATION_SUPPORT':
    case 'ERROR_AUTHENTICATOR_NO_SUPPORTED_PUBKEYCREDPARAMS_ALG':
      return AUTH_MESSAGES.passkeyUnavailable
  }
  // NotAllowedError is what browsers raise for user cancellation, timeouts,
  // and "no matching credential" alike; they deliberately don't distinguish.
  const name = causeName(error)
  if (name === 'NotAllowedError' || name === 'AbortError') return AUTH_MESSAGES.passkeyCancelled
  if (name === 'NotSupportedError') return AUTH_MESSAGES.passkeyUnavailable
  if (name === 'SecurityError') return AUTH_MESSAGES.passkeyDomain
  return AUTH_MESSAGES.passkeyFailed
}

export function describeAuthError(error: unknown): string {
  if (isWebAuthnLikeError(error)) return describeWebAuthnError(error)

  if (error instanceof DOMException) {
    if (error.name === 'NotAllowedError' || error.name === 'AbortError') return AUTH_MESSAGES.passkeyCancelled
    return AUTH_MESSAGES.generic
  }

  if (isAuthRetryableFetchError(error)) return AUTH_MESSAGES.network

  if (isAuthError(error)) {
    switch (error.code) {
      case 'invalid_credentials':
        return AUTH_MESSAGES.invalidCredentials
      case 'email_not_confirmed':
      case 'phone_not_confirmed':
        return AUTH_MESSAGES.notActivated
      case 'user_banned':
        return AUTH_MESSAGES.blocked
      case 'over_request_rate_limit':
      case 'over_email_send_rate_limit':
        return AUTH_MESSAGES.rateLimited
      case 'signup_disabled':
        return AUTH_MESSAGES.invitationOnly
      case 'session_expired':
      case 'session_not_found':
      case 'refresh_token_not_found':
      case 'refresh_token_already_used':
        return AUTH_MESSAGES.sessionExpired
    }
    // Passkey error codes are newer than the SDK's ErrorCode union, so compare as strings.
    switch (error.code as string | undefined) {
      case 'passkey_disabled':
        return AUTH_MESSAGES.passkeyDisabled
      case 'webauthn_credential_not_found':
        return AUTH_MESSAGES.passkeyNotRegistered
      case 'webauthn_credential_exists':
        return AUTH_MESSAGES.passkeyAlreadyRegistered
      case 'webauthn_challenge_expired':
      case 'webauthn_challenge_not_found':
        return AUTH_MESSAGES.passkeyCancelled
      case 'webauthn_verification_failed':
        return AUTH_MESSAGES.passkeyFailed
    }
    if (error.status === 429) return AUTH_MESSAGES.rateLimited
    if (error.status === 400 && /invalid login credentials/i.test(error.message)) {
      return AUTH_MESSAGES.invalidCredentials
    }
    return AUTH_MESSAGES.generic
  }

  if (error instanceof TypeError && /fetch|network/i.test(error.message)) return AUTH_MESSAGES.network
  return AUTH_MESSAGES.generic
}
