import { AuthApiError, AuthRetryableFetchError } from '@supabase/supabase-js'
import { describe, expect, it } from 'vitest'
import { AUTH_MESSAGES, describeAuthError } from './authErrors'

function webAuthnError(code: string, causeName?: string) {
  const error = new Error('raw browser detail') as Error & { code: string; cause?: unknown }
  error.code = code
  if (causeName) error.cause = { name: causeName }
  return error
}

describe('describeAuthError', () => {
  it('maps invalid credentials without revealing whether the account exists', () => {
    const error = new AuthApiError('Invalid login credentials', 400, 'invalid_credentials')
    expect(describeAuthError(error)).toBe(AUTH_MESSAGES.invalidCredentials)
  })

  it('maps rate limiting', () => {
    expect(describeAuthError(new AuthApiError('slow down', 429, 'over_request_rate_limit'))).toBe(AUTH_MESSAGES.rateLimited)
    expect(describeAuthError(new AuthApiError('slow down', 429, undefined))).toBe(AUTH_MESSAGES.rateLimited)
  })

  it('maps disabled signups to an invitation-only message', () => {
    expect(describeAuthError(new AuthApiError('Signups not allowed', 422, 'signup_disabled'))).toBe(AUTH_MESSAGES.invitationOnly)
  })

  it('maps network failures', () => {
    expect(describeAuthError(new AuthRetryableFetchError('Failed to fetch', 0))).toBe(AUTH_MESSAGES.network)
  })

  it('maps passkey server error codes', () => {
    expect(describeAuthError(new AuthApiError('x', 400, 'passkey_disabled' as never))).toBe(AUTH_MESSAGES.passkeyDisabled)
    expect(describeAuthError(new AuthApiError('x', 404, 'webauthn_credential_not_found' as never))).toBe(
      AUTH_MESSAGES.passkeyNotRegistered,
    )
    expect(describeAuthError(new AuthApiError('x', 400, 'webauthn_verification_failed' as never))).toBe(AUTH_MESSAGES.passkeyFailed)
  })

  it('treats browser cancellation as a cancellation', () => {
    expect(describeAuthError(webAuthnError('ERROR_CEREMONY_ABORTED'))).toBe(AUTH_MESSAGES.passkeyCancelled)
    expect(describeAuthError(webAuthnError('ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY', 'NotAllowedError'))).toBe(
      AUTH_MESSAGES.passkeyCancelled,
    )
    expect(describeAuthError(new DOMException('cancelled', 'NotAllowedError'))).toBe(AUTH_MESSAGES.passkeyCancelled)
  })

  it('maps relying-party misconfiguration', () => {
    expect(describeAuthError(webAuthnError('ERROR_INVALID_RP_ID'))).toBe(AUTH_MESSAGES.passkeyDomain)
  })

  it('maps duplicate passkey registration', () => {
    expect(describeAuthError(webAuthnError('ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED'))).toBe(
      AUTH_MESSAGES.passkeyAlreadyRegistered,
    )
  })

  it('never surfaces raw error text', () => {
    const leaky = new AuthApiError('database error: relation "secret_table" at host 10.0.0.1', 500, 'unexpected_failure')
    const message = describeAuthError(leaky)
    expect(message).toBe(AUTH_MESSAGES.generic)
    expect(describeAuthError(new Error('stack trace with internals'))).toBe(AUTH_MESSAGES.generic)
    expect(describeAuthError('a string')).toBe(AUTH_MESSAGES.generic)
    expect(describeAuthError(null)).toBe(AUTH_MESSAGES.generic)
  })
})
