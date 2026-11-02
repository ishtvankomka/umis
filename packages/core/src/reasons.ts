export const REASON_CODES = [
  'OK',
  'MALFORMED',
  'UNSUPPORTED_FORMAT',
  'ISSUER_UNTRUSTED',
  'ISSUER_VCT_NOT_ALLOWED',
  'ISSUER_KEY_UNKNOWN',
  'ISSUER_SUSPENDED',
  'SIGNATURE_INVALID',
  'HOLDER_BINDING_INVALID',
  'NONCE_MISMATCH',
  'AUDIENCE_MISMATCH',
  'PRESENTATION_EXPIRED',
  'PRESENTATION_TOO_LONG_LIVED',
  'REPLAY',
  'CLOCK_SKEW',
  'UNKNOWN_CREDENTIAL_REF',
  'CREDENTIAL_EXPIRED',
  'CREDENTIAL_NOT_YET_VALID',
  'STATUS_REVOKED',
  'STATUS_SUSPENDED',
  'STATUS_LIST_STALE',
  'STATUS_LIST_MISSING',
  'STATUS_LIST_INVALID',
  'VCT_NOT_ALLOWED',
  'CHANNEL_NOT_ALLOWED',
  'CLAIM_MISSING',
  'DELEGATION_UNDISCLOSED',
  'AUTHORITY_MISSING',
  'AUTHORITY_EXPIRED',
  'AUTHORITY_LIMIT_EXCEEDED',
  'AUTHORITY_PERIOD_EXCEEDED',
  'DELEGATION_WIDER_THAN_PARENT',
  'DELEGATION_DEPTH_EXCEEDED',
  'DELEGATION_OUTLIVES_PARENT',
  'PARENT_REVOKED',
] as const;
export type ReasonCode = (typeof REASON_CODES)[number];

/** Codes of errors that are not verification outcomes: caller mistakes and environment failures. */
export type UmisErrorCode =
  'INVALID_ARGUMENT' | 'CRYPTO_UNAVAILABLE' | 'KEY_NOT_FOUND' | 'USER_CANCELLED' | 'NETWORK' | 'PROTOCOL';

/** The only error type the SDK throws. `code` is a verification reason or one of the {@link UmisErrorCode} values. */
export class UmisError extends Error {
  readonly code: ReasonCode | UmisErrorCode;

  constructor(code: ReasonCode | UmisErrorCode, message?: string, options?: { cause?: unknown }) {
    super(message ?? code, options);
    this.name = 'UmisError';
    this.code = code;
  }
}

const REASON_CODE_SET: ReadonlySet<unknown> = new Set<string>(REASON_CODES);

export function isReasonCode(x: unknown): x is ReasonCode {
  return REASON_CODE_SET.has(x);
}
