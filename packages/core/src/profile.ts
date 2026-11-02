export const PROFILE_ID = 'umis-v1' as const;
export const VCT = {
  orgMember: 'https://umis.systems/vct/org-member/v1',
  roleAuthority: 'https://umis.systems/vct/role-authority/v1',
} as const;
export const TYP = {
  sdJwtVc: 'dc+sd-jwt', //              SD-JWT VC draft-22 §2.2.1 (profile pins -19; unchanged)
  kb: 'kb+jwt', //                      RFC 9901 §4.3
  statusList: 'statuslist+jwt', //      Token Status List draft-21 §5.1
  vciProof: 'openid4vci-proof+jwt', //  OpenID4VCI 1.0 Appendix F.1
  oneWay: 'umis-ow+jwt',
  request: 'umis-req+jwt',
  policy: 'umis-policy+jwt',
  registry: 'umis-registry+jwt',
  event: 'umis-event+jwt',
  relayCommand: 'umis-relay-cmd+jwt',
} as const;
export const ALG = 'ES256' as const;
export const SD_ALG = 'sha-256' as const;
export const DISCLOSABLE_CLAIMS = ['org', 'org_unit', 'role', 'authority', 'delegation', 'display'] as const;
export type DisclosableClaim = (typeof DISCLOSABLE_CLAIMS)[number];
export const CHANNELS = ['qr_oneway', 'qr_full', 'qr_reverse', 'ble', 'oid4vp'] as const;
export type Channel = (typeof CHANNELS)[number];
export const RISK_CLASSES = ['low', 'medium', 'high', 'highest'] as const;
export type RiskClass = (typeof RISK_CLASSES)[number];
export const PERIODS = ['shift', 'day', 'week', 'month', 'operation'] as const;
export type Period = (typeof PERIODS)[number];
export const CLASS_CAPS: Readonly<
  Record<
    RiskClass,
    { readonly maxStatusAgeS: number; readonly channels: readonly Channel[]; readonly biometric: boolean }
  >
> = {
  low: { maxStatusAgeS: 259_200, channels: ['qr_oneway', 'qr_full', 'qr_reverse', 'ble', 'oid4vp'], biometric: false },
  medium: { maxStatusAgeS: 86_400, channels: ['qr_reverse', 'ble', 'oid4vp'], biometric: true },
  high: { maxStatusAgeS: 3_600, channels: ['qr_reverse', 'ble', 'oid4vp'], biometric: true },
  highest: { maxStatusAgeS: 600, channels: ['oid4vp'], biometric: true },
};
export const DEFAULT_REFRESH_S = { online: 600, economy: 3_600 } as const; // Δ, the status refresh interval
export const LIMITS = {
  oneWayMaxTtlS: 30,
  requestMaxTtlS: 120,
  defaultSkewS: 10,
  nonceBytes: 16,
  saltBytes: 16,
  qrMaxChars: 4_296, //        QR version 40-L, alphanumeric mode
  frameMaxBytes: 16_384, //    inflated frame container cap
  statusListMaxBytes: 1_048_576,
} as const;
export const MUTUAL_AUD = 'umis:mutual' as const;
export const FRAME_KINDS = ['oneway', 'full', 'request', 'response', 'mutual_init', 'mutual_reply'] as const;
export type FrameKind = (typeof FRAME_KINDS)[number];
export const FRAME_PREFIX: Readonly<Record<FrameKind, string>> = {
  oneway: 'UMIS1O:',
  full: 'UMIS1F:',
  request: 'UMIS1R:',
  response: 'UMIS1P:',
  mutual_init: 'UMIS1M:',
  mutual_reply: 'UMIS1N:',
};
export const FRAME_KIND_CODE: Readonly<Record<FrameKind, number>> = {
  oneway: 1,
  full: 2,
  request: 3,
  response: 4,
  mutual_init: 5,
  mutual_reply: 6,
};
export const FRAME_TERMINATOR = '.' as const;
export const URI_SCHEMES = { credentialOffer: 'openid-credential-offer://', vpRequest: 'openid4vp://' } as const;
export const UMIS_METADATA_KEYS = {
  statusLists: 'umis_status_lists',
  verifierJwks: 'umis_verifier_jwks',
  registryUri: 'umis_registry_uri',
} as const;
export const URN_PREFIX = {
  checkpoint: 'urn:umis:checkpoint:',
  verifier: 'urn:umis:verifier:',
  wallet: 'urn:umis:wallet:',
  relay: 'urn:umis:relay:',
} as const;
export const UMIS_BLE_V1 = {
  service: '04855e79-ac59-4fd0-b286-dc08d76c0659',
  request: '04855e7a-ac59-4fd0-b286-dc08d76c0659', //  read / notify (verifier → wallet)
  response: '04855e7b-ac59-4fd0-b286-dc08d76c0659', // write (wallet → verifier)
  control: '04855e7c-ac59-4fd0-b286-dc08d76c0659', //  write / notify
} as const;
