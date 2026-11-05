import type { CryptoProvider } from './crypto/provider.js';
import type { Channel, DisclosableClaim, Period, RiskClass } from './profile.js';
import type { ReasonCode } from './reasons.js';

export interface EcPublicJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  kid?: string;
  alg?: 'ES256';
  use?: 'sig';
}
export interface EcPrivateJwk extends EcPublicJwk {
  d: string;
}
/** ES256 signer. `sign` returns the 64-byte IEEE P1363 signature r‖s (RFC 7518 §3.4). */
export interface Signer {
  readonly alg: 'ES256';
  readonly kid: string;
  readonly publicJwk: EcPublicJwk;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export interface StatusRef {
  uri: string;
  idx: number;
}
export interface AuthorityLimit {
  amount: number;
  unit: string;
  per?: Period;
}
export interface AuthorityItem {
  action: string;
  resource: string;
  limit: AuthorityLimit;
  object?: string;
  valid_until?: number;
}
export interface DelegationParent {
  id: string;
  status: StatusRef;
  authority: AuthorityItem[];
  exp: number;
}
export interface DelegationClaim {
  parent?: DelegationParent;
  depth: number;
  max_depth: number;
}
export interface UmisClaimSet {
  org: { id: string; name: string; lei?: string };
  org_unit?: { id: string; name: string };
  role?: { code: string; name: string };
  authority?: AuthorityItem[];
  delegation?: DelegationClaim;
  display?: { name: string; photo_hash?: string };
}
/** Always-visible (non-disclosable) claims of a UMIS credential. */
export interface CredentialPayload {
  iss: string;
  sub: string;
  jti: string;
  iat: number;
  exp: number;
  nbf?: number;
  vct: string;
  cnf: { jwk: EcPublicJwk };
  status: { status_list: StatusRef };
}
export interface AuthorityRequest {
  action: string;
  resource: string;
  amount: number;
  unit: string;
  object?: string;
}

export interface TrustedIssuerEntryV1 {
  issuer: string;
  name: string;
  jwks: { keys: EcPublicJwk[] };
  vcts: string[];
  statusLists: string[];
  validUntil?: number;
  status: 'active' | 'suspended' | 'revoked';
}
export interface CheckpointPolicyV1 {
  schema: 'umis.policy.v1';
  riskClass: RiskClass;
  channels: Channel[];
  maxStatusAgeSeconds: number; //      S
  statusRefreshSeconds: number; //     Δ ≤ S
  oneWayTokenMaxAgeSeconds: number; // ≤ 30
  requireBiometric: boolean;
  accepted: Array<{ vct: string; issuers: 'self' | 'registry' | string[] }>;
  requestedClaims: Array<Exclude<DisclosableClaim, 'delegation'>>;
  authority?: {
    action: string;
    resource: string;
    unit: string;
    amountSource: 'request' | 'fixed';
    fixedAmount?: number;
  };
  relay?: { openSeconds: number };
}
export interface MemberCacheEntry {
  credRef: string;
  issuer: string;
  vct: string;
  cnfJwk: EcPublicJwk;
  exp: number;
  status: StatusRef;
  claims: Pick<UmisClaimSet, 'org' | 'org_unit' | 'role' | 'display'>;
}
/** Resolves to false when `id` was already seen (replay). */
export interface ReplayStore {
  checkAndRemember(id: string, expiresAt: number): Promise<boolean>;
}
export interface PeriodWindow {
  start: number;
  end: number;
}
export interface AuthorityLedger {
  used(key: string, window: PeriodWindow): Promise<number>;
  add(key: string, window: PeriodWindow, amount: number): Promise<void>;
}
/**
 * Minimal fetch contract (global fetch, expo fetch and test doubles all satisfy it). `redirect` has the Fetch standard
 * meaning: `'error'` asks the implementation to fail instead of following a redirect.
 */
export type FetchLike = (
  url: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
    redirect?: 'follow' | 'error' | 'manual';
  },
) => Promise<{ status: number; headers: { get(name: string): string | null }; text(): Promise<string> }>;
export interface ParsedStatusList {
  uri: string;
  iat: number;
  exp?: number;
  ttl?: number;
  bits: 1 | 2 | 4 | 8;
  size: number;
  get(idx: number): number;
}
export interface StatusListCache {
  get(token: string): ParsedStatusList | undefined;
  set(token: string, value: ParsedStatusList): void;
}

export interface VerifierContext {
  now: number;
  audiences: readonly string[];
  policy: CheckpointPolicyV1;
  trusted: readonly TrustedIssuerEntryV1[];
  statusLists: ReadonlyMap<string, { token: string; fetchedAt: number }>;
  memberCache?: ReadonlyMap<string, MemberCacheEntry>;
  replay: ReplayStore;
  selfIssuer?: string; //                       issuer id that the policy value 'self' means
  ledger?: AuthorityLedger; //                  per-period accumulation (for example per shift)
  statusCache?: StatusListCache; //             memo of verified status-list tokens (performance)
  fetchStatusList?: (uri: string) => Promise<string>; // online verifiers only (OID4VP OP)
  crypto?: CryptoProvider;
  skewSeconds?: number; //                      default LIMITS.defaultSkewS
  pointId?: string;
  policyVersion?: number;
}
export type StepName =
  | 'parse'
  | 'issuer_trust'
  | 'issuer_signature'
  | 'holder_binding'
  | 'validity'
  | 'status'
  | 'policy'
  | 'authority'
  | 'decision';
export interface CheckStep {
  step: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;
  name: StepName;
  ok: boolean;
  ms: number;
  skipped?: boolean;
  reason?: ReasonCode;
}
export interface VerificationResult {
  decision: 'accept' | 'reject';
  reasons: ReasonCode[]; //                     ['OK'] on accept, exactly one code on reject
  channel: Channel;
  at: number;
  issuer?: string;
  vct?: string;
  credentialRef?: string;
  claims?: Partial<UmisClaimSet> & { sub?: string }; // only after issuer trust and signature passed
  statusListAgeSeconds?: number;
  authority?: { requested: AuthorityRequest; matched?: AuthorityItem; usedInPeriod?: number };
  delegation?: { depth: number; parentId?: string };
  timings: { totalMs: number };
  trace: CheckStep[];
  pointId?: string;
  policyVersion?: number;
}
export interface PresentationRequestPayloadV1 {
  v: 1;
  nonce: string; //                             ≥ 16 random bytes, base64url
  aud: string; //                               requester id: urn:umis:verifier:<id> | urn:umis:wallet:<id>
  iat: number;
  exp: number; //                               exp − iat ≤ LIMITS.requestMaxTtlS
  vct: string[];
  claims: DisclosableClaim[];
  authority?: AuthorityRequest;
  policy?: { id: string; v: number; risk: RiskClass };
  verifier?: { name: string; org?: string }; // self-asserted display name
  mutual?: boolean;
}
export interface ParsedRequest extends PresentationRequestPayloadV1 {
  kind: 'request' | 'mutual_init';
  jws: string;
  kid?: string;
  signatureVerified: boolean;
  counterPresentation?: string; //              mutual_init only: the requester's SD-JWT+KB
}
export interface PendingRequest {
  nonce: string;
  aud: string;
  iat: number;
  exp: number;
  vct: string[];
  claims: DisclosableClaim[];
  authority?: AuthorityRequest;
  policyId?: string;
  mutual: boolean;
}
export interface OneWayTokenPayload {
  cred_ref: string;
  aud: string;
  iat: number;
  exp: number;
  ctr: number;
}
export interface DecisionEventV1 {
  iss: string;
  seq: number;
  iat: number;
  chk: string;
  ch: Channel;
  dec: 'accept' | 'reject';
  rsn: ReasonCode[];
  vct?: string;
  ciss?: string;
  cref?: string;
  lat: number;
  sla?: number;
  pv?: number;
}
export interface CredentialOffer {
  credential_issuer: string;
  credential_configuration_ids: string[];
  grants: {
    'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
      'pre-authorized_code': string;
      tx_code?: { length?: number; input_mode?: 'numeric' | 'text'; description?: string };
    };
  };
}
