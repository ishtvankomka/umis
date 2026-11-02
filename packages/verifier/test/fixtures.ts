import { expect } from 'vitest';
import {
  MUTUAL_AUD,
  TYP,
  VCT,
  base64urlEncode,
  decodeFrame,
  decodePresentationRequest,
  encodeFrame,
  generateSigner,
  issueCredential,
  presentCredential,
  randomId,
  utf8Encode,
  webCryptoProvider,
} from '@umis/core';
import type {
  AuthorityItem,
  AuthorityRequest,
  CryptoProvider,
  DisclosableClaim,
  ParsedRequest,
  PendingRequest,
  ReasonCode,
  Signer,
  TrustedIssuerEntryV1,
  UmisClaimSet,
  VerificationResult,
  VerifierContext,
} from '@umis/core';
import { DEFAULT_POLICIES, createMemoryLedger } from '@umis/policy';
import { parseRegistry, selfEntry, signRegistry } from '@umis/registry';
import { buildStatusListToken } from '@umis/status-list';
import { createMemoryReplayStore, createRequestQr, memberCacheEntryFromCredential } from '../src/index.js';
import type { CreateRequestInput } from '../src/index.js';

export const DAY = 86_400;
/** 2026-11-04T00:00:00Z: when the credentials were issued. */
export const T0 = 1_793_750_400;
/** The moment a request is made. */
export const NOW = T0 + 3_600;
/** The moment a decision is taken in most tests: after the request and the answer to it. */
export const AT = NOW + 2;

export const ISSUER_A = 'https://issuer.example/contractor-a';
export const ISSUER_B = 'https://issuer.example/supplier-b';
export const ISSUER_V = 'https://issuer.example/coworking-v';
export const LIST_A = 'https://issuer.example/status/contractor-a/1';
export const LIST_B = 'https://issuer.example/status/supplier-b/1';
export const LIST_V = 'https://issuer.example/status/coworking-v/1';
export const VERIFIER_B = 'urn:umis:verifier:warehouse-b';
export const WALLET_OLEH = 'urn:umis:wallet:oleh';

export const TEN_TONNES: AuthorityRequest = { action: 'receive_materials', resource: 'rebar', amount: 10, unit: 't' };

export const OLEH_AUTHORITY: AuthorityItem[] = [
  {
    action: 'receive_materials',
    resource: 'rebar',
    limit: { amount: 10, unit: 't', per: 'shift' },
    object: 'bridge-01',
  },
];
export const IVAN_AUTHORITY: AuthorityItem[] = [
  {
    action: 'receive_materials',
    resource: 'rebar',
    limit: { amount: 8, unit: 't', per: 'shift' },
    object: 'bridge-01',
  },
];

const ORG_A = { id: 'contractor-a', name: 'Підрядник А' };
const ORG_B = { id: 'supplier-b', name: 'Постачальник Б' };
const ORG_V = { id: 'coworking-v', name: 'Коворкінг В' };

/** Indexes in the status lists. */
export const IDX = { oleh: 1, ivan: 2, spare: 3, mariia: 1, andriy: 1 } as const;
const LIST_SIZE = 1_024;

export interface World {
  crypto: CryptoProvider;
  issuerA: Signer;
  issuerB: Signer;
  issuerV: Signer;
  ownerB: Signer;
  deviceB: Signer;
  oleh: Signer;
  ivan: Signer;
  mariia: Signer;
  andriy: Signer;
  /** Role-authority credentials of contractor A: a root of 10 t per shift and its delegate of 8 t. */
  olehCredential: string;
  ivanCredential: string;
  /** Org-member credential of the supplier's warehouse manager. */
  mariiaCredential: string;
  /** Org-member credential of a coworking resident. */
  andriyCredential: string;
  /** The registry of supplier B: it trusts contractor A. */
  entryA: TrustedIssuerEntryV1;
  /** The registry of contractor A: it trusts supplier B. */
  entryB: TrustedIssuerEntryV1;
  trustedByB: TrustedIssuerEntryV1[];
  trustedByA: TrustedIssuerEntryV1[];
  /** Status lists signed in time, with nothing revoked. */
  listA: string;
  listB: string;
  listV: string;
}

/** A status list token for `uri` signed by `signer`; `revoked` and `suspended` are indexes. */
export function statusList(
  signer: Signer,
  uri: string,
  o: { iat: number; revoked?: number[]; suspended?: number[]; exp?: number },
): Promise<string> {
  const values = new Uint8Array(LIST_SIZE);
  for (const index of o.revoked ?? []) values[index] = 1;
  for (const index of o.suspended ?? []) values[index] = 2;
  return buildStatusListToken({
    signer,
    uri,
    bits: 2,
    values,
    iat: o.iat,
    ...(o.exp === undefined ? {} : { exp: o.exp }),
  });
}

export interface CredentialSpec {
  issuer: Signer;
  iss: string;
  holder: Signer;
  jti: string;
  idx: number;
  listUri: string;
  vct?: string;
  iat?: number;
  exp?: number;
  nbf?: number;
  claims: Partial<UmisClaimSet>;
  crypto: CryptoProvider;
}

export function credential(spec: CredentialSpec): Promise<string> {
  return issueCredential({
    signer: spec.issuer,
    payload: {
      iss: spec.iss,
      sub: `p_${spec.jti}`,
      jti: spec.jti,
      iat: spec.iat ?? T0,
      exp: spec.exp ?? T0 + 90 * DAY,
      ...(spec.nbf === undefined ? {} : { nbf: spec.nbf }),
      vct: spec.vct ?? VCT.roleAuthority,
      cnf: { jwk: spec.holder.publicJwk },
      status: { status_list: { idx: spec.idx, uri: spec.listUri } },
    },
    claims: spec.claims,
    crypto: spec.crypto,
  });
}

/** The delegation claim of a credential issued under the root Oleh holds. */
export const OLEH_PARENT = {
  id: 'cred-oleh-0001',
  status: { idx: IDX.oleh, uri: LIST_A },
  authority: OLEH_AUTHORITY,
  exp: T0 + 90 * DAY,
};

export async function registryOf(owner: Signer, entries: TrustedIssuerEntryV1[]): Promise<TrustedIssuerEntryV1[]> {
  const jws = await signRegistry({ iss: 'urn:umis:org:registry-owner', ver: 1, iat: T0, entries }, owner);
  return (await parseRegistry(jws, owner.publicJwk)).entries;
}

export function entryFor(
  signer: Signer,
  issuer: string,
  name: string,
  vcts: string[],
  listUri: string,
): TrustedIssuerEntryV1 {
  return selfEntry({ issuer, name, keys: [signer.publicJwk], vcts, statusLists: [listUri] });
}

/** Contractor A, supplier B and coworking V with their people, credentials, registries and status lists. */
export async function buildWorld(crypto: CryptoProvider = webCryptoProvider): Promise<World> {
  const [issuerA, issuerB, issuerV, ownerB, deviceB, oleh, ivan, mariia, andriy] = (await Promise.all(
    Array.from({ length: 9 }, () => generateSigner({ crypto })),
  )) as [Signer, Signer, Signer, Signer, Signer, Signer, Signer, Signer, Signer];

  const [olehCredential, ivanCredential, mariiaCredential, andriyCredential] = await Promise.all([
    credential({
      issuer: issuerA,
      iss: ISSUER_A,
      holder: oleh,
      jti: 'cred-oleh-0001',
      idx: IDX.oleh,
      listUri: LIST_A,
      claims: {
        org: ORG_A,
        org_unit: { id: 'bridge-crew', name: 'Бригада будівництва мосту' },
        role: { code: 'crew_lead', name: 'Керівник бригади' },
        authority: OLEH_AUTHORITY,
        delegation: { depth: 0, max_depth: 1 },
        display: { name: 'Олег' },
      },
      crypto,
    }),
    credential({
      issuer: issuerA,
      iss: ISSUER_A,
      holder: ivan,
      jti: 'cred-ivan-0001',
      idx: IDX.ivan,
      listUri: LIST_A,
      iat: T0 + 60,
      exp: T0 + 30 * DAY,
      claims: {
        org: ORG_A,
        role: { code: 'crew_member', name: 'Бригадир зміни' },
        authority: IVAN_AUTHORITY,
        delegation: { parent: OLEH_PARENT, depth: 1, max_depth: 1 },
        display: { name: 'Іван' },
      },
      crypto,
    }),
    credential({
      issuer: issuerB,
      iss: ISSUER_B,
      holder: mariia,
      jti: 'cred-mariia-0001',
      idx: IDX.mariia,
      listUri: LIST_B,
      vct: VCT.orgMember,
      claims: {
        org: ORG_B,
        role: { code: 'warehouse_manager', name: 'Комірник' },
        display: { name: 'Марія' },
      },
      crypto,
    }),
    credential({
      issuer: issuerV,
      iss: ISSUER_V,
      holder: andriy,
      jti: 'cred-andriy-0001',
      idx: IDX.andriy,
      listUri: LIST_V,
      vct: VCT.orgMember,
      claims: { org: ORG_V, role: { code: 'resident', name: 'Резидент' }, display: { name: 'Андрій' } },
      crypto,
    }),
  ]);

  const entryA = entryFor(issuerA, ISSUER_A, ORG_A.name, [VCT.roleAuthority, VCT.orgMember], LIST_A);
  const entryB = entryFor(issuerB, ISSUER_B, ORG_B.name, [VCT.orgMember, VCT.roleAuthority], LIST_B);
  const [listA, listB, listV, trustedByB, trustedByA] = await Promise.all([
    statusList(issuerA, LIST_A, { iat: NOW - 600 }),
    statusList(issuerB, LIST_B, { iat: NOW - 600 }),
    statusList(issuerV, LIST_V, { iat: NOW - 600 }),
    registryOf(ownerB, [entryA]),
    registryOf(ownerB, [entryB]),
  ]);
  return {
    crypto,
    issuerA,
    issuerB,
    issuerV,
    ownerB,
    deviceB,
    oleh,
    ivan,
    mariia,
    andriy,
    olehCredential,
    ivanCredential,
    mariiaCredential,
    andriyCredential,
    entryA,
    entryB,
    trustedByB,
    trustedByA,
    listA,
    listB,
    listV,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// verifier contexts
// ---------------------------------------------------------------------------------------------------------------

type Overrides = Partial<VerifierContext>;

const held = (token: string) => ({ token, fetchedAt: NOW - 300 });

/** Supplier B's warehouse: a medium-class checkpoint that trusts contractor A through its registry. */
export function warehouseContext(w: World, over: Overrides = {}): VerifierContext {
  return {
    now: AT,
    audiences: [VERIFIER_B],
    policy: structuredClone(DEFAULT_POLICIES.warehouse_medium),
    trusted: w.trustedByB,
    statusLists: new Map([[LIST_A, held(w.listA)]]),
    replay: createMemoryReplayStore(),
    ledger: createMemoryLedger(),
    selfIssuer: ISSUER_B,
    pointId: 'gate-1',
    policyVersion: 3,
    crypto: w.crypto,
    ...over,
  };
}

/** Coworking V's door: a low-class checkpoint for its own residents, whose credentials are in the member cache. */
export async function doorContext(w: World, over: Overrides = {}): Promise<VerifierContext> {
  const resident = await memberCacheEntryFromCredential(w.andriyCredential, w.crypto);
  return {
    now: AT,
    audiences: [ISSUER_V],
    policy: structuredClone(DEFAULT_POLICIES.door_low),
    trusted: [entryFor(w.issuerV, ISSUER_V, ORG_V.name, [VCT.orgMember], LIST_V)],
    statusLists: new Map([[LIST_V, held(w.listV)]]),
    memberCache: new Map([[resident.credRef, resident]]),
    replay: createMemoryReplayStore(),
    selfIssuer: ISSUER_V,
    pointId: 'door-1',
    policyVersion: 1,
    crypto: w.crypto,
    ...over,
  };
}

/** Supplier B reading the person who opens a mutual exchange. */
export function mutualContextB(w: World, over: Overrides = {}): VerifierContext {
  return warehouseContext(w, { policy: structuredClone(DEFAULT_POLICIES.mutual_medium), ...over });
}

/** Contractor A's side of the exchange: it trusts supplier B and reads the reply. */
export function mutualContextA(w: World, over: Overrides = {}): VerifierContext {
  return warehouseContext(w, {
    policy: structuredClone(DEFAULT_POLICIES.mutual_medium),
    trusted: w.trustedByA,
    statusLists: new Map([[LIST_B, held(w.listB)]]),
    audiences: [WALLET_OLEH],
    ...over,
  });
}

// ---------------------------------------------------------------------------------------------------------------
// the wallet side: requests, answers and one-way tokens
// ---------------------------------------------------------------------------------------------------------------

/** Marija's request: ten tonnes of rebar. */
export function ask(
  w: World,
  over: Partial<CreateRequestInput> = {},
): Promise<{ qr: string; pending: PendingRequest }> {
  return createRequestQr({
    deviceSigner: w.deviceB,
    audience: VERIFIER_B,
    claims: ['org', 'role', 'authority'],
    authority: TEN_TONNES,
    policy: { id: 'warehouse_medium', v: 3, risk: 'medium' },
    verifier: { name: 'Постачальник Б', org: ORG_B.id },
    now: NOW,
    crypto: w.crypto,
    ...over,
  });
}

export interface AnswerOptions {
  disclose?: readonly DisclosableClaim[];
  iat?: number;
  aud?: string;
  nonce?: string;
  kind?: 'response' | 'mutual_reply';
  /** The key that signs the key-binding JWT; the credential's holder by default. */
  kbSigner?: Signer;
}

/** The presentation a wallet makes in answer to a request. */
export function presentation(
  w: World,
  cred: string,
  holder: Signer,
  pending: PendingRequest,
  o: AnswerOptions = {},
): Promise<string> {
  return presentCredential({
    credential: cred,
    disclose: o.disclose ?? pending.claims,
    kb: {
      signer: o.kbSigner ?? holder,
      aud: o.aud ?? pending.aud,
      nonce: o.nonce ?? pending.nonce,
      iat: o.iat ?? pending.iat + 1,
    },
    crypto: w.crypto,
  });
}

/** The text of the QR code that a wallet shows in answer to a request. */
export async function answer(
  w: World,
  cred: string,
  holder: Signer,
  pending: PendingRequest,
  o: AnswerOptions = {},
): Promise<string> {
  const token = await presentation(w, cred, holder, pending, o);
  return encodeFrame({ kind: o.kind ?? (pending.mutual ? 'mutual_reply' : 'response'), tokens: [token] });
}

/** What a wallet makes of a `mutual_init` QR code, as far as the verifier is concerned: the signed text and the rest. */
export function readMutualInit(qr: string): ParsedRequest {
  const frame = decodeFrame(qr);
  const [jws, counterPresentation] = frame.tokens as [string, string];
  const { header, payload } = decodePresentationRequest(jws);
  return {
    ...payload,
    kind: 'mutual_init',
    jws,
    ...(header.kid === undefined ? {} : { kid: header.kid }),
    signatureVerified: true,
    counterPresentation,
  };
}

const segment = (value: unknown): string => base64urlEncode(utf8Encode(JSON.stringify(value)));

/** A JWS with exactly this header and payload, signed by `signer`: for tokens that are wrong in one respect. */
export async function forgeJws(signer: Signer, header: object, payload: object): Promise<string> {
  const signingInput = `${segment(header)}.${segment(payload)}`;
  return `${signingInput}.${base64urlEncode(await signer.sign(utf8Encode(signingInput)))}`;
}

export interface OneWayOptions {
  holder?: Signer;
  credRef?: string;
  aud?: string;
  iat?: number;
  ttl?: number;
  ctr?: number;
  /** Put the signer's key id into the header; one-way tokens normally carry none. */
  kid?: boolean;
}

/** An `umis-ow+jwt` as the holder's wallet makes it. */
export async function oneWayToken(w: World, o: OneWayOptions = {}): Promise<string> {
  const holder = o.holder ?? w.andriy;
  const iat = o.iat ?? AT - 3;
  const header = { alg: 'ES256', typ: TYP.oneWay, ...(o.kid === true ? { kid: holder.kid } : {}) };
  const payload = {
    cred_ref: o.credRef ?? 'cred-andriy-0001',
    aud: o.aud ?? ISSUER_V,
    iat,
    exp: iat + (o.ttl ?? 30),
    ctr: o.ctr ?? 1,
  };
  return forgeJws(holder, header, payload);
}

export const oneWayQr = async (w: World, o: OneWayOptions = {}): Promise<string> =>
  encodeFrame({ kind: 'oneway', tokens: [await oneWayToken(w, o)] });

/** A holder's unsolicited presentation for a checkpoint (the `full` frame). */
export async function fullQr(
  w: World,
  o: { aud?: string; iat?: number; nonce?: string; disclose?: readonly DisclosableClaim[] } = {},
): Promise<string> {
  const token = await presentCredential({
    credential: w.andriyCredential,
    disclose: o.disclose ?? ['org', 'display'],
    kb: {
      signer: w.andriy,
      aud: o.aud ?? ISSUER_V,
      nonce: o.nonce ?? randomId(16, w.crypto),
      iat: o.iat ?? AT - 3,
    },
    crypto: w.crypto,
  });
  return encodeFrame({ kind: 'full', tokens: [token] });
}

/** The counter-presentation audience, for tests that build mutual frames by hand. */
export { MUTUAL_AUD };

// ---------------------------------------------------------------------------------------------------------------
// assertions
// ---------------------------------------------------------------------------------------------------------------

/** The steps that may report each reason. */
const STEP_OF: Record<ReasonCode, number[]> = {
  OK: [9],
  MALFORMED: [1],
  UNSUPPORTED_FORMAT: [1],
  ISSUER_UNTRUSTED: [2, 7],
  ISSUER_VCT_NOT_ALLOWED: [2],
  ISSUER_KEY_UNKNOWN: [2],
  ISSUER_SUSPENDED: [2],
  SIGNATURE_INVALID: [3],
  HOLDER_BINDING_INVALID: [4],
  NONCE_MISMATCH: [4],
  AUDIENCE_MISMATCH: [4],
  PRESENTATION_EXPIRED: [4],
  PRESENTATION_TOO_LONG_LIVED: [4],
  REPLAY: [4],
  CLOCK_SKEW: [4],
  UNKNOWN_CREDENTIAL_REF: [2],
  CREDENTIAL_EXPIRED: [5],
  CREDENTIAL_NOT_YET_VALID: [5],
  STATUS_REVOKED: [6],
  STATUS_SUSPENDED: [6],
  STATUS_LIST_STALE: [6, 8],
  STATUS_LIST_MISSING: [6, 8],
  STATUS_LIST_INVALID: [6, 8],
  VCT_NOT_ALLOWED: [7],
  CHANNEL_NOT_ALLOWED: [7],
  CLAIM_MISSING: [7],
  DELEGATION_UNDISCLOSED: [7],
  AUTHORITY_MISSING: [8],
  AUTHORITY_EXPIRED: [8],
  AUTHORITY_LIMIT_EXCEEDED: [8],
  AUTHORITY_PERIOD_EXCEEDED: [8],
  DELEGATION_WIDER_THAN_PARENT: [8],
  DELEGATION_DEPTH_EXCEEDED: [8],
  DELEGATION_OUTLIVES_PARENT: [8],
  PARENT_REVOKED: [8],
};

const STEP_NAMES = [
  'parse',
  'issuer_trust',
  'issuer_signature',
  'holder_binding',
  'validity',
  'status',
  'policy',
  'authority',
  'decision',
];

export interface Verdict {
  reason: ReasonCode;
  step: number;
}

/**
 * Checks the shape every result has and returns the verdict: the trace has nine steps in order, a rejection has one
 * reason on exactly one failing step, the steps after it did not run, and the reason is one that this step reports.
 * Only a fault of the verifier's own context (a store that throws, a broken crypto provider) may be reported as
 * malformed by a later step; such a test says so with `fault`.
 */
export function verdictOf(result: VerificationResult, o: { fault?: boolean } = {}): Verdict {
  expect(result.trace).toHaveLength(9);
  result.trace.forEach((entry, index) => {
    expect(entry.step).toBe(index + 1);
    expect(entry.name).toBe(STEP_NAMES[index]);
    expect(Number.isFinite(entry.ms) && entry.ms >= 0).toBe(true);
  });
  expect(Number.isFinite(result.timings.totalMs)).toBe(true);
  expect(result.reasons).toHaveLength(1);

  const reason = result.reasons[0]!;
  if (result.decision === 'accept') {
    expect(reason).toBe('OK');
    expect(result.trace.every((entry) => entry.ok)).toBe(true);
    expect(result.trace[8]!.skipped).toBeUndefined();
    return { reason, step: 9 };
  }
  expect(reason).not.toBe('OK');
  const failing = result.trace.filter((entry) => !entry.ok && entry.skipped !== true);
  expect(failing).toHaveLength(1);
  const step = failing[0]!;
  expect(step.reason).toBe(reason);
  result.trace.slice(0, step.step - 1).forEach((entry) => expect(entry.ok).toBe(true));
  result.trace.slice(step.step).forEach((entry) => {
    expect(entry.skipped).toBe(true);
    expect(entry.ok).toBe(false);
  });
  if (o.fault !== true) expect(STEP_OF[reason], `${reason} reported by step ${step.step}`).toContain(step.step);
  return { reason, step: step.step };
}

/** A decision rejected for exactly this reason, at a step that may report it. */
export function expectReject(result: VerificationResult, reason: ReasonCode): void {
  const verdict = verdictOf(result);
  expect(result.decision).toBe('reject');
  expect(verdict.reason).toBe(reason);
}

export function expectAccept(result: VerificationResult): void {
  expect(verdictOf(result).reason).toBe('OK');
  expect(result.decision).toBe('accept');
}
