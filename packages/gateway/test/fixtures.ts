import { VCT, generateSigner, issueCredential } from '@umis/core';
import type { CheckpointPolicyV1, Signer, TrustedIssuerEntryV1, VerifierContext } from '@umis/core';
import { buildStatusListToken } from '@umis/status-list';
import { createMemoryReplayStore, memberCacheEntryFromCredential } from '@umis/verifier';
import { createOneWayQr } from '@umis/wallet';

/** 2026-11-04T00:00:00Z. */
export const T0 = 1_793_750_400;
export const ISSUER = 'https://issuer.example/coworking-v';
export const LIST = 'https://issuer.example/status/coworking-v/1';
export const STATION_ISS = 'umis-station-7';

/** The door of a coworking space: a low-class checkpoint for its own residents, who are in the member cache. */
export const DOOR_POLICY: CheckpointPolicyV1 = {
  schema: 'umis.policy.v1',
  riskClass: 'low',
  channels: ['qr_oneway', 'qr_full'],
  maxStatusAgeSeconds: 259_200,
  statusRefreshSeconds: 600,
  oneWayTokenMaxAgeSeconds: 30,
  requireBiometric: false,
  accepted: [{ vct: VCT.orgMember, issuers: 'self' }],
  requestedClaims: ['org', 'display'],
  relay: { openSeconds: 3 },
};

export interface Door {
  /** The signer of the station that sends commands to the relay. */
  station: Signer;
  resident: Signer;
  credential: string;
  /** A verifier context for the door; each call gives a fresh replay store unless one is passed. */
  context(over?: Partial<VerifierContext>): VerifierContext;
  /** The text of a one-way QR code of the resident, made at `now`. */
  oneWayQr(now: number, ctr?: number): Promise<string>;
}

export async function buildDoor(): Promise<Door> {
  const [issuer, resident, station] = await Promise.all([generateSigner(), generateSigner(), generateSigner()]);
  const credential = await issueCredential({
    signer: issuer,
    payload: {
      iss: ISSUER,
      sub: 'p_resident',
      jti: 'cred-resident-0001',
      iat: T0,
      exp: T0 + 90 * 86_400,
      vct: VCT.orgMember,
      cnf: { jwk: resident.publicJwk },
      status: { status_list: { idx: 1, uri: LIST } },
    },
    claims: {
      org: { id: 'coworking-v', name: 'Коворкінг В' },
      role: { code: 'resident', name: 'Резидент' },
      display: { name: 'Андрій' },
    },
  });
  const entry: TrustedIssuerEntryV1 = {
    issuer: ISSUER,
    name: 'Коворкінг В',
    jwks: { keys: [issuer.publicJwk] },
    vcts: [VCT.orgMember],
    statusLists: [LIST],
    status: 'active',
  };
  const list = await buildStatusListToken({
    signer: issuer,
    uri: LIST,
    bits: 2,
    values: new Uint8Array(1_024),
    iat: T0,
  });
  const member = await memberCacheEntryFromCredential(credential);
  return {
    station,
    resident,
    credential,
    context: (over = {}) => ({
      now: T0 + 3_600,
      audiences: [ISSUER],
      policy: structuredClone(DOOR_POLICY),
      trusted: [entry],
      statusLists: new Map([[LIST, { token: list, fetchedAt: T0 }]]),
      memberCache: new Map([[member.credRef, member]]),
      replay: createMemoryReplayStore(),
      selfIssuer: ISSUER,
      pointId: 'door-1',
      policyVersion: 1,
      ...over,
    }),
    oneWayQr: (now, ctr = 1) => createOneWayQr({ sdJwtVc: credential, signer: resident, now, ctr }),
  };
}
