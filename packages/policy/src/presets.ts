import { VCT, type CheckpointPolicyV1 } from '@umis/core';

type PresetName = 'door_low' | 'warehouse_medium' | 'mutual_medium' | 'login_oid4vp';

const presets = {
  // One-way and full QR at a door: the lowest risk class, membership of the verifier's own organisation.
  door_low: {
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
  },
  // A warehouse that receives materials: a power of authority from an issuer in the registry, checked against the
  // amount in the request.
  warehouse_medium: {
    schema: 'umis.policy.v1',
    riskClass: 'medium',
    channels: ['qr_reverse', 'ble'],
    maxStatusAgeSeconds: 86_400,
    statusRefreshSeconds: 3_600,
    oneWayTokenMaxAgeSeconds: 30,
    requireBiometric: true,
    accepted: [{ vct: VCT.roleAuthority, issuers: 'registry' }],
    requestedClaims: ['org', 'role', 'authority'],
    authority: { action: 'receive_materials', resource: 'rebar', unit: 't', amountSource: 'request' },
  },
  // Two parties show each other who they are and which role they hold.
  mutual_medium: {
    schema: 'umis.policy.v1',
    riskClass: 'medium',
    channels: ['qr_reverse', 'ble'],
    maxStatusAgeSeconds: 86_400,
    statusRefreshSeconds: 3_600,
    oneWayTokenMaxAgeSeconds: 30,
    requireBiometric: true,
    accepted: [
      { vct: VCT.orgMember, issuers: 'registry' },
      { vct: VCT.roleAuthority, issuers: 'registry' },
    ],
    requestedClaims: ['org', 'role', 'display'],
  },
  // Signing in to a relying party over OpenID4VP, where the status list is refreshed online.
  login_oid4vp: {
    schema: 'umis.policy.v1',
    riskClass: 'medium',
    channels: ['oid4vp'],
    maxStatusAgeSeconds: 600,
    statusRefreshSeconds: 600,
    oneWayTokenMaxAgeSeconds: 30,
    requireBiometric: true,
    accepted: [
      { vct: VCT.orgMember, issuers: 'registry' },
      { vct: VCT.roleAuthority, issuers: 'registry' },
    ],
    requestedClaims: ['org', 'role'],
  },
} satisfies Record<PresetName, CheckpointPolicyV1>;

function freeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const member of Object.values(value)) freeze(member);
    Object.freeze(value);
  }
  return value;
}

/** Ready-made policies for the common checkpoints. They are frozen; copy one before changing it. */
export const DEFAULT_POLICIES: Readonly<Record<PresetName, CheckpointPolicyV1>> = freeze(presets);
