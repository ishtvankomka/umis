import { existsSync, readFileSync } from 'node:fs';
import {
  TYP,
  UmisError,
  base64urlDecode,
  base64urlEncode,
  decodeJwsUnverified,
  generateSigner,
  signJws,
  utf8Decode,
  utf8Encode,
  type CheckpointPolicyV1,
  type PeriodWindow,
} from '@umis/core';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_POLICIES,
  checkpointPolicyJsonSchema,
  createMemoryLedger,
  isChannelAllowed,
  signPolicy,
  validatePolicy,
  verifyPolicy,
  type PolicyEnvelopeV1,
} from '../src/index.js';

const { door_low, warehouse_medium, mutual_medium, login_oid4vp } = DEFAULT_POLICIES;

/** A copy of `base` with some members replaced; `undefined` removes a member. */
function changed(base: CheckpointPolicyV1, changes: Record<string, unknown>): unknown {
  const copy: Record<string, unknown> = { ...structuredClone(base) };
  for (const [name, value] of Object.entries(changes)) {
    if (value === undefined) delete copy[name];
    else copy[name] = value;
  }
  return copy;
}

function failure(doc: unknown) {
  const result = validatePolicy(doc);
  if (result.ok) throw new Error('the policy was accepted');
  return result;
}

async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await run();
  } catch (error) {
    return error instanceof UmisError ? error.code : `not a UmisError: ${String(error)}`;
  }
  return undefined;
}

describe('checkpoint policy validation', () => {
  it('accepts the presets and returns a copy', () => {
    for (const [name, policy] of Object.entries(DEFAULT_POLICIES)) {
      const result = validatePolicy(policy);
      expect(result, name).toEqual({ ok: true, policy });
      if (result.ok) expect(result.policy).not.toBe(policy);
    }
    expect(Object.isFrozen(door_low)).toBe(true);
    expect(Object.isFrozen(door_low.channels)).toBe(true);
  });

  it('rejects documents that are malformed or contradict themselves as POLICY_INVALID', () => {
    const fixedAmount = (value?: number) => ({
      authority: {
        action: 'receive_materials',
        resource: 'rebar',
        unit: 't',
        amountSource: 'fixed',
        fixedAmount: value,
      },
    });
    const invalid: Array<[string, unknown]> = [
      ['unknown member', changed(warehouse_medium, { surprise: true })],
      ['unknown member of a nested object', changed(warehouse_medium, { relay: { openSeconds: 3, wide: 1 } })],
      ['not an object', 'umis.policy.v1'],
      ['wrong schema id', changed(warehouse_medium, { schema: 'umis.policy.v2' })],
      ['unknown channel', changed(warehouse_medium, { channels: ['nfc'] })],
      ['no channel', changed(warehouse_medium, { channels: [] })],
      [
        'refresh interval above S',
        changed(warehouse_medium, { maxStatusAgeSeconds: 3_600, statusRefreshSeconds: 7_200 }),
      ],
      ['no accepted credential type', changed(warehouse_medium, { accepted: [] })],
      ['authority check without the claim', changed(warehouse_medium, { requestedClaims: ['org', 'role'] })],
      ['fixed amount without a value', changed(warehouse_medium, fixedAmount())],
      ['fixed amount of zero', changed(warehouse_medium, fixedAmount(0))],
      ['delegation among the requested claims', changed(warehouse_medium, { requestedClaims: ['org', 'delegation'] })],
      ['fractional seconds', changed(door_low, { relay: { openSeconds: 0.5 } })],
    ];
    for (const [label, doc] of invalid) {
      const result = failure(doc);
      expect(result.code, label).toBe('POLICY_INVALID');
      expect(result.errors.length, label).toBeGreaterThan(0);
    }
    expect(failure(changed(warehouse_medium, { surprise: true })).errors.join()).toContain('surprise');
    expect(validatePolicy(changed(warehouse_medium, fixedAmount(2.5))).ok).toBe(true);
  });

  it('applies the risk-class caps as POLICY_CLASS_CAP_EXCEEDED', () => {
    const exceeded: Array<[string, unknown, string]> = [
      [
        'one-way QR in the medium class',
        changed(warehouse_medium, { channels: ['qr_reverse', 'qr_oneway'] }),
        'qr_oneway',
      ],
      [
        'channel outside the highest class',
        changed(login_oid4vp, { riskClass: 'highest', channels: ['oid4vp', 'ble'] }),
        'ble',
      ],
      ['S above the medium cap', changed(warehouse_medium, { maxStatusAgeSeconds: 90_000 }), 'maxStatusAgeSeconds'],
      ['S above the low cap', changed(door_low, { maxStatusAgeSeconds: 259_201 }), 'maxStatusAgeSeconds'],
      [
        'S above the high cap',
        changed(warehouse_medium, { riskClass: 'high', maxStatusAgeSeconds: 7_200 }),
        'maxStatusAgeSeconds',
      ],
      ['no biometric in the medium class', changed(warehouse_medium, { requireBiometric: false }), 'requireBiometric'],
      ['one-way token above 30 s', changed(door_low, { oneWayTokenMaxAgeSeconds: 31 }), 'oneWayTokenMaxAgeSeconds'],
    ];
    for (const [label, doc, member] of exceeded) {
      const result = failure(doc);
      expect(result.code, label).toBe('POLICY_CLASS_CAP_EXCEEDED');
      expect(result.errors.join(), label).toContain(member);
    }

    // The caps are inclusive, and the low class may ask for a biometric check.
    expect(validatePolicy(changed(warehouse_medium, { maxStatusAgeSeconds: 86_400 })).ok).toBe(true);
    expect(validatePolicy(changed(door_low, { maxStatusAgeSeconds: 259_200, oneWayTokenMaxAgeSeconds: 30 })).ok).toBe(
      true,
    );
    expect(validatePolicy(changed(door_low, { requireBiometric: true })).ok).toBe(true);
    expect(validatePolicy(changed(warehouse_medium, { oneWayTokenMaxAgeSeconds: 0 })).ok).toBe(true);
    expect(validatePolicy(changed(login_oid4vp, { riskClass: 'highest', maxStatusAgeSeconds: 600 })).ok).toBe(true);
  });

  it('allows a channel only when the policy lists it and its class permits it', () => {
    expect(isChannelAllowed(door_low, 'qr_oneway')).toBe(true);
    expect(isChannelAllowed(door_low, 'qr_full')).toBe(true);
    expect(isChannelAllowed(door_low, 'ble')).toBe(false);
    expect(isChannelAllowed(warehouse_medium, 'qr_reverse')).toBe(true);
    expect(isChannelAllowed(warehouse_medium, 'qr_oneway')).toBe(false);
    expect(isChannelAllowed(mutual_medium, 'oid4vp')).toBe(false);
    expect(isChannelAllowed(login_oid4vp, 'oid4vp')).toBe(true);

    // A policy that lists a channel its class does not permit, or has no known class, allows nothing there.
    const oneWayInMedium = { ...warehouse_medium, channels: ['qr_oneway' as const] };
    expect(isChannelAllowed(oneWayInMedium, 'qr_oneway')).toBe(false);
    expect(isChannelAllowed({ ...door_low, riskClass: 'constructor' as never }, 'qr_oneway')).toBe(false);
  });
});

describe('checkpoint policy JSON Schema', () => {
  it('is committed, exported and equal to the schema built from the code', () => {
    const file = new URL('../schema/checkpoint-policy.v1.schema.json', import.meta.url);
    expect(JSON.parse(readFileSync(file, 'utf8')), 'run "pnpm schema:emit" in packages/policy').toEqual(
      checkpointPolicyJsonSchema,
    );
    expect(checkpointPolicyJsonSchema).toMatchObject({
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      additionalProperties: false,
    });

    const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      exports: Record<string, unknown>;
      files: string[];
    };
    expect(manifest.exports['./schema/checkpoint-policy.v1.schema.json']).toBe(
      './schema/checkpoint-policy.v1.schema.json',
    );
    expect(manifest.files).toContain('schema');
    expect(existsSync(file)).toBe(true);
  });
});

describe('policy envelope', () => {
  const envelope: PolicyEnvelopeV1 = {
    iss: 'org-b',
    sub: 'warehouse-gate',
    ver: 3,
    iat: 1_793_664_000,
    policy: warehouse_medium,
  };

  it('signs, verifies and rejects tampering, a wrong type, a wrong key and an invalid policy', async () => {
    const owner = await generateSigner();
    const stranger = await generateSigner();
    const jws = await signPolicy(envelope, owner);

    expect(decodeJwsUnverified(jws).header).toMatchObject({ alg: 'ES256', typ: 'umis-policy+jwt', kid: owner.kid });
    await expect(verifyPolicy(jws, owner.publicJwk)).resolves.toEqual(envelope);
    await expect(verifyPolicy(jws, [stranger.publicJwk, owner.publicJwk])).resolves.toEqual(envelope);

    // A changed payload under the original signature.
    const [header, payload, signature] = jws.split('.') as [string, string, string];
    const edited = { ...(JSON.parse(utf8Decode(base64urlDecode(payload))) as object), ver: 4 };
    const tampered = `${header}.${base64urlEncode(utf8Encode(JSON.stringify(edited)))}.${signature}`;
    expect(await codeOf(() => verifyPolicy(tampered, owner.publicJwk))).toBe('SIGNATURE_INVALID');

    // Another key, and another token type signed by the right key.
    expect(await codeOf(() => verifyPolicy(jws, stranger.publicJwk))).toBe('SIGNATURE_INVALID');
    const registryToken = await signJws({ header: { typ: TYP.registry }, payload: envelope, signer: owner });
    expect(await codeOf(() => verifyPolicy(registryToken, owner.publicJwk))).toBe('UNSUPPORTED_FORMAT');

    // The policy is validated before signing and again after verifying.
    const overCap = { ...envelope, policy: { ...warehouse_medium, requireBiometric: false } };
    expect(await codeOf(() => signPolicy(overCap, owner))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => signPolicy({ ...envelope, ver: -1 }, owner))).toBe('INVALID_ARGUMENT');
    const forced = await signJws({ header: { typ: TYP.policy }, payload: overCap, signer: owner });
    expect(await codeOf(() => verifyPolicy(forced, owner.publicJwk))).toBe('MALFORMED');
    const extra = await signJws({ header: { typ: TYP.policy }, payload: { ...envelope, exp: 1 }, signer: owner });
    expect(await codeOf(() => verifyPolicy(extra, owner.publicJwk))).toBe('MALFORMED');
  });
});

describe('authority ledger', () => {
  it('adds up a budget per key and window: 6 t and 4 t fit 10 t, one more does not', async () => {
    const midnight = Date.UTC(2026, 10, 3) / 1000;
    // The shifts of one day: 00:00-08:00, 08:00-16:00, 16:00-24:00.
    const shift = (n: number): PeriodWindow => ({ start: midnight + n * 28_800, end: midnight + (n + 1) * 28_800 });
    const key = 'https://a.example/issuer|credential-1|receive_materials|rebar|t';
    const limit = 10;
    const ledger = createMemoryLedger();
    const fits = async (amount: number, window = shift(1)): Promise<boolean> =>
      (await ledger.used(key, window)) + amount <= limit;

    expect(await ledger.used(key, shift(1))).toBe(0);
    expect(await fits(6)).toBe(true);
    await ledger.add(key, shift(1), 6);
    expect(await fits(4)).toBe(true);
    await ledger.add(key, shift(1), 4);
    expect(await ledger.used(key, shift(1))).toBe(10);
    expect(await fits(1)).toBe(false);

    // The next shift and another budget start empty.
    expect(await fits(10, shift(2))).toBe(true);
    expect(await ledger.used(key, shift(0))).toBe(0);
    expect(await ledger.used('https://a.example/issuer|credential-2|receive_materials|rebar|t', shift(1))).toBe(0);

    // Nothing that would free budget is accepted.
    expect(await codeOf(() => ledger.add(key, shift(1), -1))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => ledger.add(key, shift(1), Number.NaN))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => ledger.add('', shift(1), 1))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => ledger.used(key, { start: 2, end: 1 }))).toBe('INVALID_ARGUMENT');
    expect(await ledger.used(key, shift(1))).toBe(10);
  });
});
