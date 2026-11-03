// Writes test-vectors/umis-profile-v1.json from the demo world: `pnpm -F @umis/testkit gen:vectors`. The output is the
// same on every run and on every machine, so the committed file changes only when the profile does.
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  VCT,
  base64urlEncode,
  decodeFrame,
  decodeFrameBytes,
  encodeFrameBytes,
  parseQuery,
  randomId,
} from '@umis/core';
import type { FetchLike, VerificationResult, VerifierContext } from '@umis/core';
import {
  createMemoryReplayStore,
  serializeVerifierContext,
  verifyAtCheckpoint,
  verifyResponseQr,
} from '@umis/verifier';
import type { SerializedVerifierContextV1 } from '@umis/verifier';
import { createVpRequest, umisDcqlQuery, verifyVpResponse } from '@umis/verifier/oid4vp';
import { createFullQr } from '@umis/wallet';
import { respondToVpRequest } from '@umis/wallet/oid4vp';
import { authorityCheck, credentialOf, mutualExchange, oneWayAtDoor } from '../src/hero.js';
import type { Decision } from '../src/hero.js';
import { createDemoWorld } from '../src/world.js';
import type { DemoWorld } from '../src/world.js';

const OUTPUT = fileURLToPath(new URL('../../../test-vectors/umis-profile-v1.json', import.meta.url));

type Entry = Record<string, unknown>;

function expectedOf(result: VerificationResult): { decision: 'accept' | 'reject'; reasons: string[] } {
  return { decision: result.decision, reasons: [...result.reasons] };
}

/** The contexts of the file, each stored once: an entry names one and brings its own `now`. */
class Contexts {
  readonly stored: Record<string, SerializedVerifierContextV1> = {};

  /** Stores the context under `<org>:<policy>`, or checks that it equals the one stored, and returns the name. */
  add(org: string, policy: string, context: VerifierContext): string {
    const name = `${org}:${policy}`;
    const serialized = serializeVerifierContext(context);
    const known = this.stored[name];
    if (known === undefined) {
      this.stored[name] = serialized;
    } else if (JSON.stringify({ ...known, now: 0 }) !== JSON.stringify({ ...serialized, now: 0 })) {
      throw new Error(`the context ${name} is not the same in two entries`);
    }
    return name;
  }
}

/** The members every entry has: the context it is decided in, the time of the decision and how its input is written. */
function where(contexts: Contexts, org: string, policy: string, decision: Decision): Entry {
  return { context: contexts.add(org, policy, decision.context), now: decision.context.now, encoding: 'qr-text' };
}

/** Frame bytes as a link carries them, written as base64url. */
function linkBytes(frame: string): Uint8Array {
  return encodeFrameBytes(decodeFrame(frame));
}

async function signIn(world: DemoWorld, contexts: Contexts): Promise<Entry> {
  const { clock, crypto } = world;
  const context = world.context({ org: 'pidriadnyk-a', policy: 'login_oid4vp' });
  const nonce = randomId(16, crypto);
  const state = randomId(12, crypto);
  const { requestObject, walletUri } = await createVpRequest({
    responseUri: 'https://login.example.test/oid4vp/response',
    nonce,
    state,
    dcql: umisDcqlQuery({ vcts: [VCT.roleAuthority], claims: ['org', 'role'] }),
    clientName: 'Acme Intranet',
  });

  clock.advance(2);
  let posted = '';
  const capture: FetchLike = (_url, init) => {
    posted = init?.body ?? '';
    return Promise.resolve({ status: 200, headers: { get: () => null }, text: () => Promise.resolve('{}') });
  };
  await respondToVpRequest({
    walletUri,
    sdJwtVc: credentialOf(world, 'oleg', 'roleAuthority'),
    disclose: ['org', 'role'],
    signer: world.people.oleg.holder,
    now: clock.now(),
    fetch: capture,
    crypto,
  });
  const body = parseQuery(posted);

  clock.advance(1);
  const now = clock.now();
  const result = await verifyVpResponse({
    body,
    nonce,
    state,
    audience: requestObject.client_id,
    trusted: context.trusted,
    fetchStatusList: (uri) => {
      const held = context.statusLists.get(uri);
      return held === undefined ? Promise.reject(new Error(`no status list ${uri}`)) : Promise.resolve(held.token);
    },
    now,
    policy: context.policy,
    replay: createMemoryReplayStore(),
    crypto,
  });
  return {
    id: 'login-oid4vp',
    channel: 'oid4vp',
    check: 'verifyVpResponse',
    context: contexts.add('pidriadnyk-a', 'login_oid4vp', context),
    now,
    encoding: 'form',
    request: walletUri,
    nonce,
    state,
    audience: requestObject.client_id,
    input: body,
    expected: expectedOf(result),
  };
}

async function presentations(world: DemoWorld, contexts: Contexts): Promise<Entry[]> {
  const out: Entry[] = [];

  // qr_oneway: the door of Коворкінг В decides from its member cache
  const door = await oneWayAtDoor(world);
  out.push({
    id: 'oneway-door',
    channel: 'qr_oneway',
    check: 'verifyAtCheckpoint',
    ...where(contexts, 'kovorking-v', 'door_low', door),
    input: door.frame,
    expected: expectedOf(door.result),
  });

  // qr_full: the same door, a presentation of the credential with two disclosures
  const doorContext = world.context({ org: 'kovorking-v', policy: 'door_low' });
  const frame = await createFullQr({
    sdJwtVc: credentialOf(world, 'oleg', 'coworkingMember'),
    disclose: ['org', 'display'],
    signer: world.people.oleg.holder,
    audience: doorContext.audiences[0],
    now: world.clock.now(),
    crypto: world.crypto,
  });
  const full: Decision = { frame, context: doorContext, result: await verifyAtCheckpoint(frame, doorContext) };
  out.push({
    id: 'full-door',
    channel: 'qr_full',
    check: 'verifyAtCheckpoint',
    ...where(contexts, 'kovorking-v', 'door_low', full),
    input: full.frame,
    expected: expectedOf(full.result),
  });

  // qr_reverse, authority check: 10 t asked of Олег (his limit) and of Іван (his limit is 8 t)
  for (const [id, holder] of [
    ['authority-oleg-10t', 'oleg'],
    ['authority-ivan-10t', 'ivan'],
  ] as const) {
    const asked = await authorityCheck(world, { holder, amount: 10 });
    out.push({
      id,
      channel: 'qr_reverse',
      check: 'verifyResponseQr',
      ...where(contexts, 'postachalnyk-b', 'warehouse_medium', asked),
      request: asked.request,
      pending: asked.pending,
      input: asked.frame,
      expected: expectedOf(asked.result),
    });
  }

  // qr_reverse, mutual exchange: Олег opens it, Марія answers
  const { opening, reply } = await mutualExchange(world);
  out.push({
    id: 'mutual-opening',
    channel: 'qr_reverse',
    check: 'verifyCounterparty',
    ...where(contexts, 'postachalnyk-b', 'mutual_medium', opening),
    input: opening.frame,
    expected: expectedOf(opening.result),
  });
  out.push({
    id: 'mutual-reply',
    channel: 'qr_reverse',
    check: 'verifyResponseQr',
    ...where(contexts, 'pidriadnyk-a', 'mutual_medium', reply),
    request: opening.frame,
    pending: reply.pending,
    input: reply.frame,
    expected: expectedOf(reply.result),
  });

  // ble: the authority check of Олег again, as the bytes of a link; the verifier is handed the decoded frame
  const asked = await authorityCheck(world, { holder: 'oleg', amount: 10 });
  const requestBytes = linkBytes(asked.request);
  const responseBytes = linkBytes(asked.frame);
  const bleContext = world.context({ org: 'postachalnyk-b', policy: 'warehouse_medium' });
  const bleResult = await verifyResponseQr(decodeFrameBytes(responseBytes), asked.pending, bleContext);
  out.push({
    id: 'authority-oleg-10t-ble',
    channel: 'ble',
    check: 'verifyResponseQr',
    context: contexts.add('postachalnyk-b', 'warehouse_medium', bleContext),
    now: bleContext.now,
    encoding: 'frame-bytes-base64url',
    request: base64urlEncode(requestBytes),
    pending: asked.pending,
    input: base64urlEncode(responseBytes),
    expected: expectedOf(bleResult),
  });

  // oid4vp: signing in at a relying party's provider with a credential
  out.push(await signIn(world, contexts));
  return out;
}

/** The test vectors as the text of the file. */
export async function buildVectors(): Promise<string> {
  const world = await createDemoWorld();
  const start = world.clock.now();
  const { orgs, people } = world;
  const contexts = new Contexts();
  const checked = await presentations(world, contexts);

  const document = {
    format: 'umis-test-vectors/v1',
    profile: 'umis-v1',
    description:
      'Credentials, QR frames and offline decisions of the UMIS v1 profile for three invented organisations. Every ' +
      'key is derived from a public seed and protects nothing; the file holds public keys only. To check an entry, ' +
      'take the context it names, set its now to the now of the entry and give it an empty replay store, call the ' +
      'function named in check on input (a frame that answers a request also takes the pending record; an oid4vp ' +
      'entry takes its nonce, state and audience), and compare the decision and the reasons with expected.',
    now: start,
    issuers: Object.values(orgs).map((org) => ({
      slug: org.slug,
      name: org.name,
      issuer: org.issuer,
      jwks: { keys: [org.issuerSigner.publicJwk] },
      statusList: org.statusListUri,
    })),
    credentials: [
      {
        id: 'org-member',
        holder: people.oleg.name,
        issuer: orgs['kovorking-v'].issuer,
        vct: VCT.orgMember,
        sdJwtVc: credentialOf(world, 'oleg', 'coworkingMember'),
      },
      {
        id: 'role-authority',
        holder: people.oleg.name,
        issuer: orgs['pidriadnyk-a'].issuer,
        vct: VCT.roleAuthority,
        sdJwtVc: credentialOf(world, 'oleg', 'roleAuthority'),
      },
      {
        id: 'role-authority-delegated',
        holder: people.ivan.name,
        issuer: orgs['pidriadnyk-a'].issuer,
        vct: VCT.roleAuthority,
        sdJwtVc: credentialOf(world, 'ivan', 'delegated'),
      },
    ],
    contexts: contexts.stored,
    presentations: checked,
  };
  return `${JSON.stringify(document, null, 2)}\n`;
}

async function main(): Promise<void> {
  const out = process.argv[2] === '--out' && process.argv[3] !== undefined ? process.argv[3] : OUTPUT;
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, await buildVectors(), 'utf8');
  console.log(`wrote ${out}`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
