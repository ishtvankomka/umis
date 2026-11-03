import { UmisError, utf8Encode } from '@umis/core';
import type { ParsedRequest, PendingRequest, ReasonCode, VerificationResult, VerifierContext } from '@umis/core';
import { keyFromSeed } from '@umis/core/noble';
import { createGateway, shellyRpcRelay } from '@umis/gateway';
import { startShellyEmulator } from '@umis/gateway/node';
import { createMemoryReplayStore, verifyAtCheckpoint, verifyCounterparty, verifyResponseQr } from '@umis/verifier';
import { createFullQr, createOneWayQr } from '@umis/wallet';
import { DECISION_DELAY_S, authorityFrames, credentialOf, decideLogin, mutualFrames, postedLogin } from '../hero.js';
import type { LoginRequest, MutualFrames } from '../hero.js';
import type { DemoWorld } from '../world.js';

/** The scenarios of the benchmark, in the order they are run and reported. */
export const BENCH_SCENARIOS = [
  'oneway-low',
  'full-qr-low',
  's1-accept',
  's1-reject',
  'mutual',
  'oid4vp',
  'gateway',
] as const;

export type BenchScenario = (typeof BENCH_SCENARIOS)[number];

/** What one timed call came to: the result of every `verify…` call in it, in order, and a fault outside the decision. */
export interface Decided {
  results: VerificationResult[];
  /** A short label when something besides the decision did not come out as it should: the relay did not open. */
  fault?: string;
}

/** A text that is shown to a verifier. The sizes of the `checked` ones make the frame size of a scenario. */
export interface FrameKind {
  kind: string;
  checked: boolean;
}

/** One repeat of a scenario, made and ready to be timed. */
export interface PreparedRepeat {
  /** The number of characters of every text of presentation `i`, in the order of the `frames` of the scenario. */
  chars(i: number): readonly number[];
  /** The timed part: decides on presentation `i`. The replay store it decides with is new and belongs to this repeat. */
  verify(i: number): Promise<Decided>;
  /** Frees what was made for the repeat. */
  release(): Promise<void>;
}

export interface Scenario {
  readonly name: BenchScenario;
  /** The decision every presentation of the scenario comes to: an accept, or a reject for this reason. */
  readonly expected: 'accept' | ReasonCode;
  readonly frames: readonly FrameKind[];
  /** Makes `n` distinct presentations. None of it is timed, and none of it has been verified in the replay store used later. */
  prepare(n: number): Promise<PreparedRepeat>;
}

/** What a presentation came to: a reject for the first call that refused, else an accept (or the fault that spoiled it). */
export function outcomeOf(decided: Decided): { decision: 'accept' | 'reject'; reason: string } {
  const [first] = decided.results;
  if (first === undefined) throw new UmisError('PROTOCOL', 'a presentation was timed without a decision');
  const refused = decided.results.find((result) => result.decision === 'reject');
  if (refused !== undefined) return { decision: 'reject', reason: refused.reasons[0] ?? 'MALFORMED' };
  return { decision: 'accept', reason: decided.fault ?? first.reasons[0] ?? 'OK' };
}

/** True when `outcome` is the decision a scenario expects: an accept with no fault, or a reject for exactly that reason. */
export function isExpected(outcome: { decision: string; reason: string }, expected: 'accept' | ReasonCode): boolean {
  return expected === 'accept'
    ? outcome.decision === 'accept' && outcome.reason === 'OK'
    : outcome.decision === 'reject' && outcome.reason === expected;
}

const door = { org: 'kovorking-v', policy: 'door_low' } as const;
const nothing = (): Promise<void> => Promise.resolve();
const one = (result: VerificationResult): Decided => ({ results: [result] });

/**
 * `n` one-way QR codes of Олег for the door, all made at `at` and all different: the counter of each token starts at
 * `firstCounter` and goes up by one.
 */
export async function oneWayFrames(world: DemoWorld, at: number, n: number, firstCounter: number): Promise<string[]> {
  const sdJwtVc = credentialOf(world, 'oleg', 'coworkingMember');
  const { holder } = world.people.oleg;
  const frames: string[] = [];
  for (let i = 0; i < n; i++) {
    frames.push(await createOneWayQr({ sdJwtVc, signer: holder, now: at, ctr: firstCounter + i }));
  }
  return frames;
}

/** The door of Коворкінг В reads a one-way QR code: the member cache decides, and the same codes feed the gateway. */
function oneWay(world: DemoWorld, start: number): Scenario {
  return {
    name: 'oneway-low',
    expected: 'accept',
    frames: [{ kind: 'qr_oneway', checked: true }],
    async prepare(n) {
      const frames = await oneWayFrames(world, start, n, 1);
      world.clock.set(start + DECISION_DELAY_S.door);
      const context = world.context(door);
      return {
        chars: (i) => [frames[i]!.length],
        verify: async (i) => one(await verifyAtCheckpoint(frames[i]!, context)),
        release: nothing,
      };
    },
  };
}

/** Олег offers his membership at the door without being asked: a full presentation with a key-binding JWT. */
function fullQr(world: DemoWorld, start: number): Scenario {
  return {
    name: 'full-qr-low',
    expected: 'accept',
    frames: [{ kind: 'qr_full', checked: true }],
    async prepare(n) {
      const sdJwtVc = credentialOf(world, 'oleg', 'coworkingMember');
      const { holder } = world.people.oleg;
      const frames: string[] = [];
      for (let i = 0; i < n; i++) {
        frames.push(
          await createFullQr({
            sdJwtVc,
            disclose: ['org', 'display'],
            signer: holder,
            now: start,
            crypto: world.crypto,
          }),
        );
      }
      world.clock.set(start + DECISION_DELAY_S.door);
      const context = world.context(door);
      return {
        chars: (i) => [frames[i]!.length],
        verify: async (i) => one(await verifyAtCheckpoint(frames[i]!, context)),
        release: nothing,
      };
    },
  };
}

/**
 * The warehouse of Постачальник Б asks for 10 t of rebar and decides on the answer. Олег holds 10 t and is accepted; Іван
 * holds 8 t, delegated from Олег, and is stopped with AUTHORITY_LIMIT_EXCEEDED. Each presentation answers a request of
 * its own, and no ledger is kept, so that one decision does not change the next.
 */
function authority(name: 's1-accept' | 's1-reject', world: DemoWorld, start: number): Scenario {
  const holder = name === 's1-accept' ? 'oleg' : 'ivan';
  return {
    name,
    expected: name === 's1-accept' ? 'accept' : 'AUTHORITY_LIMIT_EXCEEDED',
    frames: [
      { kind: 'qr_request', checked: false },
      { kind: 'qr_response', checked: true },
    ],
    async prepare(n) {
      const requestChars: number[] = [];
      const frames: string[] = [];
      const pending: PendingRequest[] = [];
      let context: VerifierContext | undefined;
      for (let i = 0; i < n; i++) {
        world.clock.set(start);
        const asked = await authorityFrames(world, { holder, amount: 10 });
        requestChars.push(asked.request.length);
        frames.push(asked.frame);
        pending.push(asked.pending);
        context = asked.context;
      }
      const decideWith = context!; // the contexts of all the requests are the same: one time, one registry
      return {
        chars: (i) => [requestChars[i]!, frames[i]!.length],
        verify: async (i) => one(await verifyResponseQr(frames[i]!, pending[i]!, decideWith)),
        release: nothing,
      };
    },
  };
}

/**
 * A mutual exchange: Марія's side decides on the credential Олег shows with his opening, then Олег's side decides on the
 * credential Марія answers with. One presentation is the exchange, and its time is that of both decisions.
 */
function mutual(world: DemoWorld, start: number): Scenario {
  return {
    name: 'mutual',
    expected: 'accept',
    frames: [
      { kind: 'qr_mutual_init', checked: true },
      { kind: 'qr_mutual_reply', checked: true },
    ],
    async prepare(n) {
      const requests: ParsedRequest[] = [];
      const replies: string[] = [];
      const pending: PendingRequest[] = [];
      const chars: number[][] = [];
      let last: MutualFrames | undefined;
      for (let i = 0; i < n; i++) {
        world.clock.set(start);
        const made = await mutualFrames(world);
        requests.push(made.opening.request);
        replies.push(made.reply.frame);
        pending.push(made.reply.pending);
        chars.push([made.opening.frame.length, made.reply.frame.length]);
        last = made;
      }
      const { opening, reply } = last!;
      return {
        chars: (i) => chars[i]!,
        verify: async (i) => {
          const first = await verifyCounterparty(requests[i]!, opening.context);
          const second = await verifyResponseQr(replies[i]!, pending[i]!, reply.context);
          return { results: [first, second] };
        },
        release: nothing,
      };
    },
  };
}

/**
 * Олег signs in to the intranet of Підрядник А over OpenID4VP: the relying party's provider decides on the form the
 * wallet posted, with the status lists fetched from memory. The wallet's part and the HTTP round trip are not timed.
 */
function login(world: DemoWorld, start: number): Scenario {
  return {
    name: 'oid4vp',
    expected: 'accept',
    frames: [
      { kind: 'qr_login_request', checked: true },
      { kind: 'post_body', checked: false },
    ],
    async prepare(n) {
      const logins: LoginRequest[] = [];
      const bodies: Array<Record<string, string>> = [];
      const chars: number[][] = [];
      for (let i = 0; i < n; i++) {
        world.clock.set(start);
        const posted = await postedLogin(world);
        logins.push(posted.login);
        bodies.push(posted.body);
        chars.push([posted.login.walletUri.length, posted.text.length]);
      }
      const now = world.clock.now();
      const replay = createMemoryReplayStore();
      return {
        chars: (i) => chars[i]!,
        verify: async (i) => one(await decideLogin(logins[i]!, bodies[i]!, { now, replay, crypto: world.crypto })),
        release: nothing,
      };
    },
  };
}

/**
 * The gateway of the door decides on a one-way QR code of Олег and, for an accept, posts a signed relay command to an
 * emulator of the relay over HTTP on the loopback interface. A new emulator serves each repeat, and one request to it
 * before the timing opens the connection that the timed commands use.
 */
async function gateway(world: DemoWorld, start: number): Promise<Scenario> {
  const station = await world.crypto.importSigner(keyFromSeed(utf8Encode('umis-bench:station')), {
    kid: 'bench-station',
  });
  return {
    name: 'gateway',
    expected: 'accept',
    frames: [{ kind: 'qr_oneway', checked: true }],
    async prepare(n) {
      const frames = await oneWayFrames(world, start, n, 1);
      world.clock.set(start + DECISION_DELAY_S.door);
      const context = world.context(door);
      const now = (): number => world.clock.now();
      const emulator = await startShellyEmulator({ port: 0, trust: [station.publicJwk], now });
      try {
        const rpc = `${emulator.url}/rpc`;
        const probe = await fetch(rpc, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id: 1, method: 'Shelly.GetDeviceInfo' }),
        });
        await probe.arrayBuffer();
        if (!probe.ok) throw new UmisError('NETWORK', `the relay emulator answered ${probe.status}`);

        const relay = shellyRpcRelay({ url: rpc, signer: station, relayAud: emulator.url, iss: 'umis-bench' });
        const checkpoint = createGateway({ context: () => context, relay, now });
        return {
          chars: (i) => [frames[i]!.length],
          verify: async (i) => {
            const { result, relay: opened } = await checkpoint.handle(frames[i]!);
            if (result.decision !== 'accept' || opened?.ok === true) return one(result);
            return {
              results: [result],
              fault: opened === undefined ? 'relay_not_asked' : `relay_http_${opened.status}`,
            };
          },
          release: () => emulator.close(),
        };
      } catch (error) {
        await emulator.close();
        throw error;
      }
    },
  };
}

/** Opens `name` on `world`: the time of the world at this moment is the instant all the presentations are made at. */
export async function openScenario(name: BenchScenario, world: DemoWorld): Promise<Scenario> {
  const start = world.clock.now();
  switch (name) {
    case 'oneway-low':
      return oneWay(world, start);
    case 'full-qr-low':
      return fullQr(world, start);
    case 's1-accept':
    case 's1-reject':
      return authority(name, world, start);
    case 'mutual':
      return mutual(world, start);
    case 'oid4vp':
      return login(world, start);
    case 'gateway':
      return gateway(world, start);
    default:
      throw new UmisError('INVALID_ARGUMENT', `unknown scenario "${String(name).slice(0, 64)}"`);
  }
}
