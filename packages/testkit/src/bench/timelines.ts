import { DEFAULT_REFRESH_S, UmisError, decodeCredential } from '@umis/core';
import type { ReasonCode } from '@umis/core';
import { DEFAULT_POLICIES } from '@umis/policy';
import { DECISION_DELAY_S, authorityCheck, credentialOf, oneWayAtDoor } from '../hero.js';
import type { DemoWorld } from '../world.js';

/** Seconds between two presentations on a timeline: one every five minutes. */
export const PROBE_PERIOD_S = 300;
const HOUR_S = 3_600;

/** Where the timelines look: the policy of each class and how long the simulated checkpoint stays without a connection. */
const AUTONOMY = {
  low: { policy: 'door_low', horizonS: 80 * HOUR_S, delayS: DECISION_DELAY_S.door },
  medium: { policy: 'warehouse_medium', horizonS: 30 * HOUR_S, delayS: DECISION_DELAY_S.authority },
} as const;

export type AutonomyClass = keyof typeof AUTONOMY;

/** One presentation `t` seconds after the last sync, when the status list is `ageS` seconds old. */
export interface AutonomyRow {
  t: number;
  ageS: number;
  decision: 'accept' | 'reject';
  reason: ReasonCode;
}

export interface AutonomyReport {
  riskClass: AutonomyClass;
  policy: 'door_low' | 'warehouse_medium';
  /** S: the oldest status list, in seconds, that a checkpoint of this class decides on. */
  maxStatusAgeS: number;
  /** How long after the last sync the presentations go on, and how far apart they are. */
  horizonS: number;
  periodS: number;
  probes: number;
  /** The last presentation that was accepted and the first one refused because the list was too old. */
  lastAcceptS: number | null;
  firstStaleS: number | null;
  /**
   * True when every presentation up to S seconds after the sync is accepted, every later one is refused with
   * STATUS_LIST_STALE, and the switch comes exactly at S + 1 seconds.
   */
  exact: boolean;
}

/** The moments to try: every `PROBE_PERIOD_S` up to the horizon, and the extra ones asked for, in order. */
function probeTimes(horizonS: number, extra: readonly number[]): number[] {
  const times = new Set<number>(extra);
  for (let t = PROBE_PERIOD_S; t <= horizonS; t += PROBE_PERIOD_S) times.add(t);
  return [...times].sort((a, b) => a - b);
}

function reasonOf(reasons: readonly ReasonCode[]): ReasonCode {
  return reasons[0] ?? 'MALFORMED';
}

/** The newest status list a checkpoint holds, as a time: the last sync. */
function lastSync(world: DemoWorld): number {
  let newest = Number.NEGATIVE_INFINITY;
  for (const held of world.statusLists().values()) newest = Math.max(newest, held.fetchedAt);
  if (!Number.isFinite(newest)) throw new UmisError('PROTOCOL', 'the world holds no status list');
  return newest;
}

/**
 * A checkpoint that synced its status lists once and has no connection since. One presentation every five minutes is
 * decided on the simulated clock of `world`, from the first one after the sync to `horizonS`: the door of Коворкінг В for
 * the low class (a one-way QR code of Олег, 80 hours), the warehouse of Постачальник Б for the medium class (Олег asks for
 * 10 t, 30 hours). The extra moments S and S + 1 s are tried too, so that the switch can be seen to the second. The world
 * should be a new one: the sync is the moment its lists were signed. The clock is the only source of time.
 */
export async function autonomyTimeline(
  world: DemoWorld,
  riskClass: AutonomyClass,
): Promise<{ rows: AutonomyRow[]; report: AutonomyReport }> {
  const { policy: policyName, horizonS, delayS } = AUTONOMY[riskClass];
  const s = DEFAULT_POLICIES[policyName].maxStatusAgeSeconds;
  const sync = lastSync(world);
  const rows: AutonomyRow[] = [];

  for (const t of probeTimes(horizonS, [s, s + 1])) {
    world.clock.set(sync + t - delayS);
    const { result } =
      riskClass === 'low' ? await oneWayAtDoor(world) : await authorityCheck(world, { holder: 'oleg', amount: 10 });
    if (result.at !== sync + t) {
      throw new UmisError(
        'PROTOCOL',
        `a presentation planned ${t} s after the sync was decided at ${result.at - sync} s`,
      );
    }
    rows.push({ t, ageS: result.at - sync, decision: result.decision, reason: reasonOf(result.reasons) });
  }

  let lastAcceptS: number | null = null;
  let firstStaleS: number | null = null;
  for (const row of rows) {
    if (row.decision === 'accept') lastAcceptS = row.t;
    else if (row.reason === 'STATUS_LIST_STALE' && firstStaleS === null) firstStaleS = row.t;
  }
  const asPolicySays = rows.every((row) =>
    row.t <= s
      ? row.decision === 'accept' && row.reason === 'OK'
      : row.decision === 'reject' && row.reason === 'STATUS_LIST_STALE',
  );
  const report: AutonomyReport = {
    riskClass,
    policy: policyName,
    maxStatusAgeS: s,
    horizonS,
    periodS: PROBE_PERIOD_S,
    probes: rows.length,
    lastAcceptS,
    firstStaleS,
    exact: asPolicySays && lastAcceptS === s && firstStaleS === s + 1,
  };
  return { rows, report };
}

/** What an online and an offline verifier decide `t` seconds after a credential was revoked. */
export interface RevocationRow {
  t: number;
  online: ReasonCode;
  offline: ReasonCode;
}

export interface RevocationReport {
  /** Δ: how often the online verifier fetches the status lists. */
  refreshS: number;
  /** S: the oldest status list, in seconds, that the verifier decides on. */
  maxStatusAgeS: number;
  /** T: the lifetime of the credential that was revoked. */
  lifetimeS: number;
  /** Seconds after the last sync at which the issuer revoked the credential. */
  revokedAtS: number;
  /** Seconds from the revocation to the first refusal by the online and by the offline verifier. */
  tauOnlineS: number | null;
  tauOfflineS: number | null;
  /** The bounds: τ_online ≤ Δ and τ_offline ≤ min(T; S). */
  boundOnlineS: number;
  boundOfflineS: number;
  /** True when both τ are within their bounds and the refusals are for the expected reasons and stay. */
  withinBounds: boolean;
}

/** The issuer revokes the credential this many seconds after the last sync: just after it, the worst case for both. */
const REVOKED_AT_S = 1;

/**
 * The delegated credential of Іван is revoked one second after the last sync. An online verifier fetches the status lists
 * every Δ = 600 s; an offline verifier keeps the lists of the last sync. Both decide on the same request for 8 t at the
 * warehouse of Постачальник Б, from the revocation up to two hours past S, every five minutes and at the moments around
 * the first refresh and around S. The worlds must be two new, identical ones (`createDemoWorld` with the same seed).
 */
export async function revocationTimeline(
  online: DemoWorld,
  offline: DemoWorld,
): Promise<{ rows: RevocationRow[]; report: RevocationReport }> {
  const sync = lastSync(online);
  if (lastSync(offline) !== sync) throw new UmisError('INVALID_ARGUMENT', 'the two worlds must start at the same time');

  const policy = DEFAULT_POLICIES.warehouse_medium;
  const s = policy.maxStatusAgeSeconds;
  const delta = DEFAULT_REFRESH_S.online;
  const credential = decodeCredential(credentialOf(online, 'ivan', 'delegated'));
  const lifetime = credential.exp - credential.iat;
  const firstRefresh = (Math.floor(REVOKED_AT_S / delta) + 1) * delta;
  online.revoke(credential.jti); // the lists the online verifier fetches from now on say so

  const rows: RevocationRow[] = [];
  let published = 0;
  const times = probeTimes(s + 2 * HOUR_S, [REVOKED_AT_S, firstRefresh - 1, firstRefresh, s, s + 1]);
  for (const at of times) {
    if (at < REVOKED_AT_S) continue;
    const refresh = Math.floor(at / delta) * delta;
    if (refresh > published) {
      online.clock.set(sync + refresh);
      await online.publish();
      published = refresh;
    }
    const decisions: ReasonCode[] = [];
    for (const world of [online, offline]) {
      world.clock.set(sync + at - DECISION_DELAY_S.authority);
      const { result } = await authorityCheck(world, { holder: 'ivan', amount: 8 });
      if (result.at !== sync + at) {
        throw new UmisError(
          'PROTOCOL',
          `a presentation planned ${at} s after the sync was decided at ${result.at - sync} s`,
        );
      }
      decisions.push(reasonOf(result.reasons));
    }
    rows.push({ t: at - REVOKED_AT_S, online: decisions[0]!, offline: decisions[1]! });
  }

  const first = (pick: (row: RevocationRow) => ReasonCode): number | null =>
    rows.find((row) => pick(row) !== 'OK')?.t ?? null;
  const tauOnlineS = first((row) => row.online);
  const tauOfflineS = first((row) => row.offline);
  const boundOfflineS = Math.min(lifetime, s);
  const refused = (pick: (row: RevocationRow) => ReasonCode, tau: number | null, reason: ReasonCode): boolean =>
    tau !== null && rows.every((row) => (row.t < tau ? pick(row) === 'OK' : pick(row) === reason));
  const report: RevocationReport = {
    refreshS: delta,
    maxStatusAgeS: s,
    lifetimeS: lifetime,
    revokedAtS: REVOKED_AT_S,
    tauOnlineS,
    tauOfflineS,
    boundOnlineS: delta,
    boundOfflineS,
    withinBounds:
      refused((row) => row.online, tauOnlineS, 'STATUS_REVOKED') &&
      refused((row) => row.offline, tauOfflineS, 'STATUS_LIST_STALE') &&
      tauOnlineS !== null &&
      tauOnlineS <= delta &&
      tauOfflineS !== null &&
      tauOfflineS <= boundOfflineS,
  };
  return { rows, report };
}
