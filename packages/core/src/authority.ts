import { PERIODS, type Period } from './profile.js';
import { UmisError } from './reasons.js';
import type { AuthorityItem, AuthorityRequest, DelegationClaim, PeriodWindow } from './types.js';

const DAY_SECONDS = 86_400;
const HOUR_SECONDS = 3_600;
const DEFAULT_SHIFT_HOURS = 8;

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

// ---------------------------------------------------------------------------------------------------------------
// matching a request against the authority items of a credential
// ---------------------------------------------------------------------------------------------------------------

/** An item that is past its `valid_until`. A `valid_until` that is not a number counts as past. */
function isExpired(item: AuthorityItem, now: number): boolean {
  return item.valid_until !== undefined && !(item.valid_until >= now);
}

/**
 * Finds the authority item that answers `req`. An item matches when action, resource and unit are equal strings (no
 * unit conversion) and the object agrees: the request names none, the item names none, or both name the same one.
 *
 * - no match: AUTHORITY_MISSING;
 * - every match is past its `valid_until`: AUTHORITY_EXPIRED, with the item that expired last;
 * - otherwise the unexpired match with the largest limit decides, and the request is accepted when its amount does
 *   not exceed that limit (equal is accepted). Over the limit: AUTHORITY_LIMIT_EXCEEDED, with that item so that the
 *   limit can be shown. An amount that is negative or not a number is over every limit.
 */
export function matchAuthority(
  items: readonly AuthorityItem[] | undefined,
  req: AuthorityRequest,
  now: number,
):
  | { ok: true; item: AuthorityItem }
  | {
      ok: false;
      reason: 'AUTHORITY_MISSING' | 'AUTHORITY_EXPIRED' | 'AUTHORITY_LIMIT_EXCEEDED';
      item?: AuthorityItem;
    } {
  const matching = (items ?? []).filter(
    (item) =>
      item.action === req.action &&
      item.resource === req.resource &&
      item.limit.unit === req.unit &&
      (req.object === undefined || item.object === undefined || item.object === req.object),
  );
  if (matching.length === 0) return { ok: false, reason: 'AUTHORITY_MISSING' };

  const valid = matching.filter((item) => !isExpired(item, now));
  if (valid.length === 0) {
    const lastExpiring = matching.reduce((a, b) => (b.valid_until! > a.valid_until! ? b : a));
    return { ok: false, reason: 'AUTHORITY_EXPIRED', item: lastExpiring };
  }

  const decisive = valid.reduce((a, b) => (b.limit.amount > a.limit.amount ? b : a));
  if (!(req.amount >= 0 && req.amount <= decisive.limit.amount)) {
    return { ok: false, reason: 'AUTHORITY_LIMIT_EXCEEDED', item: decisive };
  }
  return { ok: true, item: decisive };
}

// ---------------------------------------------------------------------------------------------------------------
// delegation: a child is never wider than its parent
// ---------------------------------------------------------------------------------------------------------------

/**
 * Whether `child` grants no more than `parent`: the same action, resource, unit and period; an amount that is not
 * larger; the parent's object restriction kept; and, when the parent expires, a child that expires too, at the same time or sooner.
 */
export function isNarrowerItem(child: AuthorityItem, parent: AuthorityItem): boolean {
  if (child.action !== parent.action || child.resource !== parent.resource) return false;
  if (child.limit.unit !== parent.limit.unit || child.limit.per !== parent.limit.per) return false;
  if (!(child.limit.amount <= parent.limit.amount)) return false;
  if (parent.object !== undefined && child.object !== parent.object) return false;
  if (parent.valid_until !== undefined) {
    if (child.valid_until === undefined || !(child.valid_until <= parent.valid_until)) return false;
  }
  return true;
}

/**
 * The delegation rules, checked in this order: depth (`parent.depth + 1` within `maxDepth`), lifetime (`child.exp` not
 * after `parent.exp`), and width (every child item is narrower than some parent item). Values that are not numbers
 * fail their rule.
 */
export function checkDelegation(i: {
  parent: { authority: AuthorityItem[]; exp: number; depth: number; maxDepth: number };
  child: { authority: AuthorityItem[]; exp: number };
}):
  | { ok: true }
  | { ok: false; reason: 'DELEGATION_WIDER_THAN_PARENT' | 'DELEGATION_DEPTH_EXCEEDED' | 'DELEGATION_OUTLIVES_PARENT' } {
  const { parent, child } = i;
  if (!(parent.depth + 1 <= parent.maxDepth)) return { ok: false, reason: 'DELEGATION_DEPTH_EXCEEDED' };
  if (!(child.exp <= parent.exp)) return { ok: false, reason: 'DELEGATION_OUTLIVES_PARENT' };
  const covered = child.authority.every((item) =>
    parent.authority.some((parentItem) => isNarrowerItem(item, parentItem)),
  );
  return covered ? { ok: true } : { ok: false, reason: 'DELEGATION_WIDER_THAN_PARENT' };
}

// ---------------------------------------------------------------------------------------------------------------
// budget periods
// ---------------------------------------------------------------------------------------------------------------

/** Calendar date of a day number counted from 1970-01-01 (proleptic Gregorian). */
function civilFromDays(days: number): { year: number; month: number; day: number } {
  const z = days + 719_468;
  const era = Math.floor(z / 146_097);
  const dayOfEra = z - era * 146_097;
  const yearOfEra = Math.floor(
    (dayOfEra - Math.floor(dayOfEra / 1_460) + Math.floor(dayOfEra / 36_524) - Math.floor(dayOfEra / 146_096)) / 365,
  );
  const dayOfYear = dayOfEra - (365 * yearOfEra + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100));
  const monthIndex = Math.floor((5 * dayOfYear + 2) / 153);
  const day = dayOfYear - Math.floor((153 * monthIndex + 2) / 5) + 1;
  const month = monthIndex < 10 ? monthIndex + 3 : monthIndex - 9;
  return { year: yearOfEra + era * 400 + (month <= 2 ? 1 : 0), month, day };
}

/** Day number counted from 1970-01-01 of a calendar date (proleptic Gregorian). */
function daysFromCivil(year: number, month: number, day: number): number {
  const y = month <= 2 ? year - 1 : year;
  const era = Math.floor(y / 400);
  const yearOfEra = y - era * 400;
  const dayOfYear = Math.floor((153 * (month > 2 ? month - 3 : month + 9) + 2) / 5) + day - 1;
  const dayOfEra = yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear;
  return era * 146_097 + dayOfEra - 719_468;
}

/**
 * The window `[start, end)` of the budget period that contains `at`, in NumericDate seconds; `end` is the first second
 * of the next period.
 *
 * - `shift`: blocks of `shiftHours` (default 8) counted from local midnight, the last block of a day ending at midnight;
 * - `day`: local midnight to local midnight;
 * - `week`: ISO week, Monday 00:00 to the next Monday 00:00;
 * - `month`: calendar month;
 * - `operation`: the single instant `{start: at, end: at}`.
 *
 * Local time is UTC plus `utcOffsetMinutes` (default 0); daylight saving time is not modelled.
 */
export function periodWindow(
  per: Period,
  at: number,
  opts?: { shiftHours?: number; utcOffsetMinutes?: number },
): PeriodWindow {
  if (!(PERIODS as readonly string[]).includes(per)) throw invalid(`unknown period "${String(per)}"`);
  if (typeof at !== 'number' || !Number.isFinite(at)) throw invalid('the instant must be a finite number of seconds');
  if (per === 'operation') return { start: at, end: at };

  const offsetMinutes = opts?.utcOffsetMinutes ?? 0;
  if (!Number.isInteger(offsetMinutes) || Math.abs(offsetMinutes) > 24 * 60) {
    throw invalid('utcOffsetMinutes must be an integer within a day');
  }
  const offset = offsetMinutes * 60;
  const local = Math.floor(at) + offset;
  const dayNumber = Math.floor(local / DAY_SECONDS);
  const dayStart = dayNumber * DAY_SECONDS - offset;

  switch (per) {
    case 'shift': {
      const hours = opts?.shiftHours ?? DEFAULT_SHIFT_HOURS;
      const length = hours * HOUR_SECONDS;
      if (!Number.isFinite(hours) || hours <= 0 || hours > 24 || !Number.isInteger(length)) {
        throw invalid('shiftHours must be a positive number of hours, at most 24, in whole seconds');
      }
      const start = dayStart + Math.floor((Math.floor(at) - dayStart) / length) * length;
      return { start, end: Math.min(start + length, dayStart + DAY_SECONDS) };
    }
    case 'day':
      return { start: dayStart, end: dayStart + DAY_SECONDS };
    case 'week': {
      const weekday = (((dayNumber + 3) % 7) + 7) % 7; // 1970-01-01 was a Thursday; Monday is 0
      const start = (dayNumber - weekday) * DAY_SECONDS - offset;
      return { start, end: start + 7 * DAY_SECONDS };
    }
    default: {
      const { year, month } = civilFromDays(dayNumber);
      const next = month === 12 ? daysFromCivil(year + 1, 1, 1) : daysFromCivil(year, month + 1, 1);
      return { start: daysFromCivil(year, month, 1) * DAY_SECONDS - offset, end: next * DAY_SECONDS - offset };
    }
  }
}

/** Escapes the separator, so that no two different sets of parts can give the same key. */
const keyPart = (part: string): string => part.replaceAll('%', '%25').replaceAll('|', '%7C');

/**
 * The key under which a verifier books an accepted amount: `iss|budget|action|resource|unit`. The budget is the id of
 * the parent credential for a delegated credential and the credential's own `jti` otherwise, so that a delegate and its
 * parent draw on one budget. `|` and `%` inside a part are written as `%7C` and `%25`.
 */
export function ledgerKey(i: {
  iss: string;
  jti: string;
  delegation?: DelegationClaim;
  req: AuthorityRequest;
}): string {
  const budget = i.delegation?.parent?.id ?? i.jti;
  return [i.iss, budget, i.req.action, i.req.resource, i.req.unit].map(keyPart).join('|');
}
