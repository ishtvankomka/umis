import { describe, expect, it } from 'vitest';
import {
  checkDelegation,
  isNarrowerItem,
  ledgerKey,
  matchAuthority,
  periodWindow,
  type AuthorityItem,
  type AuthorityRequest,
} from '../src/index.js';
import { IVAN_AUTHORITY, NOW, OLEH_AUTHORITY, codeOf } from './fixtures.js';

const request = (over: Partial<AuthorityRequest> = {}): AuthorityRequest => ({
  action: 'receive_materials',
  resource: 'rebar',
  amount: 10,
  unit: 't',
  ...over,
});

const item = (over: Partial<AuthorityItem> = {}, limit: Partial<AuthorityItem['limit']> = {}): AuthorityItem => ({
  ...OLEH_AUTHORITY[0]!,
  ...over,
  limit: { ...OLEH_AUTHORITY[0]!.limit, ...limit },
});

const seconds = (iso: string): number => Date.parse(iso) / 1000;

describe('matching a request against authority items', () => {
  it('accepts ten tonnes against a limit of ten and rejects ten tonnes against a limit of eight', () => {
    const accepted = matchAuthority(OLEH_AUTHORITY, request(), NOW);
    expect(accepted).toEqual({ ok: true, item: OLEH_AUTHORITY[0] });
    const rejected = matchAuthority(IVAN_AUTHORITY, request(), NOW);
    expect(rejected).toEqual({ ok: false, reason: 'AUTHORITY_LIMIT_EXCEEDED', item: IVAN_AUTHORITY[0] });
    expect(rejected.ok === false && rejected.item?.limit.amount).toBe(8);
    expect(matchAuthority(IVAN_AUTHORITY, request({ amount: 8 }), NOW).ok).toBe(true);
    expect(matchAuthority(IVAN_AUTHORITY, request({ amount: 8.0001 }), NOW).ok).toBe(false);
  });

  it('matches action, resource and unit exactly and the object when both sides name one', () => {
    const reason = (req: AuthorityRequest, items: readonly AuthorityItem[] | undefined) => {
      const result = matchAuthority(items, req, NOW);
      return result.ok ? 'ok' : result.reason;
    };
    const oleh = (req: AuthorityRequest) => reason(req, OLEH_AUTHORITY);
    expect(oleh(request({ unit: 'kg' }))).toBe('AUTHORITY_MISSING');
    expect(oleh(request({ unit: 'T' }))).toBe('AUTHORITY_MISSING');
    expect(oleh(request({ action: 'issue_materials' }))).toBe('AUTHORITY_MISSING');
    expect(oleh(request({ resource: 'cement' }))).toBe('AUTHORITY_MISSING');
    expect(oleh(request({ object: 'bridge-02' }))).toBe('AUTHORITY_MISSING');
    expect(oleh(request({ object: 'bridge-01' }))).toBe('ok');
    expect(oleh(request())).toBe('ok'); //                                          the request names no object
    expect(reason(request({ object: 'bridge-02' }), [item({ object: undefined })])).toBe('ok'); // the item names none
    expect(reason(request(), [])).toBe('AUTHORITY_MISSING');
    expect(reason(request(), undefined)).toBe('AUTHORITY_MISSING');
  });

  it('reports an item past its valid_until as expired, and takes the largest unexpired limit among several', () => {
    const past = item({ valid_until: NOW - 1 });
    const result = matchAuthority([past], request(), NOW);
    expect(result).toEqual({ ok: false, reason: 'AUTHORITY_EXPIRED', item: past });
    expect(matchAuthority([item({ valid_until: NOW })], request(), NOW).ok).toBe(true); // valid through valid_until

    const small = item({}, { amount: 5 });
    const large = item({ object: undefined }, { amount: 12 });
    const expiredLarge = item({ valid_until: NOW - 1 }, { amount: 99 });
    expect(matchAuthority([small, expiredLarge, large], request({ amount: 11 }), NOW)).toEqual({
      ok: true,
      item: large,
    });
    expect(matchAuthority([small, expiredLarge], request({ amount: 6 }), NOW)).toEqual({
      ok: false,
      reason: 'AUTHORITY_LIMIT_EXCEEDED',
      item: small,
    });
  });

  it('treats a request amount that is negative or not a number as over every limit', () => {
    for (const amount of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(matchAuthority(OLEH_AUTHORITY, request({ amount }), NOW)).toMatchObject({
        ok: false,
        reason: 'AUTHORITY_LIMIT_EXCEEDED',
      });
    }
  });
});

describe('delegation is never wider than its parent', () => {
  const parent = { authority: OLEH_AUTHORITY, exp: NOW + 90 * 86_400, depth: 0, maxDepth: 1 };
  const check = (child: AuthorityItem[], over: Partial<typeof parent & { childExp: number }> = {}) => {
    const { childExp = NOW + 30 * 86_400, ...parentOver } = over;
    const result = checkDelegation({
      parent: { ...parent, ...parentOver },
      child: { authority: child, exp: childExp },
    });
    return result.ok ? 'ok' : result.reason;
  };

  it('accepts a narrower amount and rejects a wider one, another period, a dropped object or an extended validity', () => {
    expect(check(IVAN_AUTHORITY)).toBe('ok');
    expect(check(OLEH_AUTHORITY)).toBe('ok'); //                               equal is not wider
    expect(check([item({}, { amount: 12 })])).toBe('DELEGATION_WIDER_THAN_PARENT');
    expect(check([item({}, { per: 'day' })])).toBe('DELEGATION_WIDER_THAN_PARENT');
    expect(check([item({}, { per: undefined })])).toBe('DELEGATION_WIDER_THAN_PARENT');
    expect(check([item({ object: undefined })])).toBe('DELEGATION_WIDER_THAN_PARENT');
    expect(check([item({ object: 'bridge-02' })])).toBe('DELEGATION_WIDER_THAN_PARENT');
    expect(check([item({}, { unit: 'kg' })])).toBe('DELEGATION_WIDER_THAN_PARENT');
    expect(check([item({ resource: 'cement' })])).toBe('DELEGATION_WIDER_THAN_PARENT');
    expect(check([item({ action: 'issue_materials' })])).toBe('DELEGATION_WIDER_THAN_PARENT');
    expect(check([...IVAN_AUTHORITY, item({ object: 'bridge-02' })])).toBe('DELEGATION_WIDER_THAN_PARENT');
  });

  it('keeps an expiry of the parent item: the child must have one, and one that does not outlast it', () => {
    const limited = [item({ valid_until: NOW + 1_000 })];
    const result = (child: AuthorityItem) =>
      checkDelegation({ parent: { ...parent, authority: limited }, child: { authority: [child], exp: NOW + 1 } });
    expect(result(item({ valid_until: NOW + 1_000 })).ok).toBe(true);
    expect(result(item({ valid_until: NOW + 500 })).ok).toBe(true);
    expect(result(item({ valid_until: NOW + 1_001 }))).toMatchObject({ reason: 'DELEGATION_WIDER_THAN_PARENT' });
    expect(result(item({ valid_until: undefined }))).toMatchObject({ reason: 'DELEGATION_WIDER_THAN_PARENT' });
    expect(isNarrowerItem(item({}, { amount: 1 }), item())).toBe(true);
    expect(isNarrowerItem(item(), item({}, { amount: 1 }))).toBe(false);
  });

  it('allows no grandchild of a root with max_depth 1, and no child that outlives the parent', () => {
    expect(check(IVAN_AUTHORITY, { depth: 1 })).toBe('DELEGATION_DEPTH_EXCEEDED');
    expect(check(IVAN_AUTHORITY, { depth: 0, maxDepth: 0 })).toBe('DELEGATION_DEPTH_EXCEEDED');
    expect(check(IVAN_AUTHORITY, { childExp: parent.exp + 1 })).toBe('DELEGATION_OUTLIVES_PARENT');
    expect(check(IVAN_AUTHORITY, { childExp: parent.exp })).toBe('ok');
  });

  it('reports the first broken rule in the order depth, lifetime, width', () => {
    const wide = [item({}, { amount: 12 })];
    expect(check(wide, { depth: 1, childExp: parent.exp + 1 })).toBe('DELEGATION_DEPTH_EXCEEDED');
    expect(check(wide, { childExp: parent.exp + 1 })).toBe('DELEGATION_OUTLIVES_PARENT');
    expect(check(wide)).toBe('DELEGATION_WIDER_THAN_PARENT');
  });

  it('fails closed on numbers that are not numbers', () => {
    expect(check(IVAN_AUTHORITY, { depth: Number.NaN })).toBe('DELEGATION_DEPTH_EXCEEDED');
    expect(check(IVAN_AUTHORITY, { childExp: Number.NaN })).toBe('DELEGATION_OUTLIVES_PARENT');
    expect(check([item({}, { amount: Number.NaN })])).toBe('DELEGATION_WIDER_THAN_PARENT');
  });
});

describe('budget periods', () => {
  it('cuts a day into shifts of eight hours with boundaries at 08:00 and 16:00', () => {
    const midnight = seconds('2026-11-02T00:00:00Z');
    const at = (time: string) => periodWindow('shift', seconds(`2026-11-02T${time}Z`));
    expect(at('00:00:00')).toEqual({ start: midnight, end: midnight + 8 * 3_600 });
    expect(at('07:59:59')).toEqual({ start: midnight, end: midnight + 8 * 3_600 });
    expect(at('08:00:00')).toEqual({ start: midnight + 8 * 3_600, end: midnight + 16 * 3_600 });
    expect(at('15:59:59')).toEqual({ start: midnight + 8 * 3_600, end: midnight + 16 * 3_600 });
    expect(at('16:00:00')).toEqual({ start: midnight + 16 * 3_600, end: midnight + 86_400 });
    expect(at('23:59:59').end).toBe(midnight + 86_400);
  });

  it('counts from local midnight, honours the shift length and ends a shift at midnight', () => {
    const at = seconds('2026-11-02T21:30:00Z'); //                  23:30 at UTC+2
    const local = periodWindow('shift', at, { utcOffsetMinutes: 120 });
    expect(local).toEqual({ start: seconds('2026-11-02T14:00:00Z'), end: seconds('2026-11-02T22:00:00Z') });
    const tenHours = periodWindow('shift', seconds('2026-11-02T22:00:00Z'), { shiftHours: 10 });
    expect(tenHours).toEqual({ start: seconds('2026-11-02T20:00:00Z'), end: seconds('2026-11-03T00:00:00Z') });
  });

  it('gives the day, the ISO week from Monday and the calendar month', () => {
    const at = seconds('2026-11-04T10:00:00Z'); //                    a Wednesday
    expect(periodWindow('day', at)).toEqual({
      start: seconds('2026-11-04T00:00:00Z'),
      end: seconds('2026-11-05T00:00:00Z'),
    });
    expect(periodWindow('week', at)).toEqual({
      start: seconds('2026-11-02T00:00:00Z'),
      end: seconds('2026-11-09T00:00:00Z'),
    });
    expect(periodWindow('week', seconds('2026-11-08T23:59:59Z')).start).toBe(seconds('2026-11-02T00:00:00Z'));
    expect(periodWindow('week', seconds('2026-11-09T00:00:00Z')).start).toBe(seconds('2026-11-09T00:00:00Z'));
    expect(periodWindow('month', at)).toEqual({
      start: seconds('2026-11-01T00:00:00Z'),
      end: seconds('2026-12-01T00:00:00Z'),
    });
    expect(periodWindow('month', seconds('2026-12-31T23:59:59Z'))).toEqual({
      start: seconds('2026-12-01T00:00:00Z'),
      end: seconds('2027-01-01T00:00:00Z'),
    });
    expect(periodWindow('month', seconds('2028-02-29T12:00:00Z'))).toEqual({
      start: seconds('2028-02-01T00:00:00Z'),
      end: seconds('2028-03-01T00:00:00Z'),
    });
    expect(periodWindow('week', at, { utcOffsetMinutes: -300 }).start).toBe(seconds('2026-11-02T05:00:00Z'));
  });

  it('agrees with the calendar for every day over several years, before and after 1970', () => {
    for (let day = seconds('1969-01-01T00:00:00Z'); day < seconds('2031-01-01T00:00:00Z'); day += 86_400 * 7 + 3_600) {
      const date = new Date(day * 1000);
      const first = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1) / 1000;
      const next = Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1) / 1000;
      expect(periodWindow('month', day)).toEqual({ start: first, end: next });
      expect(new Date(periodWindow('week', day).start * 1000).getUTCDay()).toBe(1);
    }
  });

  it('makes an operation a single instant and refuses unusable input', async () => {
    expect(periodWindow('operation', NOW)).toEqual({ start: NOW, end: NOW });
    expect(await codeOf(() => periodWindow('fortnight' as never, NOW))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => periodWindow('day', Number.NaN))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => periodWindow('shift', NOW, { shiftHours: 0 }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => periodWindow('shift', NOW, { shiftHours: 25 }))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => periodWindow('day', NOW, { utcOffsetMinutes: 90.5 }))).toBe('INVALID_ARGUMENT');
  });
});

describe('ledger keys', () => {
  const base = { iss: 'https://issuer.example/a', jti: 'cred-1', req: request() };

  it('names the credential itself, or the parent for a delegate, so that both draw on one budget', () => {
    expect(ledgerKey(base)).toBe('https://issuer.example/a|cred-1|receive_materials|rebar|t');
    const delegation = {
      parent: { id: 'cred-1', status: { uri: 'u', idx: 1 }, authority: OLEH_AUTHORITY, exp: NOW },
      depth: 1,
      max_depth: 1,
    };
    expect(ledgerKey({ ...base, jti: 'cred-2', delegation })).toBe(ledgerKey(base));
    expect(ledgerKey({ ...base, delegation: { depth: 0, max_depth: 1 } })).toBe(ledgerKey(base));
  });

  it('cannot be made to collide through the separator', () => {
    const a = ledgerKey({ ...base, iss: 'a|b', jti: 'c' });
    const b = ledgerKey({ ...base, iss: 'a', jti: 'b|c' });
    expect(a).not.toBe(b);
    expect(ledgerKey({ ...base, req: request({ amount: 1, object: 'bridge-01' }) })).toBe(ledgerKey(base)); // amount and object are not part of it
  });
});
