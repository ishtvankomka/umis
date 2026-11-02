import { UmisError } from '@umis/core';
import type { ParsedStatusList, StatusListCache } from '@umis/core';

/**
 * A least-recently-used cache of verified status lists, keyed by the token string. `verifyStatusListToken` only reuses
 * an entry it stored itself and only while the keys it was verified under are still offered, so sharing one cache
 * between issuers is safe.
 */
export function createStatusListCache(max = 64): StatusListCache {
  if (!Number.isSafeInteger(max) || max < 1) {
    throw new UmisError('INVALID_ARGUMENT', 'the cache size must be a positive integer');
  }
  const entries = new Map<string, ParsedStatusList>();
  return {
    get(token: string): ParsedStatusList | undefined {
      const hit = entries.get(token);
      if (hit !== undefined) {
        entries.delete(token);
        entries.set(token, hit);
      }
      return hit;
    },
    set(token: string, value: ParsedStatusList): void {
      entries.delete(token);
      entries.set(token, value);
      while (entries.size > max) {
        const oldest = entries.keys().next();
        if (oldest.done) break;
        entries.delete(oldest.value);
      }
    },
  };
}
