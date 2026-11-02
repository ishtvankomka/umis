import { UmisError, type AuthorityLedger, type PeriodWindow } from '@umis/core';

function checkArguments(key: string, window: PeriodWindow): void {
  if (typeof key !== 'string' || key === '') {
    throw new UmisError('INVALID_ARGUMENT', 'a ledger key is a non-empty string');
  }
  if (!Number.isFinite(window?.start) || !Number.isFinite(window?.end) || window.start > window.end) {
    throw new UmisError('INVALID_ARGUMENT', 'a period window needs finite start and end, with start not after end');
  }
}

/**
 * An in-memory {@link AuthorityLedger}. Amounts add up per key and exact window; a window never shares its total with
 * another one, so the next shift starts empty. The ledger only counts: whether a total fits a limit is the caller's
 * decision. `add` refuses negative or non-finite amounts, which would otherwise free budget.
 */
export function createMemoryLedger(): AuthorityLedger {
  const totals = new Map<string, Map<string, number>>();
  const windowId = (window: PeriodWindow): string => `${window.start}:${window.end}`;
  return {
    async used(key, window) {
      checkArguments(key, window);
      return totals.get(key)?.get(windowId(window)) ?? 0;
    },
    async add(key, window, amount) {
      checkArguments(key, window);
      if (!Number.isFinite(amount) || amount < 0) {
        throw new UmisError('INVALID_ARGUMENT', 'a ledger amount is a finite number that is not negative');
      }
      const id = windowId(window);
      const windows = totals.get(key) ?? new Map<string, number>();
      windows.set(id, (windows.get(id) ?? 0) + amount);
      totals.set(key, windows);
    },
  };
}
