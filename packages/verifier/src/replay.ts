import { UmisError } from '@umis/core';
import type { ReplayStore } from '@umis/core';

/** Ids a store remembers at most, unless told otherwise. */
const DEFAULT_MAX = 100_000;

interface Expiry {
  readonly at: number;
  readonly id: string;
}

/** Stores made by {@link createMemoryReplayStore} learn the time of each decision here. */
const observers = new WeakMap<object, (now: number) => void>();

/**
 * Tells a store made by {@link createMemoryReplayStore} at which time the verifier is deciding, so that it can forget
 * ids that can no longer be presented. Any other store ignores the call.
 */
export function observeTime(store: object, now: number): void {
  observers.get(store)?.(now);
}

/**
 * An in-memory {@link ReplayStore}. `checkAndRemember` answers true the first time it sees an id and false for every
 * further presentation of it. An id is remembered until its `expiresAt` has passed: expired ids are dropped when a new id
 * comes in, so memory stays bounded by what is still presentable. When `max` ids are held and none has expired, new ids
 * are refused (the answer is false), so a full store rejects instead of forgetting.
 *
 * Time comes from `opts.now` (seconds) when it is given; without it, from the `now` of the verification calls that use
 * the store. The store never reads a clock of its own. `size()` counts the ids that are still remembered.
 */
export function createMemoryReplayStore(opts?: { max?: number; now?: () => number }): ReplayStore & { size(): number } {
  const max = opts?.max ?? DEFAULT_MAX;
  if (!Number.isSafeInteger(max) || max < 1) {
    throw new UmisError('INVALID_ARGUMENT', 'the capacity of a replay store is a positive integer');
  }
  const clock = opts?.now;
  if (clock !== undefined && typeof clock !== 'function') {
    throw new UmisError('INVALID_ARGUMENT', 'now must be a function that returns seconds');
  }

  const expiry = new Map<string, number>();
  const heap: Expiry[] = []; // a binary min-heap on `at`: the id that expires first is on top
  let observed = Number.NEGATIVE_INFINITY;

  function push(node: Expiry): void {
    let child = heap.length;
    heap.push(node);
    while (child > 0) {
      const parent = (child - 1) >> 1;
      if (heap[parent]!.at <= node.at) break;
      heap[child] = heap[parent]!;
      child = parent;
    }
    heap[child] = node;
  }

  function pop(): Expiry {
    const top = heap[0]!;
    const last = heap.pop()!;
    if (heap.length > 0) {
      let parent = 0;
      for (;;) {
        let child = 2 * parent + 1;
        if (child >= heap.length) break;
        if (child + 1 < heap.length && heap[child + 1]!.at < heap[child]!.at) child += 1;
        if (last.at <= heap[child]!.at) break;
        heap[parent] = heap[child]!;
        parent = child;
      }
      heap[parent] = last;
    }
    return top;
  }

  /** Drops the ids whose time has passed: at the instant `expiresAt` itself an id is still remembered. */
  function evict(): void {
    const at = clock !== undefined ? clock() : observed;
    while (heap.length > 0 && heap[0]!.at < at) expiry.delete(pop().id);
  }

  const store = {
    async checkAndRemember(id: string, expiresAt: number): Promise<boolean> {
      if (typeof id !== 'string' || id === '') {
        throw new UmisError('INVALID_ARGUMENT', 'a replay id is a non-empty string');
      }
      if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) {
        throw new UmisError('INVALID_ARGUMENT', 'expiresAt must be a finite number of seconds');
      }
      evict();
      if (expiry.has(id) || expiry.size >= max) return false;
      expiry.set(id, expiresAt);
      push({ at: expiresAt, id });
      return true;
    },
    size(): number {
      evict();
      return expiry.size;
    },
  };
  observers.set(store, (now) => {
    observed = now;
  });
  return store;
}
