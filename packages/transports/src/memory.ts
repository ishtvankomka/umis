import { UmisError } from '@umis/core';
import { assertMtu, chunkFrame, createReassembler } from './chunk.js';
import type { PresentationTransport } from './session.js';

/** A write size that phones commonly negotiate for BLE. */
const DEFAULT_MTU = 185;

type Listener = (frame: Uint8Array) => void;

/** One end of the link: who listens, the reassembly of what arrives, and the id of the next frame it sends. */
interface End {
  readonly listeners: Set<Listener>;
  readonly reassembler: ReturnType<typeof createReassembler>;
  nextId: number;
}

function newEnd(): End {
  return { listeners: new Set(), reassembler: createReassembler(), nextId: 0 };
}

/**
 * Two transports that are the ends of one in-memory link, for tests and for running a verifier and a wallet side by
 * side in one program. Frames are cut into chunks of at most `mtu` bytes (185 by default) and put back together on the
 * other side, exactly as a BLE link does, and they are delivered asynchronously. `dropChunk(n)` is asked for every chunk
 * put on the link, counted from 0 over both directions together, and a chunk for which it answers true is lost. A frame
 * that loses a chunk never arrives. Closing either end closes the link: a send after that is NETWORK and nothing more
 * is delivered.
 */
export function createMemoryTransportPair(
  o: { mtu?: number; dropChunk?: (n: number) => boolean } = {},
): [PresentationTransport, PresentationTransport] {
  if (typeof o !== 'object' || o === null) throw new UmisError('INVALID_ARGUMENT', 'the options must be an object');
  const mtu = o.mtu ?? DEFAULT_MTU;
  assertMtu(mtu);
  const { dropChunk } = o;
  if (dropChunk !== undefined && typeof dropChunk !== 'function') {
    throw new UmisError('INVALID_ARGUMENT', 'dropChunk must be a function');
  }

  const ends: [End, End] = [newEnd(), newEnd()];
  let written = 0;
  let closed = false;

  function receive(end: End, chunk: Uint8Array): void {
    let frame: Uint8Array | undefined;
    try {
      frame = end.reassembler.push(chunk);
    } catch {
      return; // a damaged message is lost, as it would be on a real link
    }
    if (frame === undefined) return;
    const arrived = frame;
    void Promise.resolve().then(() => {
      if (closed) return;
      for (const listener of [...end.listeners]) {
        try {
          listener(arrived.slice());
        } catch {
          // one listener failing does not keep the others from the frame
        }
      }
    });
  }

  function transportOf(self: End, peer: End): PresentationTransport {
    return {
      async send(frame) {
        if (closed) throw new UmisError('NETWORK', 'the transport is closed');
        const chunks = chunkFrame(frame, mtu, self.nextId);
        self.nextId = (self.nextId + 1) & 0xff;
        for (const chunk of chunks) {
          if (closed) throw new UmisError('NETWORK', 'the transport is closed');
          const n = written++;
          if (dropChunk?.(n) === true) continue;
          receive(peer, chunk);
        }
      },

      onFrame(cb) {
        if (typeof cb !== 'function') throw new UmisError('INVALID_ARGUMENT', 'a frame listener is a function');
        const listener: Listener = (frame) => cb(frame);
        self.listeners.add(listener);
        return () => {
          self.listeners.delete(listener);
        };
      },

      async close() {
        closed = true;
        for (const end of ends) {
          end.listeners.clear();
          end.reassembler.reset();
        }
      },
    };
  }

  return [transportOf(ends[0], ends[1]), transportOf(ends[1], ends[0])];
}
