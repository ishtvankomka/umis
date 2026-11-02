import { UmisError, decodeFrameBytes, encodeFrameBytes } from '@umis/core';
import type { Frame } from '@umis/core';

/**
 * A link that carries whole frames (the bytes of `encodeFrameBytes`) between a verifier and a wallet. An implementation
 * cuts the frames to the size its medium allows and puts them back together, so that the layers above see frames only.
 */
export interface PresentationTransport {
  /** Hands one frame to the link. Rejects when the link is closed or the frame cannot be sent. */
  send(frame: Uint8Array): Promise<void>;
  /** Calls `cb` with every frame that arrives, until the returned function is called. */
  onFrame(cb: (frame: Uint8Array) => void): () => void;
  /** Ends the link; nothing is sent or delivered afterwards. */
  close(): Promise<void>;
}

const DEFAULT_TIMEOUT_MS = 10_000;

/** The transports that carried a request, and those that served one: a session holds one of each at most. */
const requested = new WeakSet<object>();
const served = new WeakSet<object>();

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

function assertTransport(t: unknown): asserts t is PresentationTransport {
  const ok =
    typeof t === 'object' &&
    t !== null &&
    typeof (t as Partial<PresentationTransport>).send === 'function' &&
    typeof (t as Partial<PresentationTransport>).onFrame === 'function' &&
    typeof (t as Partial<PresentationTransport>).close === 'function';
  if (!ok) throw invalid('expected a transport with send, onFrame and close');
}

/**
 * The verifier's side of a session: sends `request` and resolves with the frame that comes back. A session carries one
 * request and one answer; a second request on the same transport is PROTOCOL. Nothing arrives within `timeoutMs`
 * (10 seconds unless told otherwise) is NETWORK, and so is a link that fails to send; an answer that is not a UMIS frame
 * is MALFORMED or UNSUPPORTED_FORMAT, and a request that is not a valid frame is INVALID_ARGUMENT. Whether the answer is
 * the right one for the request is for the verifier's decision to say.
 */
export function requestOverTransport(
  t: PresentationTransport,
  request: Frame,
  o: { timeoutMs?: number } = {},
): Promise<Frame> {
  return new Promise<Frame>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let unsubscribe: (() => void) | undefined;
    const settle = (finish: () => void): void => {
      if (timer !== undefined) clearTimeout(timer);
      unsubscribe?.();
      finish();
    };

    try {
      assertTransport(t);
      if (typeof o !== 'object' || o === null) throw invalid('the options must be an object');
      const timeoutMs = o.timeoutMs ?? DEFAULT_TIMEOUT_MS;
      if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
        throw invalid('timeoutMs must be more than 0');
      }
      if (requested.has(t)) throw new UmisError('PROTOCOL', 'a session carries one request');
      const bytes = encodeFrameBytes(request);
      requested.add(t);

      unsubscribe = t.onFrame((incoming) => {
        try {
          const answer = decodeFrameBytes(incoming);
          settle(() => resolve(answer));
        } catch (error) {
          settle(() => reject(error));
        }
      });
      timer = setTimeout(
        () => settle(() => reject(new UmisError('NETWORK', `no answer within ${timeoutMs} ms`))),
        timeoutMs,
      );
      t.send(bytes).catch((cause: unknown) => {
        const error =
          cause instanceof UmisError ? cause : new UmisError('NETWORK', 'the request could not be sent', { cause });
        settle(() => reject(error));
      });
    } catch (error) {
      settle(() => reject(error));
    }
  });
}

/**
 * The wallet's side of a session: waits for a request frame, hands it to `onRequest` and sends back the frame that
 * `onRequest` resolves with. The first frame that decodes is the request; anything else that arrives is ignored, and so
 * is everything after the request, because a session carries one request and one answer. A request that `onRequest`
 * refuses (it rejects) gets no answer, and the asker's timeout ends the session. Serving a transport twice is PROTOCOL.
 * The returned function stops serving.
 */
export function serveOverTransport(
  t: PresentationTransport,
  onRequest: (request: Frame) => Promise<Frame>,
): () => void {
  assertTransport(t);
  if (typeof onRequest !== 'function') throw invalid('onRequest must be a function');
  if (served.has(t)) throw new UmisError('PROTOCOL', 'a session is served once');
  served.add(t);

  let finished = false;
  let unsubscribe: () => void = () => undefined;
  const stop = (): void => {
    finished = true;
    unsubscribe();
  };

  async function answer(request: Frame): Promise<void> {
    try {
      await t.send(encodeFrameBytes(await onRequest(request)));
    } catch {
      // a refused or failed request gets no answer; the asker gives up when its time is over
    }
  }

  unsubscribe = t.onFrame((incoming) => {
    if (finished) return;
    let request: Frame;
    try {
      request = decodeFrameBytes(incoming);
    } catch {
      return;
    }
    stop();
    void answer(request);
  });
  if (finished) unsubscribe();
  return stop;
}
