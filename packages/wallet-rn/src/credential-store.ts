import { UmisError, base64urlDecode, base64urlEncode, utf8Decode, utf8Encode } from '@umis/core';
import type { StoredCredential } from '@umis/wallet';
import * as SecureStore from 'expo-secure-store';

export interface CredentialStore {
  /** Every readable credential, in the order they were first stored. */
  list(): Promise<StoredCredential[]>;
  /** The credential, `null` when there is none under this id; a stored credential that cannot be read is MALFORMED. */
  get(id: string): Promise<StoredCredential | null>;
  /**
   * Stores the credential, replacing the one with the same id. A write that fails or is cut short leaves the credential
   * that was stored, never a mixture of the two.
   */
  put(c: StoredCredential): Promise<void>;
  /** Deletes the credential. Removing an id that does not exist is not an error. */
  remove(id: string): Promise<void>;
}

const DEFAULT_NAMESPACE = 'umis';
const NAMESPACE_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
const ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
/** Platform secret stores accept values of up to 2 048 bytes; a chunk is base64url, one byte per character. */
const DEFAULT_CHUNK_CHARS = 1_800;
const MIN_CHUNK_CHARS = 128;
const MAX_CHUNK_CHARS = 2_047;
/** No credential comes anywhere near this many pieces; a count above it is a damaged record. */
const MAX_CHUNKS = 1_024;
/** The index is one value, so it has to fit the same limit. */
const MAX_INDEX_CHARS = 2_047;

const STORE_OPTIONS = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY };

// Operations of one namespace run one after the other: `put` and `remove` read the index, change it and write it back,
// and a reader must not find the pieces of a credential deleted under it.
const queues = new Map<string, Promise<unknown>>();

function exclusively<T>(namespace: string, task: () => Promise<T>): Promise<T> {
  const run = (queues.get(namespace) ?? Promise.resolve()).then(task);
  queues.set(
    namespace,
    run.catch(() => undefined),
  );
  return run;
}

/** The two sets of keys that the pieces of a credential go to: `<n>` is the first, `b<n>` the second. */
type PieceSet = 'a' | 'b';

/** What the count record of a credential says: which set holds the pieces and how many there are. */
interface Pieces {
  readonly set: PieceSet;
  readonly count: number;
}

/**
 * Credentials in the secret store of the device. A credential is JSON, UTF-8 and base64url, cut into pieces that each
 * fit one value. The pieces are kept in one of two sets of keys, `<namespace>.cred.<id>.<n>` and
 * `<namespace>.cred.<id>.b<n>`. The record `<namespace>.cred.<id>.n` holds their number, followed by `b` when the
 * second set is the one in use, and the list of ids is `<namespace>.creds.index`.
 *
 * Pieces are never written over a credential that is stored: they go to the set that the record does not name, and
 * writing the record is what makes them the credential. A credential with a new id exists once its id is in the index,
 * which is written last. A write that fails or is cut short therefore leaves the credential as it was.
 */
export function createCredentialStore(opts: { namespace?: string; chunkChars?: number } = {}): CredentialStore {
  const namespace = opts.namespace ?? DEFAULT_NAMESPACE;
  const chunkChars = opts.chunkChars ?? DEFAULT_CHUNK_CHARS;
  if (typeof namespace !== 'string' || !NAMESPACE_PATTERN.test(namespace)) {
    throw new UmisError('INVALID_ARGUMENT', 'the namespace is 1 to 32 characters of A-Z, a-z, 0-9, "_" and "-"');
  }
  if (!Number.isInteger(chunkChars) || chunkChars < MIN_CHUNK_CHARS || chunkChars > MAX_CHUNK_CHARS) {
    throw new UmisError(
      'INVALID_ARGUMENT',
      `chunkChars is a whole number from ${MIN_CHUNK_CHARS} to ${MAX_CHUNK_CHARS}`,
    );
  }

  const indexKey = `${namespace}.creds.index`;
  const countKey = (id: string): string => `${namespace}.cred.${id}.n`;
  const pieceKey = (id: string, set: PieceSet, n: number): string =>
    `${namespace}.cred.${id}.${set === 'b' ? 'b' : ''}${n}`;

  async function readIndex(): Promise<string[]> {
    const text = await SecureStore.getItemAsync(indexKey);
    if (text === null) return [];
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch (cause) {
      throw new UmisError('MALFORMED', 'the credential index is not JSON', { cause });
    }
    if (!Array.isArray(value) || !value.every((id) => typeof id === 'string' && ID_PATTERN.test(id))) {
      throw new UmisError('MALFORMED', 'the credential index is not a list of credential ids');
    }
    return value as string[];
  }

  async function writeIndex(ids: readonly string[]): Promise<void> {
    const text = JSON.stringify(ids);
    if (text.length > MAX_INDEX_CHARS) {
      throw new UmisError('INVALID_ARGUMENT', 'the wallet holds as many credentials as its index can list');
    }
    await SecureStore.setItemAsync(indexKey, text, STORE_OPTIONS);
  }

  /** The count record: where the pieces are and how many, `null` when there is no usable record. */
  async function readPieces(id: string): Promise<Pieces | null> {
    const text = await SecureStore.getItemAsync(countKey(id));
    const match = text === null ? null : /^([0-9]{1,4})(b?)$/.exec(text);
    if (match === null) return null;
    const count = Number(match[1]);
    return count >= 1 && count <= MAX_CHUNKS ? { set: match[2] === 'b' ? 'b' : 'a', count } : null;
  }

  const countText = ({ set, count }: Pieces): string => (set === 'b' ? `${count}b` : String(count));

  /** From the last piece down, so that a deletion cut short leaves pieces from 0 on, which `sweep` finds. */
  async function deletePieces(id: string, { set, count }: Pieces): Promise<void> {
    for (let n = count - 1; n >= 0; n--) await SecureStore.deleteItemAsync(pieceKey(id, set, n));
  }

  /**
   * Deletes the pieces that the count record does not name: the whole set it does not point to (both sets when there is
   * no record) and those of its own set from `live.count` on. They are left by a clean-up that failed or was cut short,
   * and they always start at the lowest number of their range, so each range is read upwards until a piece is missing.
   */
  async function sweep(id: string, live: Pieces | null): Promise<void> {
    const ranges: Array<[PieceSet, number]> =
      live === null
        ? [
            ['a', 0],
            ['b', 0],
          ]
        : [
            [live.set === 'a' ? 'b' : 'a', 0],
            [live.set, live.count],
          ];
    for (const [set, start] of ranges) {
      let end = start;
      while (end < MAX_CHUNKS && (await SecureStore.getItemAsync(pieceKey(id, set, end))) !== null) end += 1;
      for (let n = end - 1; n >= start; n--) await SecureStore.deleteItemAsync(pieceKey(id, set, n));
    }
  }

  /**
   * A new credential that never reached the index leaves nothing behind. A failed index write may still have landed, so
   * the index is read again first: a credential that it lists is kept, and nothing is deleted when it cannot be read.
   */
  async function discard(id: string, written: Pieces): Promise<void> {
    const ids = await readIndex().catch(() => undefined);
    if (ids === undefined || ids.includes(id)) return;
    await SecureStore.deleteItemAsync(countKey(id)).catch(() => undefined);
    await deletePieces(id, written).catch(() => undefined);
  }

  /**
   * After a failed write over a stored credential the count record says what is stored, and the pieces of the set it
   * does not name are surplus. A write that failed may still have landed, so the record is read again before anything
   * is deleted, and nothing is deleted when it cannot be read.
   */
  async function dropSurplus(id: string, written: Pieces, former: Pieces | null): Promise<void> {
    const stored = await readPieces(id).catch(() => undefined);
    if (stored === undefined) return;
    const surplus = stored?.set === written.set ? former : written;
    if (surplus !== null) await deletePieces(id, surplus).catch(() => undefined);
  }

  async function read(id: string): Promise<StoredCredential> {
    const stored = await readPieces(id);
    if (stored === null) throw new UmisError('MALFORMED', `the pieces of credential "${id}" are missing`);
    const pieces = await Promise.all(
      Array.from({ length: stored.count }, (_, n) => SecureStore.getItemAsync(pieceKey(id, stored.set, n))),
    );
    if (pieces.some((piece) => piece === null)) {
      throw new UmisError('MALFORMED', `a piece of credential "${id}" is missing`);
    }
    let value: unknown;
    try {
      value = JSON.parse(utf8Decode(base64urlDecode(pieces.join(''))));
    } catch (cause) {
      throw new UmisError('MALFORMED', `credential "${id}" cannot be read`, { cause });
    }
    const credential = checkCredential(value, 'MALFORMED');
    if (credential.id !== id)
      throw new UmisError('MALFORMED', `the pieces of credential "${id}" belong to another one`);
    return credential;
  }

  return {
    list: () =>
      exclusively(namespace, async () => {
        const credentials: StoredCredential[] = [];
        for (const id of await readIndex()) {
          try {
            credentials.push(await read(id));
          } catch (error) {
            if (!(error instanceof UmisError && error.code === 'MALFORMED')) throw error;
          }
        }
        return credentials;
      }),

    get: (id) =>
      exclusively(namespace, async () => {
        checkId(id);
        return (await readIndex()).includes(id) ? read(id) : null;
      }),

    put: (c) =>
      exclusively(namespace, async () => {
        const credential = checkCredential(c, 'INVALID_ARGUMENT');
        const text = base64urlEncode(utf8Encode(JSON.stringify(credential)));
        const count = Math.ceil(text.length / chunkChars);
        if (count > MAX_CHUNKS) throw new UmisError('INVALID_ARGUMENT', 'the credential is too large to store');
        const { id } = credential;
        const ids = await readIndex();
        const known = ids.includes(id);
        const before = await readPieces(id);
        // The pieces go to the set that the count record does not name, so nothing that is stored is written over. For
        // a credential that is stored, writing the count record is the single step that replaces it.
        const next: Pieces = { set: before?.set === 'a' ? 'b' : 'a', count };
        try {
          for (let n = 0; n < count; n++) {
            await SecureStore.setItemAsync(
              pieceKey(id, next.set, n),
              text.slice(n * chunkChars, (n + 1) * chunkChars),
              STORE_OPTIONS,
            );
          }
          await SecureStore.setItemAsync(countKey(id), countText(next), STORE_OPTIONS);
          if (!known) await writeIndex([...ids, id]);
        } catch (error) {
          await (known ? dropSurplus(id, next, before) : discard(id, next));
          throw error;
        }
        // The old pieces are surplus now; failing to delete them does not undo the replacement, and the next put or remove
        // of this id deletes what is left.
        if (before !== null) await deletePieces(id, before).catch(() => undefined);
        await sweep(id, next).catch(() => undefined);
      }),

    remove: (id) =>
      exclusively(namespace, async () => {
        checkId(id);
        const ids = await readIndex();
        const stored = await readPieces(id);
        if (ids.includes(id)) await writeIndex(ids.filter((known) => known !== id));
        // The count record goes last: until then it tells a removal that was cut short which pieces are still there.
        if (stored !== null) await deletePieces(id, stored);
        await sweep(id, stored);
        await SecureStore.deleteItemAsync(countKey(id));
      }),
  };
}

function checkId(id: unknown): asserts id is string {
  if (typeof id !== 'string' || !ID_PATTERN.test(id)) {
    throw new UmisError('INVALID_ARGUMENT', 'a credential id is 1 to 64 characters of A-Z, a-z, 0-9, "_" and "-"');
  }
}

/** The fields of a credential as the wallet keeps them; anything else is dropped. */
function checkCredential(value: unknown, code: 'INVALID_ARGUMENT' | 'MALFORMED'): StoredCredential {
  const fail = (what: string): never => {
    throw new UmisError(code, `a stored credential needs ${what}`);
  };
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return fail('to be an object');
  const fields = value as Record<string, unknown>;
  const text = (name: string): string => {
    const field = fields[name];
    return typeof field === 'string' && field !== '' ? field : fail(`${name} as a non-empty string`);
  };
  const id = text('id');
  if (!ID_PATTERN.test(id)) fail('an id of 1 to 64 characters of A-Z, a-z, 0-9, "_" and "-"');
  const receivedAt = fields.receivedAt;
  if (typeof receivedAt !== 'number' || !Number.isFinite(receivedAt)) fail('receivedAt as a number');
  const label = fields.label;
  if (label !== undefined && typeof label !== 'string') fail('label as a string when present');
  const credential: StoredCredential = {
    id,
    sdJwtVc: text('sdJwtVc'),
    vct: text('vct'),
    issuer: text('issuer'),
    keyAlias: text('keyAlias'),
    receivedAt: receivedAt as number,
  };
  if (typeof label === 'string') credential.label = label;
  return credential;
}
