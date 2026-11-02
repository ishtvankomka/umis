import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  GENESIS_HASH,
  TYP,
  canonicalJson,
  chainHash,
  concatBytes,
  createMemoryJournal,
  decodeJwsUnverified,
  generateSigner,
  hexDecode,
  hexEncode,
  signEvent,
  utf8Encode,
  verifyEvent,
  verifyJournal,
  webCryptoProvider,
  type DecisionEventV1,
  type JournalEntry,
} from '../src/index.js';
import { NOW, codeOf, forgeJws, providers } from './fixtures.js';

interface ChainVector {
  genesis: string;
  entries: Array<{ event: DecisionEventV1; canonical: string; prevHash: string; hash: string }>;
}

const vector = JSON.parse(
  readFileSync(new URL('../../../test-vectors/event-chain.json', import.meta.url), 'utf8'),
) as ChainVector;

const ZEROS = '0'.repeat(64);

function event(seq: number, changes: Partial<DecisionEventV1> = {}): DecisionEventV1 {
  return {
    iss: 'urn:umis:verifier:warehouse-b',
    seq,
    iat: NOW + seq * 60,
    chk: 'urn:umis:checkpoint:warehouse-b-gate',
    ch: 'qr_reverse',
    dec: 'accept',
    rsn: ['OK'],
    lat: 80 + seq,
    ...changes,
  };
}

/** Three events: a bare one, a complete one that rejects, and a bare one on another channel. */
const EVENTS: DecisionEventV1[] = [
  event(1),
  event(2, {
    dec: 'reject',
    rsn: ['AUTHORITY_LIMIT_EXCEEDED'],
    vct: 'https://vct.example/role-authority/v1',
    ciss: 'https://issuer.example/contractor-a',
    cref: 'cred-ivan-0001',
    sla: 1_321,
    pv: 3,
  }),
  event(3, { ch: 'ble' }),
];

function journalOf(events: readonly DecisionEventV1[] = EVENTS): JournalEntry[] {
  const journal = createMemoryJournal();
  for (const item of events) journal.append(item);
  return structuredClone(journal.entries()) as JournalEntry[];
}

/** The same entries with one change made by `edit`. */
function tampered(edit: (entries: JournalEntry[]) => void): JournalEntry[] {
  const entries = journalOf();
  edit(entries);
  return entries;
}

describe('canonical JSON (RFC 8785)', () => {
  it('sorts members, drops white space and writes numbers the way ECMAScript does', () => {
    expect(canonicalJson({ b: 1, a: [true, null, 'x'], n: 1.0 })).toBe('{"a":[true,null,"x"],"b":1,"n":1}');
    expect(canonicalJson({ n: 1.0, a: [true, null, 'x'], b: 1 })).toBe('{"a":[true,null,"x"],"b":1,"n":1}');
    expect(canonicalJson([3, { z: 1, a: { y: [], x: {} } }, 'ü'])).toBe('[3,{"a":{"x":{},"y":[]},"z":1},"ü"]');
    expect(canonicalJson('plain')).toBe('"plain"');
    expect(canonicalJson(null)).toBe('null');
    expect(canonicalJson(-0)).toBe('0');
    expect(canonicalJson(Object.assign(Object.create(null) as object, { b: 1, a: 2 }))).toBe('{"a":2,"b":1}');
  });

  it('sorts the members by UTF-16 code units, as in the sample of RFC 8785 section 3.2.3', () => {
    const sample = {
      '€': 'Euro Sign',
      '\r': 'Carriage Return',
      דּ: 'Hebrew Letter Dalet With Dagesh',
      '1': 'One',
      '😀': 'Emoji: Grinning Face',
      '\u0080': 'Control',
      ö: 'Latin Small Letter O With Diaeresis',
    };
    const expected =
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis",' +
      '"€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}';
    expect(canonicalJson(sample)).toBe(expected);
  });

  it('writes the numbers of the table in RFC 8785 appendix B', () => {
    const table: Array<[string, string]> = [
      ['0000000000000000', '0'],
      ['8000000000000000', '0'],
      ['0000000000000001', '5e-324'],
      ['8000000000000001', '-5e-324'],
      ['7fefffffffffffff', '1.7976931348623157e+308'],
      ['ffefffffffffffff', '-1.7976931348623157e+308'],
      ['4340000000000000', '9007199254740992'],
      ['c340000000000000', '-9007199254740992'],
      ['4430000000000000', '295147905179352830000'],
      ['44b52d02c7e14af5', '9.999999999999997e+22'],
      ['44b52d02c7e14af6', '1e+23'],
      ['44b52d02c7e14af7', '1.0000000000000001e+23'],
      ['444b1ae4d6e2ef4e', '999999999999999700000'],
      ['444b1ae4d6e2ef4f', '999999999999999900000'],
      ['444b1ae4d6e2ef50', '1e+21'],
      ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
      ['3eb0c6f7a0b5ed8d', '0.000001'],
      ['41b3de4355555553', '333333333.3333332'],
      ['41b3de4355555554', '333333333.33333325'],
      ['41b3de4355555555', '333333333.3333333'],
      ['41b3de4355555556', '333333333.3333334'],
      ['41b3de4355555557', '333333333.33333343'],
      ['becbf647612f3696', '-0.0000033333333333333333'],
      ['43143ff3c1cb0959', '1424953923781206.2'],
    ];
    for (const [pattern, text] of table) {
      const bytes = hexDecode(pattern);
      const number = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getFloat64(0);
      expect(canonicalJson(number), pattern).toBe(text);
      expect(canonicalJson({ n: number }), pattern).toBe(`{"n":${text}}`);
    }
  });

  it('escapes only what JSON requires and leaves other characters as they are', () => {
    expect(canonicalJson('a"b\\c/d')).toBe('"a\\"b\\\\c/d"');
    expect(canonicalJson('\b\f\n\r\t')).toBe('"\\b\\f\\n\\r\\t"');
    expect(canonicalJson('\u0000\u001f\u007f')).toBe('"\\u0000\\u001f\u007f"');
    expect(canonicalJson('Склад Б —   😀')).toBe('"Склад Б —   😀"');
  });

  it('refuses what JSON cannot say', async () => {
    class Plain {
      readonly a = 1;
    }
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    let deep: unknown = 'bottom';
    for (let level = 0; level < 100; level++) deep = [deep];
    const refused: unknown[] = [
      undefined,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      () => 1,
      Symbol('x'),
      10n,
      new Date(0),
      new Map(),
      new Set(),
      new Uint8Array(2),
      /x/,
      new Plain(),
      { a: undefined },
      { a: { b: [undefined] } },
      { toJSON: () => 'x' },
      [1, , 3], // eslint-disable-line no-sparse-arrays
      cycle,
      deep,
    ];
    for (const value of refused) {
      expect(await codeOf(() => canonicalJson(value)), String(typeof value)).toBe('INVALID_ARGUMENT');
    }
    let fine: unknown = 'bottom';
    for (let level = 0; level < 60; level++) fine = { next: fine };
    expect(canonicalJson(fine).length).toBeGreaterThan(300);
  });
});

describe('the hash chain', () => {
  it('starts from 32 zero bytes', () => {
    expect(GENESIS_HASH).toBeInstanceOf(Uint8Array);
    expect(hexEncode(GENESIS_HASH)).toBe(ZEROS);
  });

  it('is the SHA-256 of the previous hash followed by the canonical event, as an independent digest sees it', async () => {
    for (const item of EVENTS) {
      const prev = Uint8Array.from({ length: 32 }, (_, index) => (index * 7 + item.seq) & 0xff);
      const message = Uint8Array.from(concatBytes(prev, utf8Encode(canonicalJson(item))));
      const independent = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', message));
      expect(chainHash(prev, item)).toEqual(independent);
      expect(await webCryptoProvider.sha256(message)).toEqual(independent);
    }
  });

  it('does not depend on the order of the members, but on every value and on the previous hash', () => {
    const forward = event(1, { vct: 'https://vct.example/a', sla: 5 });
    const reversed = Object.fromEntries(Object.entries(forward).reverse()) as DecisionEventV1;
    expect(chainHash(GENESIS_HASH, reversed)).toEqual(chainHash(GENESIS_HASH, forward));
    expect(chainHash(GENESIS_HASH, event(1, { lat: 82 }))).not.toEqual(chainHash(GENESIS_HASH, event(1)));
    expect(chainHash(chainHash(GENESIS_HASH, event(1)), event(1))).not.toEqual(chainHash(GENESIS_HASH, event(1)));
  });

  it('wants a previous hash of 32 bytes and an event that is a JSON object', async () => {
    for (const prev of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), 'zeros', null, undefined, [0]]) {
      expect(await codeOf(() => chainHash(prev as never, event(1)))).toBe('INVALID_ARGUMENT');
    }
    for (const value of [null, undefined, 'event', 7, [event(1)], { lat: undefined }, { n: Number.NaN }]) {
      expect(await codeOf(() => chainHash(GENESIS_HASH, value as never))).toBe('INVALID_ARGUMENT');
    }
  });

  it('reproduces the chain of the test vector, which was computed outside this package', () => {
    expect(vector.genesis).toBe(ZEROS);
    let previous = hexDecode(vector.genesis);
    for (const row of vector.entries) {
      expect(canonicalJson(row.event)).toBe(row.canonical);
      expect(hexEncode(previous)).toBe(row.prevHash);
      previous = chainHash(previous, row.event);
      expect(hexEncode(previous)).toBe(row.hash);
    }
    expect(vector.entries).toHaveLength(2);
    expect(vector.entries[1]!.event.chk).toBe('urn:umis:checkpoint:склад-б'); //            non-ASCII text is hashed as UTF-8
  });

  it('is what the journal records, and the journal accepts the vector', () => {
    const journal = createMemoryJournal();
    for (const row of vector.entries) {
      const entry = journal.append(row.event);
      expect({ prevHash: entry.prevHash, hash: entry.hash }).toEqual({ prevHash: row.prevHash, hash: row.hash });
    }
    expect(journal.head()).toBe(vector.entries[1]!.hash);
    expect(verifyJournal(vector.entries.map(({ event: e, prevHash, hash }) => ({ event: e, prevHash, hash })))).toEqual(
      {
        ok: true,
      },
    );
  });
});

describe('the journal', () => {
  it('is empty at first, chains what is appended and reports its head', () => {
    const journal = createMemoryJournal();
    expect(journal.entries()).toEqual([]);
    expect(journal.head()).toBe(ZEROS);
    const first = journal.append(EVENTS[0]!);
    const second = journal.append(EVENTS[1]!);
    const third = journal.append(EVENTS[2]!);
    expect(first.prevHash).toBe(ZEROS);
    expect(second.prevHash).toBe(first.hash);
    expect(third.prevHash).toBe(second.hash);
    expect(journal.head()).toBe(third.hash);
    expect(journal.entries()).toEqual([first, second, third]);
    for (const entry of journal.entries()) {
      expect(entry.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.prevHash).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(journal.entries().map((entry) => entry.event)).toEqual(EVENTS);
    expect(verifyJournal(journal.entries())).toEqual({ ok: true });
  });

  it('numbers the events from 1, one after another, and is unchanged by an append that fails', async () => {
    const journal = createMemoryJournal();
    expect(await codeOf(() => journal.append(event(2)))).toBe('INVALID_ARGUMENT');
    expect(await codeOf(() => journal.append(event(0)))).toBe('INVALID_ARGUMENT');
    expect(journal.entries()).toHaveLength(0);
    journal.append(event(1));
    const head = journal.head();
    expect(await codeOf(() => journal.append(event(1)))).toBe('INVALID_ARGUMENT'); //     the same number again
    expect(await codeOf(() => journal.append(event(3)))).toBe('INVALID_ARGUMENT'); //     a gap
    expect(await codeOf(() => journal.append(event(2, { ch: 'telepathy' as never })))).toBe('INVALID_ARGUMENT');
    expect(journal.head()).toBe(head);
    expect(journal.entries()).toHaveLength(1);
    journal.append(event(2));
    expect(journal.entries()).toHaveLength(2);
  });

  it('refuses an event that is not a decision event', async () => {
    const journal = createMemoryJournal();
    const broken: unknown[] = [
      null,
      'event',
      [],
      event(1, { iss: '' }),
      event(1, { ch: 'telepathy' as never }),
      event(1, { dec: 'maybe' as never }),
      event(1, { rsn: [] }),
      event(1, { rsn: ['NO_SUCH_REASON' as never] }),
      event(1, { rsn: 'OK' as never }),
      event(1, { iat: -1 }),
      event(1, { iat: Number.NaN }),
      event(1, { lat: -1 }),
      event(1, { sla: -1 }),
      event(1, { pv: -1 }),
      event(1, { pv: 1.5 }),
      event(1, { vct: '' }),
      { ...event(1), seq: '1' },
      { ...event(1), seq: 1.5 },
    ];
    for (const item of broken) {
      expect(await codeOf(() => journal.append(item as DecisionEventV1)), JSON.stringify(item)).toBe(
        'INVALID_ARGUMENT',
      );
    }
    expect(journal.entries()).toHaveLength(0);
  });

  it('keeps its own frozen copies, so that neither the caller nor a reader can change what it holds', () => {
    const journal = createMemoryJournal();
    const original = event(1);
    const entry = journal.append(original);
    original.dec = 'reject';
    original.rsn.push('AUTHORITY_MISSING');
    expect(journal.entries()[0]!.event).toEqual(event(1));
    expect(verifyJournal(journal.entries())).toEqual({ ok: true });

    expect(() => {
      (entry.event as { dec: string }).dec = 'reject';
    }).toThrow(TypeError);
    expect(() => entry.event.rsn.push('OK')).toThrow(TypeError);
    expect(() => {
      (entry as { hash: string }).hash = ZEROS;
    }).toThrow(TypeError);
    const listing = journal.entries() as JournalEntry[];
    expect(() => listing.push(entry)).toThrow(TypeError);
    expect(journal.entries()).toHaveLength(1);
    expect(verifyJournal(journal.entries())).toEqual({ ok: true });
  });

  it('drops the members it does not know, and the optional ones that are undefined', () => {
    const journal = createMemoryJournal();
    const entry = journal.append({ ...event(1), vct: undefined, extra: { admin: true } } as DecisionEventV1);
    expect(entry.event).toEqual(event(1));
    expect(Object.keys(entry.event)).not.toContain('extra');
    expect(entry.hash).toBe(hexEncode(chainHash(GENESIS_HASH, event(1))));
  });
});

describe('verifying a journal', () => {
  it('accepts three events and the empty journal, however the members of an event are ordered', () => {
    expect(verifyJournal(journalOf())).toEqual({ ok: true });
    expect(verifyJournal([])).toEqual({ ok: true });
    const reordered = tampered((entries) => {
      entries[1]!.event = Object.fromEntries(Object.entries(entries[1]!.event).reverse()) as DecisionEventV1;
    });
    expect(verifyJournal(reordered)).toEqual({ ok: true });
  });

  it('names the entry whose event was edited, whichever field it was', () => {
    const edits: Array<[string, (e: Record<string, unknown>) => void]> = [
      ['iss', (e) => (e.iss = 'urn:umis:verifier:other')],
      ['seq', (e) => (e.seq = 99)],
      ['iat', (e) => (e.iat = (e.iat as number) + 1)],
      ['chk', (e) => (e.chk = 'urn:umis:checkpoint:other')],
      ['ch', (e) => (e.ch = 'oid4vp')],
      ['dec', (e) => (e.dec = e.dec === 'accept' ? 'reject' : 'accept')],
      ['rsn', (e) => (e.rsn = ['OK', 'OK'])],
      ['lat', (e) => (e.lat = (e.lat as number) + 1)],
      ['vct added', (e) => (e.vct = 'https://vct.example/other')],
      ['ciss added', (e) => (e.ciss = 'https://issuer.example/other')],
      ['cref added', (e) => (e.cref = 'cred-other')],
      ['sla added', (e) => (e.sla = 1)],
      ['pv added', (e) => (e.pv = 1)],
      ['an unknown member', (e) => (e.note = 'added afterwards')],
    ];
    for (let index = 0; index < 3; index++) {
      for (const [label, edit] of edits) {
        const entries = tampered((list) => edit(list[index]!.event as unknown as Record<string, unknown>));
        expect(verifyJournal(entries), `${label} of entry ${index}`).toEqual({ ok: false, index });
      }
    }
    const complete = tampered((list) => {
      const second = list[1]!.event as unknown as Record<string, unknown>;
      second.pv = 4;
    });
    expect(verifyJournal(complete)).toEqual({ ok: false, index: 1 });
    for (const field of ['vct', 'ciss', 'cref', 'sla', 'pv']) {
      const removed = tampered((list) => delete (list[1]!.event as unknown as Record<string, unknown>)[field]);
      expect(verifyJournal(removed), `${field} removed`).toEqual({ ok: false, index: 1 });
    }
  });

  it('names the entry where the chain breaks: an edited or exchanged hash, a removed, repeated or reordered entry', () => {
    const flip = (hash: string): string => (hash.startsWith('0') ? '1' : '0') + hash.slice(1);
    expect(verifyJournal(tampered((e) => (e[1]!.hash = flip(e[1]!.hash))))).toEqual({ ok: false, index: 1 });
    expect(verifyJournal(tampered((e) => (e[0]!.prevHash = '1'.repeat(64))))).toEqual({ ok: false, index: 0 });
    expect(verifyJournal(tampered((e) => (e[2]!.prevHash = flip(e[2]!.prevHash))))).toEqual({ ok: false, index: 2 });
    expect(verifyJournal(tampered((e) => void e.splice(1, 1)))).toEqual({ ok: false, index: 1 });
    expect(verifyJournal(tampered((e) => void e.splice(0, 1)))).toEqual({ ok: false, index: 0 });
    expect(verifyJournal(tampered((e) => void e.push(structuredClone(e[2]!))))).toEqual({ ok: false, index: 3 });
    expect(verifyJournal(tampered((e) => void e.splice(1, 0, structuredClone(e[0]!))))).toEqual({
      ok: false,
      index: 1,
    });
    expect(
      verifyJournal(
        tampered((e) => {
          const second = e[1]!;
          e[1] = e[2]!;
          e[2] = second;
        }),
      ),
    ).toEqual({ ok: false, index: 1 });
    expect(verifyJournal(journalOf([event(1, { lat: 90 }), ...EVENTS.slice(1)]).slice(1))).toEqual({
      ok: false,
      index: 0,
    });
  });

  it('sees an edit that recomputes the hash of its own entry at the entry after it', () => {
    const entries = tampered((list) => {
      const forged = { ...list[1]!.event, lat: 1 } as DecisionEventV1;
      list[1] = {
        event: forged,
        prevHash: list[1]!.prevHash,
        hash: hexEncode(chainHash(hexDecode(list[1]!.prevHash), forged)),
      };
    });
    expect(verifyJournal(entries)).toEqual({ ok: false, index: 2 });
    // The last entry has no successor: only a head that was recorded elsewhere shows that it was rewritten.
    const rewrittenLast = tampered((list) => {
      const forged = { ...list[2]!.event, lat: 1 } as DecisionEventV1;
      list[2] = {
        event: forged,
        prevHash: list[2]!.prevHash,
        hash: hexEncode(chainHash(hexDecode(list[2]!.prevHash), forged)),
      };
    });
    expect(verifyJournal(rewrittenLast)).toEqual({ ok: true });
    expect(rewrittenLast[2]!.hash).not.toBe(journalOf()[2]!.hash);
  });

  it('rejects entries of the wrong form and never throws', () => {
    const base = journalOf();
    const cases: Array<[string, unknown, number]> = [
      ['not a list', 'entries', 0],
      ['null', null, 0],
      ['undefined', undefined, 0],
      ['an object with a length', { length: 0 }, 0],
      ['a null entry', [base[0], null, base[2]], 1],
      ['a number as an entry', [base[0], base[1], 3], 2],
      ['an entry without an event', [base[0], { prevHash: base[1]!.prevHash, hash: base[1]!.hash }], 1],
      ['an event that is not an object', [{ ...base[0], event: 'accept' }], 0],
      ['an event that is a list', [{ ...base[0], event: [] }], 0],
      ['an uppercase hash', [{ ...base[0], hash: base[0]!.hash.toUpperCase() }], 0],
      ['a short hash', [{ ...base[0], hash: base[0]!.hash.slice(2) }], 0],
      ['a hash that is not text', [{ ...base[0], hash: 12 }], 0],
      ['a missing prevHash', [{ event: base[0]!.event, hash: base[0]!.hash }], 0],
      ['a prevHash in uppercase', [{ ...base[0], prevHash: ZEROS.toUpperCase().replace(/0/g, 'A') }], 0],
      ['an event with a bigint', [{ ...base[0], event: { ...base[0]!.event, lat: 1n } }], 0],
      ['an event with a cyclic member', [{ ...base[0], event: Object.assign({}, base[0]!.event, { self: {} }) }], 0],
      ['an invalid decision event', [{ ...base[0], event: { ...base[0]!.event, dec: 'maybe' } }], 0],
    ];
    for (const [label, entries, index] of cases) {
      expect(verifyJournal(entries as never), label).toEqual({ ok: false, index });
    }
    const hostile = new Proxy(
      {},
      {
        get: () => {
          throw new Error('refused');
        },
      },
    );
    expect(verifyJournal([hostile] as never)).toEqual({ ok: false, index: 0 });
    const cyclic: Record<string, unknown> = { ...base[0]!.event };
    cyclic.self = cyclic;
    expect(verifyJournal([{ ...base[0]!, event: cyclic }] as never)).toEqual({ ok: false, index: 0 });
  });
});

describe.each(providers)('signed events on %s', (_name, crypto) => {
  it('are signed with the key of the device and read back, with their type umis-event+jwt', async () => {
    const signer = await generateSigner({ crypto, kid: 'device-warehouse-b' });
    const complete = EVENTS[1]!;
    const jws = await signEvent(complete, signer);
    const decoded = decodeJwsUnverified(jws);
    expect(decoded.header).toEqual({ alg: 'ES256', typ: TYP.event, kid: 'device-warehouse-b' });
    expect(decoded.payload).toEqual(complete);
    expect(await verifyEvent(jws, signer.publicJwk, crypto)).toEqual(complete);
    expect(await verifyEvent(await signEvent(EVENTS[0]!, signer), signer.publicJwk, crypto)).toEqual(EVENTS[0]);
  });

  it('are refused under another key, with another type, or with a payload that is not an event', async () => {
    const signer = await generateSigner({ crypto });
    const other = await generateSigner({ crypto });
    const jws = await signEvent(EVENTS[0]!, signer);
    expect(await codeOf(() => verifyEvent(jws, other.publicJwk, crypto))).toBe('SIGNATURE_INVALID');
    const asOneWay = await forgeJws(signer, { alg: 'ES256', typ: TYP.oneWay }, EVENTS[0]!);
    expect(await codeOf(() => verifyEvent(asOneWay, signer.publicJwk, crypto))).toBe('UNSUPPORTED_FORMAT');
    const header = { alg: 'ES256', typ: TYP.event, kid: signer.kid };
    for (const payload of [
      { ...EVENTS[0]!, ch: 'telepathy' },
      { ...EVENTS[0]!, rsn: [] },
      { ...EVENTS[0]!, seq: 0 },
      { iss: 'x' },
      {},
    ]) {
      const forged = await forgeJws(signer, header, payload);
      expect(await codeOf(() => verifyEvent(forged, signer.publicJwk, crypto)), JSON.stringify(payload)).toBe(
        'MALFORMED',
      );
    }
    expect(await codeOf(() => verifyEvent('not a token', signer.publicJwk, crypto))).toBe('MALFORMED');
  });

  it('are not signed when the event is not valid', async () => {
    const signer = await generateSigner({ crypto });
    for (const item of [event(1, { ch: 'telepathy' as never }), event(1, { rsn: [] }), event(0), null, 'event']) {
      expect(await codeOf(() => signEvent(item as DecisionEventV1, signer))).toBe('INVALID_ARGUMENT');
    }
  });

  it('come back without the members the profile does not know', async () => {
    const signer = await generateSigner({ crypto });
    const header = { alg: 'ES256', typ: TYP.event, kid: signer.kid };
    const jws = await forgeJws(signer, header, { ...EVENTS[0]!, injected: { admin: true } });
    expect(await verifyEvent(jws, signer.publicJwk, crypto)).toEqual(EVENTS[0]);
  });
});
