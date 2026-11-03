# @umis/testkit

A demo world for the UMIS v1 profile and a runner for its hero scenario.

The world has three invented organisations (a contractor, a supplier and a coworking space), three people with
credentials, signed trusted-issuer registries, status lists and a simulated clock. It needs no network and no server,
and it is the same on every run: keys, credentials, identifiers and signatures are derived from fixed seeds.

The keys come from public seeds and protect nothing. Use the package for demos, tests and test vectors, never for
real credentials.

## The hero scenario

```ts
import { runHero } from '@umis/testkit';

const rows = await runHero(); // the four steps below; `{ steps: [3, 1] }` runs some of them, in that order
```

| Step | Who shows, who decides       | Result                                                          |
| ---- | ---------------------------- | --------------------------------------------------------------- |
| 1    | Олег Бондар, Коворкінг В     | accept: a one-way QR code at the door, decided from the cache   |
| 2    | Олег Бондар, Постачальник Б  | accept: 10 t of rebar, within his authority                     |
| 2    | Іван Мельник, Постачальник Б | reject `AUTHORITY_LIMIT_EXCEEDED`: 8 t were delegated to him    |
| 3    | Олег Бондар, Постачальник Б  | accept: a mutual exchange, the first direction                  |
| 3    | Марія Коваль, Підрядник А    | accept: the second direction                                    |
| 4    | Олег Бондар, Acme Intranet   | accept: an OpenID4VP login that discloses only `org` and `role` |

Every row also carries the QR text that was checked (`frame`, `frameChars`), the time the verifier took (`ms`) and the
outcome the scenario expects (`expected`). Step 4 is played in this process: the intranet makes a request with
`createVpRequest`, the wallet of Олег answers it with `respondToVpRequest`, and `verifyVpResponse` decides, with the
status lists served from memory by a function that stands in for `fetch`.

## The world

```ts
import { createDemoWorld } from '@umis/testkit';

const world = await createDemoWorld(); // starts at 2026-11-02T08:00:00Z on the clock of the world
const context = world.context({ org: 'kovorking-v', policy: 'door_low' }); // what that door decides with

world.revoke(jti); // marks a credential revoked, and every credential delegated from it
world.clock.advance(600);
await world.publish(); // signs every status list again at the time of the clock
```

`world.orgs`, `world.people` and `world.crypto` give the organisations with their keys and registries, the people with
their credentials and holder keys, and the provider the world was made with. `deterministicCrypto(seed)` is that
provider: ES256 with RFC 6979 signatures and a random source that repeats itself.

## Benchmarks

`runBench` measures how long a verifier takes to decide on a presentation, on the demo world, and plays two timelines on
the simulated clock. It is the engine of `umis bench` and needs Node.js.

```ts
import { runBench } from '@umis/testkit';

const summaries = await runBench({
  scenarios: ['oneway-low', 'full-qr-low', 's1-accept', 's1-reject', 'mutual', 'oid4vp', 'gateway'],
  n: 1000, // presentations in one repeat
  repeats: 30, // repeats that are measured
  warmup: 1, // repeats that are run first and thrown away
  crypto: 'webcrypto', // or 'noble', the JavaScript implementation that stands in for the engine of Expo Go
  seed: 'umis', // fixes keys, identifiers and salts; WebCrypto signatures stay random
  out: 'bench-results/webcrypto', // a new or empty folder
});
```

`runBench` returns the summary of every scenario. It rejects with `PROTOCOL`, once the files are written, when a
presentation is decided otherwise than its scenario expects or a timeline is off. `benchReport` writes the same files
and returns the whole report instead of rejecting: the summaries, the two autonomy timelines, the revocation timeline
and `ok`, which is true when no presentation came to another decision than the scenario expects and both timelines
hold. Both take hooks as a second argument: `progress` hears what the run is doing, and `signal` stops it between two
repeats.

| Scenario      | What is decided                                                                       | Expected                          |
| ------------- | ------------------------------------------------------------------------------------- | --------------------------------- |
| `oneway-low`  | a one-way QR code at the door, from the member cache                                  | accept                            |
| `full-qr-low` | a full presentation as a QR code at the door                                          | accept                            |
| `s1-accept`   | the warehouse asks for 10 t of rebar and Олег, who holds 10 t, answers                | accept                            |
| `s1-reject`   | the same request, answered by Іван, who holds 8 t                                     | reject `AUTHORITY_LIMIT_EXCEEDED` |
| `mutual`      | both decisions of a mutual exchange                                                   | accept                            |
| `oid4vp`      | an OpenID4VP login, with the status lists fetched from memory                         | accept                            |
| `gateway`     | the decision of the door and a signed relay command to an emulator over loopback HTTP | accept                            |

Protocol. In every repeat `n` different presentations are made first, which is not timed, and then decided one after the
other against a new replay store; the time of a decision is taken with `performance.now()` around the one call that
decides. The warm-up repeats are thrown away. Every presentation is checked against the decision the scenario expects,
the warm-up ones included, and a different decision is counted as a mismatch, never averaged away. Nothing in a
timeline reads the wall clock: the clock of the world is set and advanced by the run.

Files in `out`:

| File                     | Content                                                                                                                                                             |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `env.json`               | Node.js, system, processor, memory, load average, commit and package versions, the options                                                                          |
| `summary.json`           | the summary of every scenario and the report of the timelines; written last                                                                                         |
| `samples-<scenario>.csv` | `repeat,i,ms,decision,reason` for every timed presentation                                                                                                          |
| `steps-<scenario>.csv`   | the mean time of each of the nine steps of the pipeline                                                                                                             |
| `sizes.csv`              | characters of every QR text per scenario: count, minimum, median, maximum                                                                                           |
| `autonomy-low.csv`       | 80 hours at the door, a presentation every 5 minutes: `t,age_s,decision,reason`                                                                                     |
| `autonomy-medium.csv`    | 30 hours at the warehouse, the same; `STATUS_LIST_STALE` starts exactly one second after S                                                                          |
| `revocation.csv`         | `t,online,offline`: the reason an online and an offline verifier give for the revoked credential; the first refusal is within Δ online and within min(T; S) offline |

`ScenarioSummary` holds the percentiles (`p50`, `p95`, `p99`), `mean`, `sd`, `min`, `max`, the 95 % interval of the mean
of the p95 of the repeats (`p95Ci95`, Student t), `mismatches`, `nfrP1Pass` (the p95 over all presentations is at most
one second) and the characters of the QR text (`frameChars`). `percentile(sorted, p)` is the nearest rank and
`meanCi95(values)` the interval; both are exported.

With `emitFrames` the run also writes a file `{ v: 1, now, context, payloads }` of `n` one-way QR codes of the door and the
context to decide on them (read it back with `deserializeVerifierContext`), for replaying the same frames against
another verifier. The results of a run belong to the machine that made them: they are not committed to the repository.

## Test vectors

`pnpm -F @umis/testkit gen:vectors` writes `test-vectors/umis-profile-v1.json` at the root of the repository: the issuer
public keys, one credential of each type, one presentation for every channel (one-way QR, full QR, request and response
QR, BLE bytes, OpenID4VP), the verifier contexts they are decided in and the expected decisions. The file holds public
keys only and is identical on every run.
