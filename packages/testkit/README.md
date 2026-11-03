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

const rows = await runHero({ steps: [1, 2, 3] });
```

| Step | Who shows, who decides       | Result                                                        |
| ---- | ---------------------------- | ------------------------------------------------------------- |
| 1    | Олег Бондар, Коворкінг В     | accept: a one-way QR code at the door, decided from the cache |
| 2    | Олег Бондар, Постачальник Б  | accept: 10 t of rebar, within his authority                   |
| 2    | Іван Мельник, Постачальник Б | reject `AUTHORITY_LIMIT_EXCEEDED`: 8 t were delegated to him  |
| 3    | Олег Бондар, Постачальник Б  | accept: a mutual exchange, the first direction                |
| 3    | Марія Коваль, Підрядник А    | accept: the second direction                                  |

Every row also carries the QR text that was checked (`frame`, `frameChars`), the time the verifier took (`ms`) and the
outcome the scenario expects (`expected`).

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

## Test vectors

`pnpm -F @umis/testkit gen:vectors` writes `test-vectors/umis-profile-v1.json` at the root of the repository: the issuer
public keys, one credential of each type, one presentation for every channel (one-way QR, full QR, request and response
QR, BLE bytes, OpenID4VP), the verifier contexts they are decided in and the expected decisions. The file holds public
keys only and is identical on every run.
