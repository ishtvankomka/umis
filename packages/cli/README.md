# @umis/cli

The `umis` command-line tool: a demo of the hero scenario, offline verification and inspection of QR frames, key
generation, an emulator of a Shelly Gen3 relay and a benchmark of the verifier.

| Command                                                                                  | What it does                                                             |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `umis demo [--steps 1,2,3,4] [--qr] [--json]`                                            | runs the hero steps on the demo world and prints a table                 |
| `umis verify (--demo <org>:<policy> \| --context <file>) [--now <epoch>] [<frame> \| -]` | decides whether a one-way or full QR frame is accepted, offline          |
| `umis inspect [<text> \| -]`                                                             | tells what a QR text, link or token is and decodes it, verifying nothing |
| `umis keygen --out <dir>`                                                                | makes a P-256 key pair and prints the public key, key id and fingerprint |
| `umis relay-emu --trust <file> [options]`                                                | runs an emulator of a relay that obeys only signed commands              |
| `umis bench [options]`                                                                   | measures the decision latency of the verifier and plays two timelines    |

Run `umis <command> --help` for the options.

## Try it from a clone

```sh
pnpm install
pnpm build
pnpm -F cli exec umis demo
pnpm -F cli exec umis demo --steps 1 --qr
```

`umis demo` prints a row for every decision (step, actor, decision, reason, milliseconds, characters of the QR text);
step 4 is a login at an intranet over OpenID4VP, played in the same process.
`umis verify --demo kovorking-v:door_low --now 1793606400 -` decides on a one-way frame read from standard input, with
the demo door of the coworking space, at the given time; a saved verifier context from `serializeVerifierContext` takes
the place of `--demo` as `--context <file>`.

## Benchmark

```sh
pnpm -F cli exec umis bench --n 50 --repeats 3 --out /tmp/umis-bench-smoke    # a short run, to see that it works
pnpm -F cli exec umis bench --crypto webcrypto --out bench-results/webcrypto  # n 1000, 30 repeats, 1 warm-up
pnpm -F cli exec umis bench --crypto noble --out bench-results/noble
```

`umis bench` times how long a verifier takes to decide, on the demo world, for seven scenarios (`--scenario all`, or
names separated by commas: `oneway-low`, `full-qr-low`, `s1-accept`, `s1-reject`, `mutual`, `oid4vp`, `gateway`). In
every repeat `--n` different presentations are made first, which is not timed, and then decided one after the other;
`--repeats` repeats are measured after `--warmup` thrown away. `--crypto webcrypto` is the platform's implementation and
`--crypto noble` the JavaScript one that stands in for the engine of Expo Go. The table has the median, p95 with the 95 %
interval of the repeats, p99, mean, standard deviation and maximum in milliseconds, the characters of the QR text, the
presentations decided otherwise than expected and whether the p95 is within one second. Under it come the autonomy of the
door (80 hours) and of the warehouse (30 hours) and the revocation, played on a simulated clock.

`--out <dir>` (default `bench-results/<UTC time>`, a folder that is new or empty) receives `env.json`, `summary.json`,
`samples-<scenario>.csv`, `steps-<scenario>.csv`, `sizes.csv`, `autonomy-low.csv`, `autonomy-medium.csv` and
`revocation.csv`; `--emit-frames <file>` also writes one-way QR codes of the door with the context to decide on them.
Progress goes to standard error, the table to standard output. A full run takes minutes with WebCrypto and much longer
with noble, which signs and verifies in JavaScript; it is best made on a machine that is otherwise idle.

## Exit codes

| Code | Meaning                                                                                                                                               |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | success: every row of the demo is as expected, the frame is accepted, the text is decoded, the benchmark finds nothing off                            |
| 2    | the answer asked for is no: an unexpected demo row, a rejected frame, a text that cannot be decoded, a benchmark presentation or timeline that is off |
| 64   | a mistake in the arguments or in a file they name                                                                                                     |
| 1    | any other failure                                                                                                                                     |

## Keys

`umis keygen` writes `key.private.jwk.json` (readable by its owner only) and `key.public.jwk.json`, and never prints the
private key. It does not overwrite existing files. Environment variables, where a command takes one, are named, never
passed as values.
