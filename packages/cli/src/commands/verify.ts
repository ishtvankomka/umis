import { parseArgs } from 'node:util';
import { UmisError } from '@umis/core';
import type { VerifierContext } from '@umis/core';
import type { DEFAULT_POLICIES } from '@umis/policy';
import { createDemoWorld } from '@umis/testkit';
import type { OrgSlug } from '@umis/testkit';
import { createMemoryReplayStore, deserializeVerifierContext, verifyAtCheckpoint } from '@umis/verifier';
import type { SerializedVerifierContextV1 } from '@umis/verifier';
import { EXIT, UsageError, epochSeconds, inputText, readJsonFile, runCommand } from './common.js';
import type { CommandIo } from './common.js';

export const VERIFY_USAGE = `usage: umis verify (--demo <org>:<policy> | --context <file>) [--now <epoch>] [<frame> | -]

Decides at a checkpoint whether a one-way or a full QR frame is accepted, offline, and prints the result as JSON.
The frame is the text of the QR code; give - (or nothing, with the text piped in) to read it from standard input.

options:
  --demo <org>:<policy>  decide in the demo world: org is pidriadnyk-a, postachalnyk-b or kovorking-v, policy is
                         door_low, warehouse_medium, mutual_medium or login_oid4vp, for example kovorking-v:door_low
  --context <file>       decide with a verifier context saved as JSON (a serialized verifier context)
  --now <epoch>          the time of the decision, in seconds since 1970-01-01; the default is the time recorded in the
                         context (for --demo, the start of the demo world, 1793606400), so a command line gives the
                         same answer on any day
  -h, --help             show this text

Every run starts with an empty replay store. Exit code 0 when the frame is accepted, 2 when it is rejected, 64 for a
mistake in the arguments.`;

async function demoContext(spec: string, now: number | undefined): Promise<VerifierContext> {
  const parts = spec.split(':');
  const [org, policy] = parts;
  if (parts.length !== 2 || org === '' || policy === '' || org === undefined || policy === undefined) {
    throw new UsageError('--demo takes <org>:<policy>, for example kovorking-v:door_low');
  }
  const world = await createDemoWorld();
  if (now !== undefined) world.clock.set(now);
  // the world names the valid organisations and policies when it refuses one
  return world.context({ org: org as OrgSlug, policy: policy as keyof typeof DEFAULT_POLICIES });
}

async function fileContext(file: string, now: number | undefined): Promise<VerifierContext> {
  const document = (await readJsonFile(file, 'the context file')) as SerializedVerifierContextV1;
  try {
    return deserializeVerifierContext(document, {
      replay: createMemoryReplayStore(),
      ...(now === undefined ? {} : { now }),
    });
  } catch (error) {
    if (error instanceof UmisError)
      throw new UsageError(`${file} is not a serialized verifier context: ${error.message}`);
    throw error;
  }
}

/**
 * `umis verify`: decides on one QR frame with a demo or a saved verifier context and prints the verification result.
 * Returns 0 for accept, 2 for reject, 64 for a mistake in the arguments.
 */
export async function verify(args: readonly string[], io: CommandIo): Promise<number> {
  return runCommand('verify', io, async () => {
    const { values, positionals } = parseArgs({
      args: [...args],
      allowPositionals: true,
      strict: true,
      options: {
        demo: { type: 'string' },
        context: { type: 'string' },
        now: { type: 'string' },
        help: { type: 'boolean', short: 'h' },
      },
    });
    if (values.help === true) {
      io.out(VERIFY_USAGE);
      return EXIT.ok;
    }
    if ((values.demo === undefined) === (values.context === undefined)) {
      throw new UsageError('give one of --demo <org>:<policy> and --context <file>');
    }
    const now = values.now === undefined ? undefined : epochSeconds(values.now, '--now');
    const context =
      values.demo !== undefined ? await demoContext(values.demo, now) : await fileContext(values.context!, now);
    const frame = await inputText(positionals, io, 'the frame');

    const result = await verifyAtCheckpoint(frame, context);
    io.out(JSON.stringify(result, null, 2));
    return result.decision === 'accept' ? EXIT.ok : EXIT.rejected;
  });
}
