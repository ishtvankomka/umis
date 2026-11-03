import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

/** A value of one CSV field. */
export type Cell = string | number;

function field(value: Cell): string {
  const text = typeof value === 'number' ? String(value) : value;
  return /["\r\n,]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

/** CSV text (RFC 4180 quoting, one line feed after every line, the header first). */
export function csvText(header: readonly string[], rows: Iterable<readonly Cell[]>): string {
  const lines = [header.map(field).join(',')];
  for (const row of rows) lines.push(row.map(field).join(','));
  return `${lines.join('\n')}\n`;
}

/** JSON text, indented by two spaces, with one line feed at the end. */
export function jsonText(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/** Writes `text` to `path` and makes the folders on the way. */
export async function writeText(path: string, text: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, text, 'utf8');
}

/** Milliseconds with four decimals, a tenth of a microsecond: the resolution of every figure that is written. */
export function ms4(value: number): string {
  return value.toFixed(4);
}
