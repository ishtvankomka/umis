import { UmisError } from '@umis/core';

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);

/**
 * The value at percentile `p` (0 to 100) of `sorted`, a list in ascending order, by the nearest-rank definition: the
 * element at the 1-based rank ceil(p / 100 · n), which is the smallest element for p = 0 and the largest for p = 100.
 * The list is not checked for order.
 */
export function percentile(sorted: readonly number[], p: number): number {
  const n = sorted.length;
  if (n === 0) throw invalid('there is no percentile of an empty list');
  if (typeof p !== 'number' || !Number.isFinite(p) || p < 0 || p > 100) throw invalid('p is a number from 0 to 100');
  // p · n first: for whole numbers the product is exact, so the rank never rounds up by accident
  const rank = Math.ceil((p * n) / 100);
  return sorted[Math.min(n, Math.max(1, rank)) - 1]!;
}

function nonEmpty(values: readonly number[]): void {
  if (values.length === 0) throw invalid('there is no statistic of an empty list');
}

export function mean(values: readonly number[]): number {
  nonEmpty(values);
  let sum = 0;
  for (const value of values) sum += value;
  return sum / values.length;
}

/** The sample standard deviation (divisor n − 1); 0 for a single value. */
export function standardDeviation(values: readonly number[]): number {
  nonEmpty(values);
  if (values.length === 1) return 0;
  const centre = mean(values);
  let squares = 0;
  for (const value of values) squares += (value - centre) ** 2;
  return Math.sqrt(squares / (values.length - 1));
}

/** P(|T| <= t) for Student's t with `df` degrees of freedom (Abramowitz and Stegun 26.7.3 and 26.7.4). */
function centralProbability(t: number, df: number): number {
  const theta = Math.atan(t / Math.sqrt(df));
  if (df === 1) return (2 * theta) / Math.PI;
  const sin = Math.sin(theta);
  const cos = Math.cos(theta);
  const cos2 = cos * cos;
  if (df % 2 === 0) {
    // sin θ · (1 + 1/2 cos²θ + (1·3)/(2·4) cos⁴θ + … + (1·3···(df−3))/(2·4···(df−2)) cos^(df−2)θ)
    let term = 1;
    let sum = 1;
    for (let k = 1; k <= (df - 2) / 2; k++) {
      term *= ((2 * k - 1) / (2 * k)) * cos2;
      sum += term;
    }
    return sin * sum;
  }
  // (2/π) · (θ + sin θ · (cos θ + 2/3 cos³θ + (2·4)/(3·5) cos⁵θ + … + (2·4···(df−3))/(3·5···(df−2)) cos^(df−2)θ))
  let term = cos;
  let sum = cos;
  for (let k = 1; k <= (df - 3) / 2; k++) {
    term *= ((2 * k) / (2 * k + 1)) * cos2;
    sum += term;
  }
  return (2 / Math.PI) * (theta + sin * sum);
}

/** The two-sided 95 % critical value of Student's t for `df` degrees of freedom: the t with P(|T| <= t) = 0.95. */
export function tCritical95(df: number): number {
  if (!Number.isInteger(df) || df < 1) throw invalid('the degrees of freedom are a whole number, 1 or more');
  let low = 0;
  let high = 1;
  while (centralProbability(high, df) < 0.95) high *= 2;
  for (let step = 0; step < 200 && high - low > 1e-13; step++) {
    const middle = (low + high) / 2;
    if (centralProbability(middle, df) < 0.95) low = middle;
    else high = middle;
  }
  return (low + high) / 2;
}

/**
 * The 95 % confidence interval of the mean of `values` by Student's t with n − 1 degrees of freedom:
 * mean ± t · SD / √n. A single value has no spread to estimate, so there is no interval and the result is null.
 */
export function meanCi95(values: readonly number[]): [number, number] | null {
  nonEmpty(values);
  if (values.length === 1) return null;
  const centre = mean(values);
  const half = tCritical95(values.length - 1) * (standardDeviation(values) / Math.sqrt(values.length));
  return [centre - half, centre + half];
}

/** The figures reported for a list of latencies. */
export interface Distribution {
  p50: number;
  p95: number;
  p99: number;
  mean: number;
  sd: number;
  min: number;
  max: number;
}

/** Percentiles by nearest rank, mean, sample SD, minimum and maximum of `values`, in any order. */
export function describe(values: readonly number[]): Distribution {
  nonEmpty(values);
  const sorted = [...values].sort((a, b) => a - b);
  return {
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    mean: mean(sorted),
    sd: standardDeviation(sorted),
    min: sorted[0]!,
    max: sorted[sorted.length - 1]!,
  };
}
