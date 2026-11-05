---
'@umis/testkit': minor
'@umis/cli': minor
---

Report the mean of the per-repeat p95 as `p95Mean` and leave `p95Ci95` and `meanCi95` without an interval (`null`) for a single repeat, add the `P95 REP` column, the `n/a` interval and the notes for the rows that are not one decision alone to `umis bench`, and record the commit of a benchmark run only inside this repository's work tree.
