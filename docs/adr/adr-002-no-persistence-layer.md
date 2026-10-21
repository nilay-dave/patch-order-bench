# ADR 002: no persistence layer

Status: accepted
Date: 2026-10-20

## Context

The plan for this project included a Parquet cache for generated corpora. Corpus
generation is the single most expensive step in the pipeline: at 500,000 findings it
takes <!--number:runtime[2].generate_seconds-->7.57<!--/number--> seconds against
<!--number:runtime[2].slowest_seconds-->2.88<!--/number--> for the slowest of the
eight orderings. The benchmark regenerates a corpus once per seed per experiment,
and pyarrow was already a dependency for reading scanner exports that ship as
Parquet. Caching looked free, and it looked like it would pay for itself on the
slowest thing here.

## Decision

Do not build it. Corpora are either reproducible from a seed or already on disk as
the user's CSV. There is nothing to persist that is not cheaper to recompute than
to invalidate.

## Why the obvious optimisation is the wrong one here

A cache is correct when recomputation is expensive and the inputs are stable. Here
the opposite holds on both counts.

**Recomputation is cheap, and the cache key is not.** A corpus is a pure function of
`CorpusSpec` plus a seed. The spec has fourteen fields, several of them floats. A
correct cache key is a hash of all of them, and every future field added to the
spec is a field somebody has to remember to put in the key. Forget one and the
cache returns a corpus generated under different assumptions, silently, and every
number downstream is wrong in a way no test catches, because the test and the stale
entry agree with each other. The failure mode of the cache is worse than the cost
it removes.

**The cache would never hit.** This is the one that settles it. Generation is
expensive, but the benchmark never generates the same corpus twice: each seed is a
different corpus by definition, and each point in the sensitivity sweep is a
different spec. A cache whose keys are all distinct is a write only cache. It would
pay the cost of serialising every corpus to disk, in exchange for a hit rate of
zero, and would leave behind a directory of large files nobody reads.

At the scale the published results actually run, 5,000 findings, generation takes
<!--number:runtime[0].generate_seconds-->0.051<!--/number--> seconds. The argument
for caching was built on the 500,000 finding row of a scaling table that exists to
show the tool does not fall over, not on the workload the benchmark runs.

**The real input is a CSV the user already has.** For the path that matters, a
scanner export on disk, Parquet adds a conversion step and a second copy of the
user's vulnerability data, which is a thing to secure and a thing to delete. Reading
the CSV each time is slower and is nobody's bottleneck at the sizes a single
scanner export reaches.

## Consequences

- `pob generate` writes a CSV when asked to and otherwise holds the corpus in
  memory. There is no cache directory, no cache invalidation, and no state between
  runs.
- Reproducibility comes from the seed, which is printed in every result and
  recorded in `docs/metrics.json`, rather than from a stored artefact.
- pyarrow stays a dependency, for reading Parquet exports from scanners that
  produce them. It is not used to write anything.
- If corpus generation ever becomes the bottleneck, the fix is to make the generator
  faster, which is a change with no correctness surface, rather than to remember
  more fields in a cache key.

## Note on how this was recorded

The planning document for this project said "Parquet over a database" as the
persistence decision. No persistence layer was built, so recording that decision
would have described a thing that does not exist in the repository. This ADR records
the decision actually taken.
