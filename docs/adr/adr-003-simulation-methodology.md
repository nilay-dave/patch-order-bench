# ADR 003: how the simulation earns the right to a number

Status: accepted
Date: 2026-10-20

## Context

Every figure this project publishes is a simulation. The live feed path in
`pob.feeds` exists, has tests against recorded responses, and has never been run
against the real feeds, because the environment it was built in cannot reach
`epss.cyentia.com` or `cisa.gov`. That is stated in `docs/metrics.json`, in the
README, and here, because a simulated number presented as a measured one is the
single most damaging thing a project like this can do.

A simulation of a backlog can produce any result its author wants by choosing
parameters. The methodology below is the set of constraints that make the output
worth reading, and each one was added because the undisciplined version of the
measurement was wrong.

## Decision

### Sourced and chosen parameters are labelled separately

`CorpusSpec.describe()` splits its parameters into three groups: sourced, chosen,
and scale. Exactly one parameter is sourced, from FIRST's EPSS model documentation:
<!--number:corpus_spec.sourced.share_epss_above_0_1-->0.0268<!--/number--> of CVSS
3.x CVEs score at or above EPSS 0.1. Everything else is a declared choice. Printing
them in separate groups stops a reader from inferring that the whole distribution
came from somewhere.

The realized values are reported next to the targets, because a generator does not
necessarily produce what it was asked for. The realized share at or above 0.1 came
out at
<!--number:headline.corpus.mean_share_epss_above_0_1-->0.0235<!--/number--> against
the sourced <!--number:corpus_spec.sourced.share_epss_above_0_1-->0.0268<!--/number-->,
and the realized rank correlation at
<!--number:headline.corpus.mean_realized_rank_correlation-->0.225<!--/number-->
against a requested 0.25. Those are the numbers the comparison actually ran on.

### The parameter the conclusion depends on is swept, not argued for

The correlation between severity and exploitation probability is unknown and
decides the whole comparison: at a correlation of 1, ranking by severity and
ranking by exploitation probability are the same ranking. Experiment B sweeps it
from 0.0 to 1.0 and reports the verdict at each point. The conclusion holds across
the range and the two orderings converge at the top of it, which is what should
happen if the mechanism is the one claimed. A sweep that produced the same verdict
at every point including correlation 1.0 would be evidence of a bug, not of
robustness.

Early on it did exactly that, because the verdict function called a gap of 0.003 a
win. It now requires a margin of 0.02 before calling either side ahead, and reports
a tie otherwise.

### Results are averaged over seeds, and the spread is published

Twelve seeds, and the spread across them in the same table as the mean.

This is the rule that cost the project its best headline. A single seed showed the
severity ordering covering 0.085 of the known exploited findings against a shuffled
backlog's 0.211, which reads as "ranking by CVSS is worse than ranking at random",
and which is the most quotable sentence this benchmark could have produced. Over
twelve seeds it is
<!--number:headline.orderings.cvss.kev_coverage-->0.382<!--/number--> against
<!--number:headline.orderings.random.kev_coverage-->0.211<!--/number-->. The
striking version was noise. Its spread across seeds is
<!--number:headline.orderings.cvss.kev_coverage_spread-->0.645<!--/number-->, wide
enough that single runs land almost anywhere, which is why the spread column exists
and why twelve seeds is stated as a limitation rather than as sufficiency.

### Ceilings are capacity aware

Window attainment is reported as a share of what is reachable, not of the backlog.
<!--number:headline.corpus.mean_already_past_window-->3,248<!--/number--> findings
are past their window on day one and no ordering can bring them back, and a
programme with finite capacity cannot reach every remaining deadline either. The
ceiling is computed by a greedy earliest deadline first pass over the findings whose
deadlines are still reachable at the given capacity, which gives
<!--number:headline.corpus.mean_window_attainment_ceiling-->170<!--/number-->
findings.

The first version of this ignored capacity and reported a ceiling of 510, which
understated every ordering's attainment by a factor of three. A denominator nobody
can reach makes every ordering look equally bad, which conveniently flatters the
comparison the project was making.

### Capacity holds its ratio to the backlog across scales

The sweep and the headline run at the same capacity share of the backlog. They did
not at first, and a shuffled baseline that should have matched the headline's
<!--number:headline.orderings.random.kev_coverage-->0.211<!--/number--> came out at
0.54, because the sweep was giving the programme more capacity per finding. Two
numbers in the same document that cannot both be right is the cheapest bug to find
and the most expensive to publish.

## Consequences

- The benchmark takes longer, because twelve seeds times six sweep points times
  eight orderings.
- Every number in `docs/results.md` is generated from `docs/metrics.json` by
  `tools/generate_results_doc.py`, with `--check` in CI, so prose cannot drift from
  the measurement.
- The limitations are a document rather than a sentence. See
  `docs/limitations.md`.
