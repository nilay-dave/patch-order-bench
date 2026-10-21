# Limitations

Read this before quoting any number from this project.

## It is a simulation, end to end

No figure here was measured against a real vulnerability backlog. The corpus is
generated, the remediation programme is a model of capacity spent per week, and the
live feed path has never run against the real feeds. `docs/sources.md` lists the
single distributional parameter that has published provenance; everything else is a
declared choice.

What this project can legitimately claim is that under a stated and swept set of
assumptions, these orderings produce these outcomes, and that the code producing
that claim is in the repository and reruns in under a minute. It cannot claim that
a real programme would see these numbers.

## The headline metric is partly a tautology

KEV coverage measures what share of the known exploited findings got remediated,
and the winning orderings are the ones that sort by the KEV flag. Of course they
win. A benchmark where the metric is the sort key is measuring its own definition.

This is why the comparison is not reported on KEV coverage alone. Window attainment
and exposure removed are scored in the same table, no ordering leads on all three,
and the orderings that dominate KEV coverage are near the bottom on windows:
`kev-then-epss` attains
<!--number:headline.orderings.kev-then-epss.window_attainment-->0.084<!--/number-->
against `window-first` at
<!--number:headline.orderings.window-first.window_attainment-->0.649<!--/number-->.
The useful finding is the tension, not the win.

The one place KEV coverage is informative on its own is effort: `kev-then-epss`
reaches 90 percent of the known exploited findings after
<!--number:headline.orderings.kev-then-epss.effort_to_90pc_kev.mean-->121<!--/number-->
remediations out of a budget of
<!--number:headline.capacity.total_effort-->1,040<!--/number-->, which says the
catalogue is small enough to clear early rather than that sorting by it works.

## Twelve seeds is not many

The spread column in `docs/results.md` is the range across
<!--number:headline.seeds-->12<!--/number--> seeds, and for the severity ordering it
is <!--number:headline.orderings.cvss.kev_coverage_spread-->0.645<!--/number-->,
which is wider than most of the differences the table reports. Twelve seeds gives a
mean with real uncertainty around it, not a settled figure.

The practical consequence: the orderings that score 1.000 with a spread of 0.000
are robust, and the ones in the middle of the table should not be ranked against
each other on these runs. Raise `--seeds` before drawing a conclusion from a small
gap. The project publishes the spread rather than a confidence interval because a
parametric interval on twelve samples of an unknown distribution would be more
precise looking and no more honest.

## The corpus generator is not a model of a real backlog

It produces findings whose EPSS distribution is fitted to one published share and
whose severity correlates with exploitation probability at a chosen strength. Real
backlogs have structure this does not reproduce: findings cluster by asset and by
software component, so remediating one often remediates many; ages are not uniform;
scanner duplicates and false positives consume capacity; and exploitation
probability is not independent across a fleet running the same stack.

The clustering omission matters most, and it cuts against this project's own
conclusion. If one patch clears forty findings, an ordering that groups by
component may beat any ordering that ranks findings individually, and no ordering
in this tool groups by component.

## Capacity is modelled as a single fungible number

One remediation is one unit of effort. In practice a kernel upgrade on a database
cluster and a browser update are not the same unit, change windows are not evenly
spaced, and some remediations are blocked on a vendor rather than on capacity. A
model where effort is fungible flatters every ordering equally, so it probably does
not change the ranking, but it does make the absolute attainment figures optimistic.

## EPSS is a thirty day probability and the simulation is not

EPSS predicts exploitation in the next thirty days. This simulation spends capacity
over <!--number:headline.capacity.weeks-->26<!--/number--> weeks and scores a single EPSS value per CVE throughout, as though
the probability were static. Real EPSS scores move, sometimes sharply, when
exploitation is observed. A programme rereading the feed weekly would reorder its
backlog as it went, which is strictly more information than any ordering here uses.

## There is no notion of risk accepted or compensating controls

Every finding in the corpus is remediable and worth remediating. Real programmes
carry findings behind a WAF rule, on a segmented network, or formally risk accepted,
and those are not failures of prioritisation.

## What would make this stronger

In roughly descending order of how much it would change the conclusions:

1. Run it against a real anonymised backlog, even one.
2. Add component clustering to the generator, and a grouping ordering to compete.
3. Replay historical EPSS and KEV snapshots so the scores move during the
   simulation instead of standing still.
4. Model effort as a distribution rather than a unit.
5. More seeds.
