# patch-order-bench

[![CI](https://github.com/nilay-dave/patch-order-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/nilay-dave/patch-order-bench/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/endpoint?url=https://nilay-dave.github.io/patch-order-bench/badges/coverage.json)](https://nilay-dave.github.io/patch-order-bench/)
[![PyPI](https://img.shields.io/pypi/v/patch-order-bench)](https://pypi.org/project/patch-order-bench/)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![dependencies](https://img.shields.io/badge/runtime%20dependencies-2-green)](pyproject.toml)
[![licence](https://img.shields.io/badge/licence-MIT-green)](LICENSE)

A benchmark for the order a patch programme works in. It takes a vulnerability
backlog, spends a fixed remediation capacity against it under eight different
orderings, and scores what each one bought.

The question it exists to answer: a scanner sorts by CVSS descending, and CVSS
measures how bad a vulnerability would be if exploited, not whether anyone is
exploiting it. How much does that cost?

```bash
pip install patch-order-bench
```

```bash
# against your own scanner export
pob columns findings.csv                      # see what the exporter called things
pob compare --csv findings.csv --map map.json # score all eight orderings
```

## Every number published here is a simulation

<!--number:headline.corpus.findings-->5,000<!--/number--> generated findings, not
a real estate. The live feed path in `pob.feeds` reads EPSS and the CISA KEV
catalogue, has tests against recorded responses, and has never been run against
the real endpoints, because the network in the environment this was built in
refuses them. One distributional parameter has published provenance; the rest are
declared choices, and the one the whole comparison rests on is swept rather than
assumed.

`docs/sources.md` separates what was sourced from what was chosen.
`docs/limitations.md` is the list of reasons not to over read these figures, and
it is longer than this section.

## What the benchmark measured

![coverage of known exploited findings by remediation order](docs/img/coverage.png)

A programme doing <!--number:headline.capacity.per_week-->40<!--/number-->
remediations a week for <!--number:headline.capacity.weeks-->26<!--/number-->
weeks, against a backlog of
<!--number:headline.corpus.findings-->5,000<!--/number-->, averaged over
<!--number:headline.seeds-->12<!--/number--> seeds:

| ordering | KEV coverage | window attainment |
| --- | --- | --- |
| `kev-then-epss` | <!--number:headline.orderings.kev-then-epss.kev_coverage-->1.000<!--/number--> | <!--number:headline.orderings.kev-then-epss.window_attainment-->0.084<!--/number--> |
| `window-first` | <!--number:headline.orderings.window-first.kev_coverage-->0.202<!--/number--> | <!--number:headline.orderings.window-first.window_attainment-->0.649<!--/number--> |
| `cvss` | <!--number:headline.orderings.cvss.kev_coverage-->0.382<!--/number--> | <!--number:headline.orderings.cvss.window_attainment-->0.132<!--/number--> |
| `random` | <!--number:headline.orderings.random.kev_coverage-->0.211<!--/number--> | <!--number:headline.orderings.random.window_attainment-->0.064<!--/number--> |

Three things in that table are worth more than the headline.

**No ordering wins on both axes.** Putting the known exploited findings first
covers all of them and meets almost no compliance windows. Working the windows
meets them and misses most of the exploited findings. A programme is choosing
between these whether or not it knows it is.

**Sorting by due date attains
<!--number:headline.orderings.due-date.window_attainment-->0.000<!--/number--> of
the window ceiling.** It is the intuitive compliance ordering and it achieves no
compliance at all, because
<!--number:headline.corpus.mean_already_past_window-->3,248<!--/number--> findings
are already past their window on day one and an ascending sort by due date spends
the whole budget on deadlines that cannot be met any more.

**Ranking by severity beats a shuffle, and not by as much as its spread.** The
`cvss` row's range across seeds is
<!--number:headline.orderings.cvss.kev_coverage_spread-->0.645<!--/number-->.
A single run of this benchmark can show severity ordering well ahead of random or
behind it. The full table with every spread is in
[docs/results.md](docs/results.md).

## Using it on your own backlog

Nothing above is about your estate. This is:

```bash
pob columns findings.csv
```

```json
{
  "cve": "CVE ID",
  "asset": "Host Name",
  "cvss": "CVSS v3 Base Score",
  "first_seen": "First Discovered"
}
```

```bash
pob compare --csv findings.csv --map map.json --per-week 40 --weeks 26
```

There are no vendor presets. A mapping file for your exporter is four lines and
lasts until the exporter changes; a preset in here would be a guess about a
product version, shipped as though it were knowledge, and wrong silently.

EPSS scores and the KEV catalogue are fetched separately:

```bash
pob fetch --out feeds/     # this path has never been run against the live feeds
```

## The eight orderings

Each one declares what it is blind to, because an ordering is a decision about
what to ignore and the honest way to present one is to say so.

| ordering | ranks by | blind to |
| --- | --- | --- |
| `cvss` | highest base score first, which is what the scanner prints | whether anyone is exploiting it, and how exposed the host is |
| `epss` | probability of exploitation in the next thirty days | how bad exploitation would be, and how exposed the host is |
| `kev-then-epss` | known exploited first, then exploitation probability | how bad exploitation would be, and how exposed the host is |
| `kev-then-cvss` | known exploited first, then severity | exploitation probability below the catalogue threshold |
| `exposure` | exploitation probability weighted by asset criticality | how bad exploitation would be |
| `due-date` | most overdue first, which is what an audit list looks like | that a closed window cannot be reopened |
| `window-first` | soonest to close among windows still open, then the overdue | everything except the band severity put it in |
| `random` | a seeded shuffle | everything, which is the point |

`random` is in the list because an ordering that cannot beat a shuffle is not an
ordering, and two of the seven can barely do it.

## What it does not do

It does not group findings by patch. Real backlogs cluster, one upgrade clears
forty findings, and an ordering that exploited that could beat every ordering
here. That omission cuts against this project's own conclusion, which is why it
is the second item on the list in [docs/limitations.md](docs/limitations.md).

It does not model effort as anything but a unit, carry risk acceptance or
compensating controls, or let EPSS scores move during the simulation, which they
do in reality.

It is a benchmark, not a prioritisation product. It will tell you what an
ordering costs. It will not tell you what to patch on Tuesday.

## Decisions

- [ADR 001](docs/adr/adr-001-exploitability-ordering.md): rank by exploitation
  probability, not severity, and what that measurement actually supports.
- [ADR 002](docs/adr/adr-002-no-persistence-layer.md): no persistence layer, and
  an argument the dependency checker falsified.
- [ADR 003](docs/adr/adr-003-simulation-methodology.md): how the simulation earns
  the right to a number, including the striking result that turned out to be
  noise.

## Development

```bash
make install
make check       # every gate CI runs: dashes, tables, published numbers,
                 # dependencies, generated docs, format, lint, tests
make bench       # rerun the benchmark and rewrite docs/metrics.json
make report      # regenerate docs/results.md and the chart from it
```

Every figure in the README and under `docs/` is tagged in the source with the
metrics path it came from, and `tools/check_numbers.py` fails the build when a
published number stops matching the measured one. `docs/results.md` is generated
rather than written, and CI checks it is current.

## Licence

MIT. See [LICENSE](LICENSE).
