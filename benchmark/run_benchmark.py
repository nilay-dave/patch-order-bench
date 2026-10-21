"""Compares the orderings, and checks whether the comparison survives its own
assumptions.

**Every number here is a simulation.** The live feed path exists and has never
been run, because the environment this was built in cannot reach the feeds. So
the figures describe how the orderings behave on a corpus whose parameters are
declared in benchmark terms, not how they would behave on this year's CVEs.
What they do establish is the shape of the problem, and that is worth having
because the shape is what most patch programmes have never looked at.

Four experiments.

**A. The headline comparison**, at a realistic capacity, averaged over seeds.
Averaged because a single seed is not enough: the realized share of CVEs above
EPSS 0.1 varies from 0.015 to 0.031 across seeds at the default scale, and the
whole result turns on those few CVEs.

**B. The sensitivity sweep**, over the correlation between severity and
exploitation probability. This is the parameter nothing in this project knows
and everything depends on: at a correlation of 1 the two orderings are the same
ordering and there is nothing to measure. The experiment reports whether the
conclusion holds across the range or flips somewhere inside it. A simulation
tuned to one value of its least known parameter is worth nothing, and this is
what stops that.

The seed averaging in experiment A exists for a reason worth stating, because
it changed a headline. A single seed run had severity ordering covering 0.085
of the known exploited findings against a shuffle's 0.211, which is the
striking result that severity ordering is worse than no ordering at all.
Averaged over twelve seeds it is 0.382 against 0.211: still much worse than
exploitation aware ordering, and better than a shuffle. The striking version
was noise, and publishing it would have been publishing the most quotable
number in the project and the wrong one.

**C. Coverage curves**, because the comparison is a curve rather than a number.
One ordering can win early and lose late, and a coverage figure at one capacity
hides that completely.

**D. Runtime**, at three corpus sizes, because a ranking that takes an hour is
not a ranking a programme will rerun weekly.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pob.corpus.generate import CorpusSpec, describe_corpus, generate  # noqa: E402
from pob.rank.orderings import ORDERINGS  # noqa: E402
from pob.simulate.metrics import attainable_in_window, coverage_curve, score  # noqa: E402
from pob.simulate.remediate import Capacity, run  # noqa: E402

# A programme that can touch forty hosts a week for half a year, which is a
# fifth of the default backlog. Capacity has to bind: at a capacity that covers
# everything there is nothing to prioritise and no comparison to make.
DEFAULT_CAPACITY = Capacity(per_week=40, weeks=26)

# The share of the backlog the capacity covers. Held constant when the corpus
# size changes, because coverage figures are not comparable across different
# ratios: a random ordering covers whatever share of the backlog the capacity
# reaches, so the baseline moves with the ratio and every comparison against it
# moves too. The sweep ran at a different ratio from the headline before this,
# which made its random baseline 0.54 against the headline's 0.20 and the two
# sets of numbers quietly incomparable.
CAPACITY_SHARE_OF_BACKLOG = DEFAULT_CAPACITY.total / 5_000


def capacity_for(findings: int, weeks: int = DEFAULT_CAPACITY.weeks) -> Capacity:
    """A capacity covering the same share of the backlog as the default."""
    total = findings * CAPACITY_SHARE_OF_BACKLOG
    return Capacity(per_week=max(total / weeks, 1e-6), weeks=weeks)


def _summarise(values: list[float | None]) -> dict:
    """Mean and spread over seeds, keeping track of what was not reached.

    A None means the programme never got there, and it is counted rather than
    dropped. Averaging only the seeds that reached a target would report the
    cost of success conditional on succeeding, which flatters whichever
    ordering succeeds least often.
    """
    reached = [value for value in values if value is not None]
    return {
        "mean": round(statistics.fmean(reached), 1) if reached else None,
        "min": round(min(reached), 1) if reached else None,
        "max": round(max(reached), 1) if reached else None,
        "seeds_reached": len(reached),
        "seeds_run": len(values),
    }


def compare(spec: CorpusSpec, capacity: Capacity, seeds: int) -> dict:
    """Run every ordering over several seeds at one configuration."""
    per_ordering: dict[str, dict[str, list]] = {
        name: {"kev_coverage": [], "window_attainment": [], "exposure_removed": [], "effort_to_90pc_kev": []}
        for name in ORDERINGS
    }
    corpora: list[dict] = []
    ceilings: list[int] = []

    for seed in range(seeds):
        corpus = generate(CorpusSpec(**{**spec.__dict__, "seed": seed}))
        corpora.append(describe_corpus(corpus))
        ceilings.append(len(attainable_in_window(corpus, capacity)))
        for name, ordering in ORDERINGS.items():
            order = ordering(corpus, capacity)
            outcome = score(corpus, name, order, run(corpus, order, capacity), capacity)
            per_ordering[name]["kev_coverage"].append(outcome.kev_coverage)
            per_ordering[name]["window_attainment"].append(outcome.window_attainment)
            per_ordering[name]["exposure_removed"].append(outcome.exposure_removed)
            per_ordering[name]["effort_to_90pc_kev"].append(outcome.effort_to_90pc_kev)

    results = {}
    for name, collected in per_ordering.items():
        results[name] = {
            "summary": ORDERINGS[name].summary,
            "blind_to": ORDERINGS[name].blind_to,
            "kev_coverage": round(statistics.fmean(collected["kev_coverage"]), 4),
            "kev_coverage_spread": round(max(collected["kev_coverage"]) - min(collected["kev_coverage"]), 4),
            "window_attainment": round(statistics.fmean(collected["window_attainment"]), 4),
            "exposure_removed": round(statistics.fmean(collected["exposure_removed"]), 4),
            "effort_to_90pc_kev": _summarise(collected["effort_to_90pc_kev"]),
        }

    return {
        "capacity": {"per_week": capacity.per_week, "weeks": capacity.weeks, "total_effort": capacity.total},
        "seeds": seeds,
        "corpus": {
            "findings": corpora[0]["findings"],
            "mean_distinct_cves": round(statistics.fmean(c["distinct_cves"] for c in corpora)),
            "mean_kev_findings": round(statistics.fmean(c["kev_findings"] for c in corpora), 1),
            "mean_realized_rank_correlation": round(
                statistics.fmean(c["realized_cvss_epss_rank_correlation"] for c in corpora), 3
            ),
            "mean_share_epss_above_0_1": round(statistics.fmean(c["share_epss_above_0_1"] for c in corpora), 4),
            "mean_already_past_window": round(statistics.fmean(c["findings_already_past_window"] for c in corpora)),
            "mean_window_attainment_ceiling": round(statistics.fmean(ceilings), 1),
        },
        "orderings": results,
    }


def experiment_headline(args) -> dict:
    spec = CorpusSpec(
        findings=args.findings,
        distinct_cves=args.cves,
        assets=args.assets,
        cvss_epss_correlation=args.correlation,
    )
    result = compare(spec, DEFAULT_CAPACITY, args.seeds)
    print(
        f"  corpus: {result['corpus']['findings']:,} findings, "
        f"{result['corpus']['mean_kev_findings']:.0f} known exploited, "
        f"{result['corpus']['mean_already_past_window']:,} already past window"
    )
    print(f"  window attainment ceiling at this rate: {result['corpus']['mean_window_attainment_ceiling']:.0f}")
    print()
    print(f"  {'ordering':16s} {'kev cov':>8s} {'effort->90%':>12s} {'window att':>11s} {'exposure':>9s}")
    for name, entry in result["orderings"].items():
        effort = entry["effort_to_90pc_kev"]
        shown = f"{effort['mean']:.0f}" if effort["mean"] is not None else "-"
        if effort["mean"] is not None and effort["seeds_reached"] < effort["seeds_run"]:
            shown += f" ({effort['seeds_reached']}/{effort['seeds_run']})"
        print(
            f"  {name:16s} {entry['kev_coverage']:8.3f} {shown:>12s} "
            f"{entry['window_attainment']:11.3f} {entry['exposure_removed']:9.3f}"
        )
    return result


def experiment_sweep(args) -> dict:
    """Does the conclusion survive the parameter nothing here knows?"""
    rows = []
    print(f"  capacity held at {CAPACITY_SHARE_OF_BACKLOG:.0%} of the backlog, so the random baseline is comparable")
    print(
        f"  {'correlation':>11s} {'realized':>9s}  {'cvss kev':>9s} {'kev-epss':>9s} {'random':>8s}  {'verdict':>22s}"
    )
    for rho in args.sweep:
        spec = CorpusSpec(
            findings=args.sweep_findings,
            distinct_cves=max(10, args.sweep_findings // 3),
            assets=args.assets,
            cvss_epss_correlation=rho,
        )
        result = compare(spec, capacity_for(args.sweep_findings), args.sweep_seeds)
        cvss = result["orderings"]["cvss"]["kev_coverage"]
        kev_epss = result["orderings"]["kev-then-epss"]["kev_coverage"]
        random_baseline = result["orderings"]["random"]["kev_coverage"]
        # A tolerance, because at a correlation of 1 the two are the same
        # ordering by construction and came out 1.000 against 0.997, which the
        # strict comparison called a win for the exploitation ordering. A
        # three thousandth gap between two orderings that are provably
        # identical is noise being reported as a result.
        margin = 0.02
        verdict = (
            "tied"
            if abs(kev_epss - cvss) <= margin
            else "exploitation ordering wins"
            if kev_epss > cvss
            else "severity ordering wins"
        )
        beats_random = "yes" if cvss > random_baseline else "no"
        rows.append(
            {
                "cvss_epss_correlation": rho,
                "realized_rank_correlation": result["corpus"]["mean_realized_rank_correlation"],
                "cvss_kev_coverage": cvss,
                "kev_then_epss_kev_coverage": kev_epss,
                "random_kev_coverage": random_baseline,
                "cvss_beats_random": cvss > random_baseline,
                "verdict": verdict,
            }
        )
        print(
            f"  {rho:11.2f} {result['corpus']['mean_realized_rank_correlation']:9.3f}  "
            f"{cvss:9.3f} {kev_epss:9.3f} {random_baseline:8.3f}  "
            f"{verdict:>22s}  cvss beats random: {beats_random}"
        )
    return {"rows": rows}


def experiment_curves(args) -> dict:
    corpus = generate(
        CorpusSpec(
            findings=args.findings,
            distinct_cves=args.cves,
            assets=args.assets,
            cvss_epss_correlation=args.correlation,
            seed=0,
        )
    )
    curves = {}
    for name, ordering in ORDERINGS.items():
        order = ordering(corpus, DEFAULT_CAPACITY)
        effort, share = coverage_curve(corpus, order, corpus.kev_findings, steps=80)
        curves[name] = {"effort": [round(float(v), 1) for v in effort], "share": [round(float(v), 4) for v in share]}
    print(f"  {len(curves)} coverage curves over {len(corpus.findings):,} findings")
    return curves


def experiment_runtime(args) -> list[dict]:
    rows = []
    for size in args.runtime_sizes:
        spec = CorpusSpec(
            findings=size,
            distinct_cves=max(10, size // 3),
            assets=max(10, size // 12),
            cvss_epss_correlation=args.correlation,
            seed=0,
        )
        started = time.perf_counter()
        corpus = generate(spec)
        generated = time.perf_counter() - started

        capacity = capacity_for(size)
        timings = {}
        for name, ordering in ORDERINGS.items():
            started = time.perf_counter()
            order = ordering(corpus, capacity)
            run(corpus, order, capacity)
            timings[name] = round(time.perf_counter() - started, 3)

        rows.append(
            {
                "findings": size,
                "generate_seconds": round(generated, 3),
                "rank_and_schedule_seconds": timings,
                "slowest_ordering": max(timings, key=timings.get),
                "slowest_seconds": max(timings.values()),
            }
        )
        print(
            f"  {size:>8,} findings  generate {generated:6.2f}s  "
            f"slowest ordering {max(timings, key=timings.get)} at {max(timings.values()):.3f}s"
        )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=int, default=5_000)
    parser.add_argument("--cves", type=int, default=1_500)
    parser.add_argument("--assets", type=int, default=400)
    parser.add_argument("--correlation", type=float, default=0.25)
    parser.add_argument("--seeds", type=int, default=12)
    parser.add_argument("--sweep", type=float, nargs="+", default=[0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
    parser.add_argument("--sweep-seeds", type=int, default=8)
    parser.add_argument("--sweep-findings", type=int, default=4_000)
    parser.add_argument("--runtime-sizes", type=int, nargs="+", default=[5_000, 50_000, 500_000])
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "metrics.json")
    args = parser.parse_args(argv)

    print("A. headline comparison (every figure a simulation)")
    headline = experiment_headline(args)

    print("\nB. sensitivity sweep over the severity and probability correlation")
    sweep = experiment_sweep(args)

    print("\nC. coverage curves")
    curves = experiment_curves(args)

    print("\nD. runtime")
    runtime = experiment_runtime(args)

    document = {
        "note": (
            "Every figure in this file is a simulation. The live feed path in pob.feeds has never been run "
            "against the real feeds, because the environment this was built in cannot reach "
            "epss.cyentia.com or cisa.gov. One distributional parameter is sourced, from FIRST's EPSS "
            "model documentation: 3,735 of 139,473 CVSS 3.x CVEs score at or above 0.1. Every other "
            "parameter is a declared choice, and the one everything depends on, the correlation between "
            "severity and exploitation probability, is swept in experiment B rather than argued for."
        ),
        "corpus_spec": CorpusSpec(
            findings=args.findings,
            distinct_cves=args.cves,
            assets=args.assets,
            cvss_epss_correlation=args.correlation,
        ).describe(),
        "headline": headline,
        "sensitivity_sweep": sweep,
        "coverage_curves": curves,
        "runtime": runtime,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
