"""The command line interface.

argparse rather than a third party parser, for the reason recorded in the
dependency budget of the preceding project in this portfolio and repeated here
because it still applies: this has four runtime dependencies that each earn
their place, and argument parsing is not worth a fifth.

Six commands, and the one to run first is ``columns``. A scanner export's
column names are the thing nobody knows in advance, there are deliberately no
vendor presets, and the mapping is easier to write with the file's own header
in front of you.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pob.corpus.generate import CorpusSpec, describe_corpus, generate
from pob.corpus.load import ColumnMap, ImportError_, columns, load
from pob.feeds.fetch import FeedError, fetch
from pob.models import Corpus
from pob.rank.orderings import ORDERINGS, ordering
from pob.simulate.metrics import attainable_in_window, score
from pob.simulate.remediate import Capacity, run


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pob",
        description=(
            "Measures how remediation order changes when findings are ranked by exploitation "
            "probability instead of severity."
        ),
    )
    parser.add_argument("--version", action="version", version="patch-order-bench 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    fetch_command = sub.add_parser("fetch", help="download the EPSS scores and the KEV catalogue")
    fetch_command.add_argument("--to", type=Path, default=Path(".feeds"))

    columns_command = sub.add_parser("columns", help="print a scanner export's column names")
    columns_command.add_argument("csv", type=Path)

    generate_command = sub.add_parser("generate", help="write a simulated corpus")
    generate_command.add_argument("--findings", type=int, default=5_000)
    generate_command.add_argument("--cves", type=int, default=1_500)
    generate_command.add_argument("--assets", type=int, default=400)
    generate_command.add_argument("--correlation", type=float, default=0.25)
    generate_command.add_argument("--seed", type=int, default=0)
    generate_command.add_argument("--out", type=Path, help="write the corpus description as JSON")

    rank_command = sub.add_parser("rank", help="print the top of a backlog under one ordering")
    _corpus_source(rank_command)
    rank_command.add_argument("--ordering", default="kev-then-epss", choices=sorted(ORDERINGS))
    rank_command.add_argument("--top", type=int, default=20)
    _capacity_options(rank_command)

    compare_command = sub.add_parser("compare", help="score every ordering on one corpus")
    _corpus_source(compare_command)
    _capacity_options(compare_command)
    compare_command.add_argument("--json", type=Path, help="write the comparison as JSON")

    chart_command = sub.add_parser("chart", help="draw the coverage curves")
    chart_command.add_argument("--findings", type=int, default=5_000)
    chart_command.add_argument("--cves", type=int, default=1_500)
    chart_command.add_argument("--assets", type=int, default=400)
    chart_command.add_argument("--correlation", type=float, default=0.25)
    chart_command.add_argument("--seeds", type=int, default=12)
    _capacity_options(chart_command)
    chart_command.add_argument("--out", type=Path, default=Path("coverage.png"))

    return parser


def _corpus_source(command: argparse.ArgumentParser) -> None:
    command.add_argument("--csv", type=Path, help="a scanner export to import")
    command.add_argument("--map", type=Path, help="a JSON column mapping for the export")
    command.add_argument("--findings", type=int, default=5_000, help="size of a simulated corpus instead")
    command.add_argument("--cves", type=int, default=1_500)
    command.add_argument("--assets", type=int, default=400)
    command.add_argument("--correlation", type=float, default=0.25)
    command.add_argument("--seed", type=int, default=0)


def _capacity_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("--per-week", type=float, default=40.0, help="remediations a week")
    command.add_argument("--weeks", type=int, default=26, help="how long the programme runs")


def _corpus(args: argparse.Namespace) -> tuple[Corpus, bool]:
    """The corpus to work on, and whether it is simulated."""
    if args.csv:
        if not args.map:
            raise ImportError_(
                "--csv needs --map, a JSON file naming which column holds which field. There are no "
                "vendor presets on purpose: a preset that named a column wrongly would import "
                "successfully with that field empty. Run 'pob columns <csv>' to see what you have."
            )
        mapping = ColumnMap(**json.loads(args.map.read_text(encoding="utf-8")))
        corpus, report = load(args.csv, mapping)
        print(f"imported: {report.summary()}", file=sys.stderr)
        for skipped in report.rows_skipped[:5]:
            print(f"  skipped {skipped}", file=sys.stderr)
        return corpus, False

    spec = CorpusSpec(
        findings=args.findings,
        distinct_cves=args.cves,
        assets=args.assets,
        cvss_epss_correlation=args.correlation,
        seed=args.seed,
    )
    return generate(spec), True


def _simulated_warning(simulated: bool) -> None:
    if simulated:
        print(
            "note: this is a simulated corpus. Figures below describe the orderings, not your estate. "
            "Use --csv with your own scanner export for numbers about it.",
            file=sys.stderr,
        )


def _command_fetch(args: argparse.Namespace) -> int:
    counts = fetch(args.to)
    print(f"wrote {args.to}: {counts['epss_rows']:,} EPSS scores, {counts['kev_rows']:,} KEV entries")
    return 0


def _command_columns(args: argparse.Namespace) -> int:
    found = columns(args.csv)
    print(f"{len(found)} column(s) in {args.csv}:")
    for name in found:
        print(f"  {name!r}")
    print()
    print("A mapping is JSON. The three required fields are cve, asset and cvss:")
    print(json.dumps({"cve": found[0] if found else "...", "asset": "...", "cvss": "..."}, indent=2))
    return 0


def _command_generate(args: argparse.Namespace) -> int:
    spec = CorpusSpec(
        findings=args.findings,
        distinct_cves=args.cves,
        assets=args.assets,
        cvss_epss_correlation=args.correlation,
        seed=args.seed,
    )
    described = {"spec": spec.describe(), "realized": describe_corpus(generate(spec))}
    rendered = json.dumps(described, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(rendered)
    return 0


def _command_rank(args: argparse.Namespace) -> int:
    corpus, simulated = _corpus(args)
    _simulated_warning(simulated)
    capacity = Capacity(per_week=args.per_week, weeks=args.weeks)
    chosen = ordering(args.ordering)
    order = chosen(corpus, capacity)

    print(f"{args.ordering}: {chosen.summary}")
    print(f"blind to: {chosen.blind_to}")
    print()
    print(f"{'#':>4}  {'cve':<18} {'asset':<16} {'cvss':>5} {'epss':>8} {'kev':>4} {'days left':>10}")
    for position, finding in enumerate(order[: args.top], start=1):
        record = corpus.vulnerabilities[finding.cve]
        print(
            f"{position:>4}  {finding.cve:<18} {finding.asset_id:<16} {record.cvss:>5.1f} "
            f"{record.epss:>8.5f} {'yes' if record.in_kev else '':>4} {corpus.days_remaining(finding):>10}"
        )
    return 0


def _command_compare(args: argparse.Namespace) -> int:
    corpus, simulated = _corpus(args)
    _simulated_warning(simulated)
    capacity = Capacity(per_week=args.per_week, weeks=args.weeks)
    ceiling = len(attainable_in_window(corpus, capacity))

    print(
        f"{len(corpus.findings):,} findings, {len(corpus.kev_findings)} known exploited, "
        f"capacity {capacity.total:,.0f} over {capacity.weeks} weeks"
    )
    print(f"window attainment ceiling at this rate: {ceiling}")
    print()
    print(f"{'ordering':16s} {'kev cov':>8s} {'effort->90%':>12s} {'window att':>11s} {'exposure':>9s}")

    results = {}
    for name, candidate in ORDERINGS.items():
        order = candidate(corpus, capacity)
        outcome = score(corpus, name, order, run(corpus, order, capacity), capacity)
        results[name] = {
            "kev_coverage": round(outcome.kev_coverage, 4),
            "effort_to_90pc_kev": outcome.effort_to_90pc_kev,
            "window_attainment": round(outcome.window_attainment, 4),
            "exposure_removed": round(outcome.exposure_removed, 4),
            "blind_to": candidate.blind_to,
        }
        effort = outcome.effort_to_90pc_kev
        print(
            f"{name:16s} {outcome.kev_coverage:8.3f} "
            f"{(f'{effort:.0f}' if effort is not None else '-'):>12s} "
            f"{outcome.window_attainment:11.3f} {outcome.exposure_removed:9.3f}"
        )

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(
                {
                    "simulated": simulated,
                    "capacity": {"per_week": capacity.per_week, "weeks": capacity.weeks},
                    "window_attainment_ceiling": ceiling,
                    "orderings": results,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote {args.json}")
    return 0


def _command_chart(args: argparse.Namespace) -> int:
    from pob.plot import coverage_chart

    spec = CorpusSpec(
        findings=args.findings,
        distinct_cves=args.cves,
        assets=args.assets,
        cvss_epss_correlation=args.correlation,
    )
    destination = coverage_chart(
        spec, Capacity(per_week=args.per_week, weeks=args.weeks), args.out, seeds=args.seeds
    )
    print(f"wrote {destination}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    commands = {
        "fetch": _command_fetch,
        "columns": _command_columns,
        "generate": _command_generate,
        "rank": _command_rank,
        "compare": _command_compare,
        "chart": _command_chart,
    }
    try:
        return commands[args.command](args)
    except FeedError as exc:
        print(f"feed error: {exc}", file=sys.stderr)
        return 2
    except ImportError_ as exc:
        print(f"import error: {exc}", file=sys.stderr)
        return 2
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"{exc.filename}: no such file or directory", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
