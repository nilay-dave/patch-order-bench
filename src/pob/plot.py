"""Draws the coverage curves, because the comparison is a curve.

A single coverage figure at one capacity hides the thing that matters most: one
ordering can win early and lose late, and a programme choosing between them is
choosing where on the curve it will be living.

Two conventions here are deliberate. The chart is readable without colour,
because a security report gets printed and forwarded as a screenshot, and an
ordering identified only by hue is an ordering nobody can discuss over the
phone. And the random baseline is drawn, in grey, so the reader can see how
much of any curve's height is prioritisation rather than simply doing work.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

# Chosen before pyplot is imported. Without it matplotlib tries to find a
# display, and on a CI runner or a container that is either a warning on every
# run or a hard failure depending on the version.
matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from pob.corpus.generate import CorpusSpec, generate  # noqa: E402
from pob.rank.orderings import ORDERINGS  # noqa: E402
from pob.simulate.metrics import coverage_curve  # noqa: E402
from pob.simulate.remediate import Capacity  # noqa: E402

# Distinguishable in greyscale and by marker, not by colour alone.
STYLES = {
    "cvss": {"linestyle": "-", "marker": "o", "color": "#1b3a6b"},
    "epss": {"linestyle": "-", "marker": "s", "color": "#8c2d19"},
    "kev-then-epss": {"linestyle": "-", "marker": "^", "color": "#1d6b3a"},
    "kev-then-cvss": {"linestyle": "--", "marker": "v", "color": "#5a3d8c"},
    "exposure": {"linestyle": "-.", "marker": "D", "color": "#8c6b19"},
    "due-date": {"linestyle": ":", "marker": "x", "color": "#6b1b4a"},
    "window-first": {"linestyle": "--", "marker": "P", "color": "#1b6b6b"},
    "random": {"linestyle": "-", "marker": None, "color": "#8a8a8a"},
}


def averaged_curves(spec: CorpusSpec, capacity: Capacity, seeds: int) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    """Coverage curves averaged over seeds, on a shared effort grid.

    Averaged for the reason the benchmark averages its tables. A single seed
    chart of this comparison showed the severity ordering tracking below a
    shuffle for most of the budget, which is the most quotable thing in the
    project and is not true: over twelve seeds it sits well above. A chart is
    the artefact most likely to be screenshotted out of its context, so it is
    the last place a one sample result belongs.

    The curves are interpolated onto one effort grid before averaging, because
    each seed produces its own effort points and averaging them pointwise
    would be averaging coverage at different amounts of work.
    """
    grid = np.linspace(0.0, float(spec.findings), 400)
    gathered: dict[str, list[np.ndarray]] = {name: [] for name in ORDERINGS}

    for seed in range(seeds):
        corpus = generate(CorpusSpec(**{**spec.__dict__, "seed": seed}))
        for name, ordering in ORDERINGS.items():
            order = ordering(corpus, capacity)
            effort, share = coverage_curve(corpus, order, corpus.kev_findings, steps=200)
            gathered[name].append(np.interp(grid, effort, share, left=0.0, right=float(share[-1])))

    return {name: (grid, np.mean(np.vstack(runs), axis=0)) for name, runs in gathered.items()}


def coverage_chart(
    spec: CorpusSpec,
    capacity: Capacity,
    destination: Path,
    *,
    seeds: int = 12,
    title: str | None = None,
) -> Path:
    """Cumulative coverage of the known exploited findings against effort."""
    figure, axes = plt.subplots(figsize=(9.5, 5.6), dpi=150)
    curves = averaged_curves(spec, capacity, seeds)

    for name, (effort, share) in curves.items():
        style = STYLES.get(name, {})
        axes.plot(
            effort,
            share * 100,
            label=name,
            linewidth=2.4 if name == "random" else 1.8,
            markersize=4,
            markevery=37,
            **style,
        )

    axes.axvline(
        capacity.total,
        color="#333333",
        linewidth=1.0,
        linestyle=(0, (4, 3)),
    )
    axes.annotate(
        f"capacity: {capacity.total:,.0f} remediations\n({capacity.per_week:.0f} a week for {capacity.weeks} weeks)",
        xy=(capacity.total, 98),
        xytext=(10, -4),
        textcoords="offset points",
        fontsize=8,
        color="#333333",
        va="top",
    )

    axes.set_xlabel("remediation effort spent")
    axes.set_ylabel("share of known exploited findings covered (%)")
    # pad leaves room for the subtitle, which otherwise lands on top of the
    # title: set_title places text at the axes top whatever else is there.
    axes.set_title(title or "Coverage of known exploited findings by remediation order", fontsize=11, pad=22)
    axes.text(
        0.5,
        1.012,
        f"mean of {seeds} simulated corpora of {spec.findings:,} findings",
        transform=axes.transAxes,
        ha="center",
        fontsize=8,
        color="#555555",
    )
    axes.set_ylim(0, 102)
    axes.set_xlim(0, min(spec.findings, capacity.total * 2.5))
    axes.grid(True, alpha=0.25, linewidth=0.6)
    axes.legend(fontsize=8, loc="lower right", framealpha=0.95)

    # Stated on the chart, not only in the caption. A chart gets screenshotted
    # out of its document and a simulated figure with no label on it becomes a
    # real one the moment it leaves the page.
    figure.text(
        0.01,
        0.015,
        "Simulated corpora. Parameters in docs/metrics.json; the live feed path has never been run.",
        fontsize=7,
        color="#666666",
    )

    figure.tight_layout(rect=(0, 0.03, 1, 1))
    destination.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(destination, bbox_inches="tight")
    plt.close(figure)
    return destination
