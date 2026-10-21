"""What a schedule is scored on.

Every metric here reports its ceiling where it has one, because the headline
question is how much of the achievable an ordering achieves, not how close to
an impossible 100% it gets.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from pob.models import Corpus, Finding
from pob.simulate.remediate import Capacity, Schedule


@dataclass(frozen=True)
class Outcome:
    """How one ordering did on one corpus at one capacity."""

    ordering: str
    findings: int
    remediated: int

    kev_findings: int
    kev_remediated: int
    # Effort spent before 90% of the known exploited findings were covered, or
    # None if the programme never got there inside its horizon. None rather
    # than the horizon, because "did not reach it" and "reached it on the last
    # day" are different answers and averaging them together hides the first.
    effort_to_90pc_kev: float | None

    in_scope_findings: int
    in_scope_remediated_in_window: int
    # The most that could have been remediated inside their window by any
    # ordering: the ones whose window had not already closed on day one. The
    # denominator that makes an attainment figure mean something.
    in_scope_attainable: int

    exposure_score_total: float
    exposure_score_removed: float

    @property
    def kev_coverage(self) -> float:
        return self.kev_remediated / self.kev_findings if self.kev_findings else 0.0

    @property
    def window_attainment(self) -> float:
        """Share of the attainable window compliance that was achieved."""
        return self.in_scope_remediated_in_window / self.in_scope_attainable if self.in_scope_attainable else 0.0

    @property
    def exposure_removed(self) -> float:
        return self.exposure_score_removed / self.exposure_score_total if self.exposure_score_total else 0.0


def exposure_score(corpus: Corpus, finding: Finding) -> float:
    """A relative weight, not a probability and not a count.

    Exploitation probability times how exposed the host is. Useful for
    comparing orderings on one corpus; meaningless as an absolute, because
    summing it across findings assumes an independence that does not hold.
    """
    return corpus.vulnerabilities[finding.cve].epss * finding.asset_criticality


def attainable_in_window(corpus: Corpus, capacity: Capacity) -> list[Finding]:
    """The most findings any ordering could remediate inside their windows.

    Not simply the ones whose window is still open. That was the first version
    and it was too generous by a wide margin: a window still open for five days
    is only attainable if the programme can reach it within five days, and at a
    realistic rate most of them cannot be. Using the open set as the
    denominator charged every ordering for deadlines that no rate could have
    met and made the whole comparison look like failure.

    The real ceiling is the largest set of deadlines a constant rate can meet,
    which for unit sized work is found by walking the deadlines in order and
    taking one whenever the slot it would occupy is still inside it. That
    greedy is optimal for unit jobs, so this is a ceiling rather than an
    estimate of one.
    """
    rate = capacity.per_week / 7.0
    horizon = capacity.weeks * 7
    candidates = sorted(
        (
            finding
            for finding in corpus.findings
            if corpus.vulnerabilities[finding.cve].cvss_severity.in_pci_scope and corpus.days_remaining(finding) >= 0
        ),
        key=lambda finding: (corpus.days_remaining(finding), finding.finding_id),
    )
    taken: list[Finding] = []
    position = 0.0
    for finding in candidates:
        day = int(np.ceil((position + finding.effort) / rate))
        if day <= min(corpus.days_remaining(finding), horizon):
            taken.append(finding)
            position += finding.effort
    return taken


def score(
    corpus: Corpus,
    ordering_name: str,
    order: tuple[Finding, ...],
    schedule: Schedule,
    capacity: Capacity,
) -> Outcome:
    """Score a completed schedule."""
    kev = corpus.kev_findings
    kev_done = [finding for finding in kev if schedule.reached(finding)]

    in_scope = [
        finding for finding in corpus.findings if corpus.vulnerabilities[finding.cve].cvss_severity.in_pci_scope
    ]
    # The ceiling any ordering could have reached at this capacity, rather than
    # the set whose windows merely happen to be open.
    attainable = attainable_in_window(corpus, capacity)
    in_window = [
        finding
        for finding in in_scope
        if schedule.reached(finding) and schedule.remediated_on[finding.finding_id] <= corpus.days_remaining(finding)
    ]

    total_exposure = float(sum(exposure_score(corpus, finding) for finding in corpus.findings))
    removed_exposure = float(
        sum(exposure_score(corpus, finding) for finding in corpus.findings if schedule.reached(finding))
    )

    return Outcome(
        ordering=ordering_name,
        findings=len(corpus.findings),
        remediated=len(schedule.remediated_on),
        kev_findings=len(kev),
        kev_remediated=len(kev_done),
        effort_to_90pc_kev=_effort_to_cover(corpus, order, kev, 0.90, schedule),
        in_scope_findings=len(in_scope),
        in_scope_remediated_in_window=len(in_window),
        in_scope_attainable=len(attainable),
        exposure_score_total=total_exposure,
        exposure_score_removed=removed_exposure,
    )


def _effort_to_cover(
    corpus: Corpus,
    order: tuple[Finding, ...],
    target: tuple[Finding, ...],
    share: float,
    schedule: Schedule,
) -> float | None:
    """Effort spent before ``share`` of ``target`` has been remediated."""
    if not target:
        return None
    needed = int(np.ceil(share * len(target)))
    wanted = {finding.finding_id for finding in target}
    spent = 0.0
    covered = 0
    for finding in order:
        spent += finding.effort
        if finding.finding_id in wanted:
            covered += 1
            if covered >= needed:
                # Only if the programme actually got this far. Beyond the
                # horizon the figure is what it would have cost, not what it
                # did, and reporting the two alike would credit an ordering
                # for coverage it never delivered.
                return spent if spent <= schedule.effort_spent else None
    return None


def coverage_curve(
    corpus: Corpus, order: tuple[Finding, ...], target: tuple[Finding, ...], steps: int = 60
) -> tuple[np.ndarray, np.ndarray]:
    """Cumulative share of ``target`` covered against effort spent.

    The comparison between orderings is a curve rather than a number: one
    ordering can win early and lose late, and a single coverage figure at one
    capacity hides that completely.
    """
    if not order:
        return np.array([0.0]), np.array([0.0])
    wanted = {finding.finding_id for finding in target}
    total = len(wanted) or 1

    effort = np.cumsum([finding.effort for finding in order])
    hits = np.cumsum([1 if finding.finding_id in wanted else 0 for finding in order])
    share = hits / total

    sample = np.unique(np.linspace(0, len(order) - 1, min(steps, len(order))).astype(int))
    return effort[sample], share[sample]
