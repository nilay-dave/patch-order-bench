"""Works through a backlog at a fixed rate and records what gets covered.

The question this project exists to answer is not which findings are worst. It
is: given that a programme can remediate a fixed number of things a week, which
order covers the most real risk soonest, and does the order change whether a
compliance window is met.

That makes capacity the central object. Without it every ordering eventually
remediates everything and the comparison is empty, which is why a ranked list
with no capacity attached is not a prioritisation decision.

Two things in here are easy to report misleadingly and are therefore reported
with their ceilings.

**Window attainment has a ceiling below 100%.** A finding whose window closed
before the programme started can never be remediated inside it, whatever the
order. On a realistic backlog that is most of them, so an attainment figure
without the attainable maximum next to it makes every ordering look like a
failure and hides the fact that the ordering made no difference to that part.

**Summed EPSS is not a number of incidents.** Adding probabilities across
findings assumes independence, which is wrong: two findings on the same host
are not independent, and two instances of one CVE are not independent of each
other at all. The sum is useful as a relative ranking between orderings on the
same corpus and is not an expected count of anything. It is named
``exposure_score`` rather than anything that sounds like a forecast.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from pob.models import Corpus, Finding


@dataclass(frozen=True)
class Capacity:
    """How much remediation a programme can do, and how fast.

    ``per_week`` is in units of effort, which for most programmes is host
    reboots or change windows rather than CVEs. A finding's effort defaults to
    1, so the default reading is findings per week.
    """

    per_week: float
    # How long the programme runs. Beyond it the backlog is simply not done,
    # which is the honest answer and is what makes the comparison bite.
    weeks: int = 52

    def __post_init__(self) -> None:
        if self.per_week <= 0:
            raise ValueError("per_week must be positive")
        if self.weeks <= 0:
            raise ValueError("weeks must be positive")

    @property
    def total(self) -> float:
        return self.per_week * self.weeks


@dataclass
class Schedule:
    """When each finding was remediated, and what that covered."""

    # Day on which each finding was remediated, by finding id. A finding the
    # programme never reached is absent rather than recorded as a large number,
    # because "not done" and "done late" are different outcomes.
    remediated_on: dict[str, int] = field(default_factory=dict)
    effort_spent: float = 0.0
    days_run: int = 0

    def reached(self, finding: Finding) -> bool:
        return finding.finding_id in self.remediated_on


def run(corpus: Corpus, order: tuple[Finding, ...], capacity: Capacity) -> Schedule:
    """Work through ``order`` at ``capacity`` and record when each item lands.

    Effort is spent continuously across the week rather than in a lump at the
    end of it, so a finding's remediation day is proportional to how far down
    the queue it sits. A weekly lump would quantise every outcome to seven day
    steps and make a thirty day window look like four coarse buckets.
    """
    schedule = Schedule()
    per_day = capacity.per_week / 7.0
    horizon_days = capacity.weeks * 7
    spent = 0.0

    for finding in order:
        spent += finding.effort
        day = int(np.ceil(spent / per_day))
        if day > horizon_days:
            break
        schedule.remediated_on[finding.finding_id] = day
        schedule.effort_spent = spent
        schedule.days_run = day

    return schedule
