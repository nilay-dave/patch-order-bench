"""The orderings being compared, including the one nobody publishes.

Each takes a corpus and returns its findings in the order a programme would
work through them. They are deliberately simple: the interesting part of this
project is not a clever ranking function, it is measuring what the obvious ones
cost.

Two of them exist to keep the comparison honest.

``random`` is the baseline. A prioritisation scheme that does not beat shuffling
the backlog is not a prioritisation scheme, and that comparison is almost never
published, which means a reader has no idea whether a reported improvement is
large or trivial. It is seeded, so it is reproducible, and the benchmark runs it
over several seeds because a single shuffle is one sample of a distribution.

``cvss`` is the incumbent, and it is here because it is what the scanner prints.
Most programmes rank by it for that reason rather than because anyone chose it.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

import numpy as np

from pob.models import Corpus, Finding
from pob.simulate.remediate import Capacity


@dataclass(frozen=True)
class Ordering:
    """A named way of sorting a backlog, with what it assumes written down.

    Orderings are given the capacity, which most of them ignore. The one that
    cannot ignore it is the compliance ordering, and the reason is the whole
    argument for passing it: whether a deadline can be met depends on how fast
    the programme moves, so an ordering that optimises for deadlines without
    knowing the rate is optimising for a constraint it cannot evaluate. Making
    capacity available to all of them is cheaper than a second kind of
    ordering, and a real programme knows its own rate.
    """

    name: str
    summary: str
    # What this ordering cannot see. Every one of them is blind to something,
    # and a comparison that does not say so invites the reader to think the
    # winner is simply better.
    blind_to: str
    key: Callable[[Corpus, Capacity], Sequence[Finding]]

    def __call__(self, corpus: Corpus, capacity: Capacity) -> tuple[Finding, ...]:
        ordered = tuple(self.key(corpus, capacity))
        if len(ordered) != len(corpus.findings):
            raise ValueError(
                f"ordering {self.name!r} returned {len(ordered)} findings from a corpus of "
                f"{len(corpus.findings)}. An ordering must be a permutation: dropping findings would "
                f"change the denominator of every measurement that uses it."
            )
        return ordered


def _sorted_by(corpus: Corpus, score: Callable[[Finding], tuple]) -> list[Finding]:
    # Descending by score, with the finding id as the final tie break so the
    # result does not depend on the order the corpus happened to be built in.
    # Without it, two orderings that agree on every score would still differ,
    # and the difference would look like a finding.
    return sorted(corpus.findings, key=lambda finding: (*score(finding), finding.finding_id), reverse=True)


def by_cvss(corpus: Corpus, capacity: Capacity) -> list[Finding]:
    return _sorted_by(corpus, lambda f: (corpus.vulnerabilities[f.cve].cvss,))


def by_epss(corpus: Corpus, capacity: Capacity) -> list[Finding]:
    return _sorted_by(corpus, lambda f: (corpus.vulnerabilities[f.cve].epss,))


def kev_first_then_epss(corpus: Corpus, capacity: Capacity) -> list[Finding]:
    return _sorted_by(
        corpus,
        lambda f: (corpus.vulnerabilities[f.cve].in_kev, corpus.vulnerabilities[f.cve].epss),
    )


def kev_first_then_cvss(corpus: Corpus, capacity: Capacity) -> list[Finding]:
    return _sorted_by(
        corpus,
        lambda f: (corpus.vulnerabilities[f.cve].in_kev, corpus.vulnerabilities[f.cve].cvss),
    )


def by_expected_exposure(corpus: Corpus, capacity: Capacity) -> list[Finding]:
    """Exploitation probability weighted by how exposed the host is.

    The only ordering here that uses anything about the asset. Neither CVSS nor
    EPSS knows whether a host is a payment terminal or a developer's laptop,
    and a programme that ignores that is making an assumption rather than
    avoiding one.

    The weighting is a product, which assumes the two are independent. They are
    not quite: an internet facing host is both more exposed and more likely to
    be attacked. Stated because the product is a convenience, not a model.
    """
    return _sorted_by(
        corpus,
        lambda f: (corpus.vulnerabilities[f.cve].epss * max(f.asset_criticality, 1e-9),),
    )


def by_due_date(corpus: Corpus, capacity: Capacity) -> list[Finding]:
    """Soonest compliance deadline first, which is what an audit drives.

    Ordered by days remaining ascending, so the most overdue comes first. This
    is the ordering a programme ends up with when the only pressure on it is
    the assessment date, and it is included because that is a real way
    programmes are run rather than a straw man.
    """
    return sorted(
        corpus.findings,
        key=lambda finding: (corpus.days_remaining(finding), finding.finding_id),
    )


def by_savable_window(corpus: Corpus, capacity: Capacity) -> list[Finding]:
    """Deadline order, skipping the deadlines this rate cannot make.

    The steelman of compliance driven ordering, and getting it right took two
    attempts.

    The naive version sorts by days remaining ascending, most overdue first.
    That spends the whole budget on findings whose window has already closed
    and reaches none that could still be saved: it scores zero. True, and a
    straw man, since nobody sensible runs a programme that way.

    The second attempt put the still open windows first, soonest to close at
    the front. That also scored zero, and the reason is the interesting part:
    earliest deadline first is optimal only when the set is feasible. On a
    backlog far larger than the capacity it is the worst possible choice,
    because the tightest deadlines are exactly the ones a queue cannot reach in
    time, and every one of them is attempted and missed.

    What actually maximises the count met is to walk the deadlines in order and
    accept one only if the position it would take is still inside it. For unit
    sized work at a constant rate that greedy is optimal, and it is what a
    programme planning around an assessment would do once it noticed some
    deadlines were already unreachable.
    """
    rate = capacity.per_week / 7.0
    still_open = sorted(
        (f for f in corpus.findings if corpus.days_remaining(f) >= 0),
        key=lambda f: (corpus.days_remaining(f), f.finding_id),
    )
    overdue = sorted(
        (f for f in corpus.findings if corpus.days_remaining(f) < 0),
        key=lambda f: (-corpus.days_remaining(f), f.finding_id),
    )

    feasible: list[Finding] = []
    skipped: list[Finding] = []
    position = 0
    for finding in still_open:
        day_if_taken = int(np.ceil((position + finding.effort) / rate))
        if day_if_taken <= corpus.days_remaining(finding):
            feasible.append(finding)
            position += finding.effort
        else:
            skipped.append(finding)

    return [*feasible, *skipped, *overdue]


def random_order(seed: int = 0) -> Callable[[Corpus, Capacity], list[Finding]]:
    """A shuffle, which is the baseline every comparison needs and few show."""

    def order(corpus: Corpus, capacity: Capacity) -> list[Finding]:
        rng = np.random.default_rng(seed)
        findings = list(corpus.findings)
        indices = rng.permutation(len(findings))
        return [findings[index] for index in indices]

    return order


ORDERINGS: dict[str, Ordering] = {
    ordering.name: ordering
    for ordering in (
        Ordering(
            name="cvss",
            summary="Highest CVSS base score first, which is what the scanner prints.",
            blind_to="whether anyone is exploiting it, and how exposed the host is",
            key=by_cvss,
        ),
        Ordering(
            name="epss",
            summary="Highest probability of exploitation activity in the next thirty days first.",
            blind_to=(
                "how bad exploitation would be, how exposed the host is, and anything already "
                "exploited whose current activity has died down"
            ),
            key=by_epss,
        ),
        Ordering(
            name="kev-then-epss",
            summary="Known exploited vulnerabilities first, then by exploitation probability.",
            blind_to="how bad exploitation would be, and how exposed the host is",
            key=kev_first_then_epss,
        ),
        Ordering(
            name="kev-then-cvss",
            summary="Known exploited vulnerabilities first, then by severity.",
            blind_to="exploitation probability below the catalogue threshold, and asset exposure",
            key=kev_first_then_cvss,
        ),
        Ordering(
            name="exposure",
            summary="Exploitation probability weighted by asset criticality.",
            blind_to="how bad exploitation would be, and anything exploited at a low current rate",
            key=by_expected_exposure,
        ),
        Ordering(
            name="due-date",
            summary="Most overdue first, which is what an audit finding list looks like.",
            blind_to=(
                "everything about the vulnerability except its severity band, and the fact that an "
                "already closed window cannot be reopened"
            ),
            key=by_due_date,
        ),
        Ordering(
            name="window-first",
            summary="Soonest to close first among windows still open, then the overdue.",
            blind_to="everything about the vulnerability except the band its severity put it in",
            key=by_savable_window,
        ),
        Ordering(
            name="random",
            summary="A seeded shuffle. The baseline an ordering has to beat to be one.",
            blind_to="everything, which is the point",
            key=random_order(0),
        ),
    )
}


def ordering(name: str) -> Ordering:
    try:
        return ORDERINGS[name]
    except KeyError:
        available = ", ".join(sorted(ORDERINGS))
        raise KeyError(f"no ordering called {name!r}; available: {available}") from None
