import datetime as dt

import pytest

from pob.corpus.generate import CorpusSpec, generate
from pob.models import Corpus, Finding, Vulnerability
from pob.rank.orderings import ORDERINGS, Ordering, ordering
from pob.simulate.remediate import Capacity

TODAY = dt.date(2026, 10, 21)
CAPACITY = Capacity(per_week=40, weeks=26)


def build(*records):
    """A tiny hand built corpus: (cve, cvss, epss, kev, age_days)."""
    vulnerabilities = {}
    findings = []
    for index, (cvss, epss, kev, age) in enumerate(records):
        cve = f"CVE-2026-{index:04d}"
        vulnerabilities[cve] = Vulnerability(
            cve, cvss, epss, kev, TODAY - dt.timedelta(days=age)
        )
        findings.append(Finding(f"F{index:03d}", cve, f"host-{index}", 0.5, TODAY))
    return Corpus(tuple(findings), vulnerabilities, as_of=TODAY)


class TestEveryOrderingIsAPermutation:
    @pytest.mark.parametrize("name", sorted(ORDERINGS))
    def test_it_returns_every_finding_exactly_once(self, name):
        """Dropping a finding would change the denominator of every
        measurement that uses the ordering."""
        corpus = generate(CorpusSpec(findings=2000, distinct_cves=600, seed=3))
        ordered = ORDERINGS[name](corpus, CAPACITY)
        assert len(ordered) == len(corpus.findings)
        assert {f.finding_id for f in ordered} == {f.finding_id for f in corpus.findings}

    def test_an_ordering_that_drops_findings_is_refused(self):
        broken = Ordering(
            name="broken", summary="", blind_to="", key=lambda corpus, capacity: corpus.findings[:-1]
        )
        corpus = generate(CorpusSpec(findings=100, distinct_cves=50, seed=1))
        with pytest.raises(ValueError, match="must be a permutation"):
            broken(corpus, CAPACITY)

    @pytest.mark.parametrize("name", sorted(ORDERINGS))
    def test_it_is_deterministic(self, name):
        """Including the random one, which is seeded. A comparison between
        orderings that is not reproducible is not a comparison."""
        corpus = generate(CorpusSpec(findings=500, distinct_cves=200, seed=4))
        first = ORDERINGS[name](corpus, CAPACITY)
        second = ORDERINGS[name](corpus, CAPACITY)
        assert [f.finding_id for f in first] == [f.finding_id for f in second]


class TestOrderingsDoWhatTheyClaim:
    def test_cvss_sorts_by_severity(self):
        corpus = build((4.0, 0.9, False, 1), (9.8, 0.001, False, 1), (7.1, 0.5, False, 1))
        ordered = ORDERINGS["cvss"](corpus, CAPACITY)
        assert [corpus.vulnerabilities[f.cve].cvss for f in ordered] == [9.8, 7.1, 4.0]

    def test_epss_sorts_by_probability_and_ignores_severity(self):
        corpus = build((9.8, 0.001, False, 1), (4.0, 0.9, False, 1))
        ordered = ORDERINGS["epss"](corpus, CAPACITY)
        assert corpus.vulnerabilities[ordered[0].cve].epss == 0.9
        assert corpus.vulnerabilities[ordered[0].cve].cvss == 4.0

    def test_kev_first_puts_the_catalogue_ahead_of_a_higher_score(self):
        """The case this ordering exists for: a known exploited vulnerability
        with a low current probability still comes first."""
        corpus = build((5.0, 0.0001, True, 1), (9.9, 0.7, False, 1))
        ordered = ORDERINGS["kev-then-epss"](corpus, CAPACITY)
        assert corpus.vulnerabilities[ordered[0].cve].in_kev is True
        assert corpus.vulnerabilities[ordered[0].cve].epss == 0.0001

    def test_due_date_puts_the_most_overdue_first(self):
        corpus = build((9.0, 0.1, False, 400), (9.0, 0.1, False, 10))
        ordered = ORDERINGS["due-date"](corpus, CAPACITY)
        assert corpus.days_remaining(ordered[0]) < corpus.days_remaining(ordered[1])

    def test_exposure_weights_probability_by_asset_criticality(self):
        vulnerabilities = {
            "CVE-A": Vulnerability("CVE-A", 5.0, 0.5, False, TODAY),
            "CVE-B": Vulnerability("CVE-B", 5.0, 0.2, False, TODAY),
        }
        findings = (
            Finding("F1", "CVE-A", "quiet-host", 0.01, TODAY),
            Finding("F2", "CVE-B", "payment-host", 0.99, TODAY),
        )
        corpus = Corpus(findings, vulnerabilities, as_of=TODAY)
        ordered = ORDERINGS["exposure"](corpus, CAPACITY)
        # 0.2 * 0.99 beats 0.5 * 0.01, so the lower probability on the more
        # exposed host comes first. Neither CVSS nor EPSS can see that.
        assert ordered[0].finding_id == "F2"

    def test_a_tie_is_broken_by_finding_id_not_by_corpus_order(self):
        """Without it, two orderings agreeing on every score would still
        differ, and the difference would look like a finding."""
        corpus = build((7.0, 0.1, False, 5), (7.0, 0.1, False, 5), (7.0, 0.1, False, 5))
        ordered = ORDERINGS["cvss"](corpus, CAPACITY)
        assert [f.finding_id for f in ordered] == sorted((f.finding_id for f in ordered), reverse=True)


class TestWindowFirstIsTheSteelman:
    def test_it_skips_deadlines_the_rate_cannot_make(self):
        """Earliest deadline first is optimal only on a feasible set. On a
        backlog far larger than the capacity it is the worst choice, because
        the tightest deadlines are exactly the ones a queue cannot reach.
        """
        # Ten findings all due in one day, at a rate of one a day. Only the
        # first is reachable in time, so a sensible plan takes one and moves
        # on rather than attempting all ten and missing all ten.
        corpus = build(*[(9.0, 0.1, False, 29)] * 10)
        ordered = ORDERINGS["window-first"](corpus, Capacity(per_week=7, weeks=4))
        assert corpus.days_remaining(ordered[0]) == 1

    def test_it_beats_every_other_ordering_on_window_attainment(self):
        """If it did not, it would be a foil rather than a steelman and the
        comparison would be unfair to the compliance driven approach."""
        from pob.simulate.metrics import score
        from pob.simulate.remediate import run

        corpus = generate(CorpusSpec(findings=5000, distinct_cves=1500, seed=5))
        results = {}
        for name, candidate in ORDERINGS.items():
            order = candidate(corpus, CAPACITY)
            results[name] = score(corpus, name, order, run(corpus, order, CAPACITY), CAPACITY).window_attainment
        assert max(results, key=results.get) == "window-first"

    def test_the_naive_version_still_scores_zero_which_is_why_it_is_kept(self):
        """due-date is retained to show what the obvious reading of a
        compliance requirement costs."""
        from pob.simulate.metrics import score
        from pob.simulate.remediate import run

        corpus = generate(CorpusSpec(findings=3000, distinct_cves=900, seed=6))
        order = ORDERINGS["due-date"](corpus, CAPACITY)
        outcome = score(corpus, "due-date", order, run(corpus, order, CAPACITY), CAPACITY)
        assert outcome.window_attainment == 0.0


class TestMetadata:
    @pytest.mark.parametrize("name", sorted(ORDERINGS))
    def test_every_ordering_says_what_it_is_blind_to(self, name):
        """A comparison that does not say so invites the reader to think the
        winner is simply better."""
        entry = ORDERINGS[name]
        assert entry.summary.endswith(".")
        assert len(entry.blind_to) > 10

    def test_an_unknown_ordering_lists_the_alternatives(self):
        with pytest.raises(KeyError, match="available: cvss"):
            ordering("severity")

    def test_the_random_baseline_is_present(self):
        """A prioritisation scheme that does not beat shuffling the backlog is
        not a prioritisation scheme, and that comparison is almost never
        published."""
        assert "random" in ORDERINGS
