import datetime as dt

import pytest

from pob.corpus.generate import CorpusSpec, generate
from pob.models import Corpus, Finding, Vulnerability
from pob.rank.orderings import ORDERINGS
from pob.simulate.metrics import attainable_in_window, coverage_curve, exposure_score, score
from pob.simulate.remediate import Capacity, run

TODAY = dt.date(2026, 10, 21)


def build(count=10, cvss=9.0, epss=0.1, kev=False, age=5, effort=1.0):
    vulnerabilities = {}
    findings = []
    for index in range(count):
        cve = f"CVE-2026-{index:04d}"
        vulnerabilities[cve] = Vulnerability(cve, cvss, epss, kev, TODAY - dt.timedelta(days=age))
        findings.append(Finding(f"F{index:03d}", cve, f"host-{index}", 0.5, TODAY, effort))
    return Corpus(tuple(findings), vulnerabilities, as_of=TODAY)


class TestCapacity:
    @pytest.mark.parametrize("kwargs", [{"per_week": 0}, {"per_week": -1}])
    def test_the_rate_must_be_positive(self, kwargs):
        with pytest.raises(ValueError, match="per_week"):
            Capacity(**kwargs)

    def test_the_horizon_must_be_positive(self):
        with pytest.raises(ValueError, match="weeks"):
            Capacity(per_week=10, weeks=0)

    def test_total_is_rate_times_horizon(self):
        assert Capacity(per_week=40, weeks=26).total == 1040


class TestSchedule:
    def test_effort_is_spent_continuously_across_the_week(self):
        """A weekly lump would quantise every outcome to seven day steps and
        make a thirty day window look like four coarse buckets."""
        corpus = build(count=14)
        schedule = run(corpus, corpus.findings, Capacity(per_week=7, weeks=4))
        days = sorted(set(schedule.remediated_on.values()))
        assert days == list(range(1, 15)), "one a day, not seven on day seven"

    def test_nothing_beyond_the_horizon_is_recorded(self):
        """Not done and done late are different outcomes, so a finding the
        programme never reached is absent rather than recorded with a large
        day number."""
        corpus = build(count=100)
        schedule = run(corpus, corpus.findings, Capacity(per_week=7, weeks=1))
        assert len(schedule.remediated_on) == 7
        assert not schedule.reached(corpus.findings[50])

    def test_effort_above_one_consumes_more_capacity(self):
        corpus = build(count=10, effort=2.0)
        schedule = run(corpus, corpus.findings, Capacity(per_week=14, weeks=1))
        assert len(schedule.remediated_on) == 7

    def test_an_empty_backlog_schedules_nothing(self):
        corpus = build(count=1)
        schedule = run(corpus, (), Capacity(per_week=10, weeks=1))
        assert schedule.remediated_on == {}


class TestAttainableCeiling:
    def test_the_ceiling_accounts_for_the_rate_not_just_the_deadline(self):
        """Using the still open set as the denominator charged every ordering
        for deadlines no rate could have met, and made the comparison look
        like universal failure."""
        # Twenty findings all due in one day, at one a day. Only one can be met.
        corpus = build(count=20, age=29)
        attainable = attainable_in_window(corpus, Capacity(per_week=7, weeks=8))
        still_open = [f for f in corpus.findings if corpus.days_remaining(f) >= 0]
        assert len(still_open) == 20
        assert len(attainable) == 1

    def test_a_faster_rate_raises_the_ceiling(self):
        corpus = build(count=40, age=20)
        slow = attainable_in_window(corpus, Capacity(per_week=7, weeks=8))
        fast = attainable_in_window(corpus, Capacity(per_week=70, weeks=8))
        assert len(fast) > len(slow)

    def test_an_already_closed_window_is_never_attainable(self):
        corpus = build(count=10, age=400)
        assert attainable_in_window(corpus, Capacity(per_week=1000, weeks=52)) == []

    def test_only_findings_in_pci_scope_count(self):
        """The one month window applies to critical and high. A medium
        severity finding is not measured against it."""
        corpus = build(count=10, cvss=5.0, age=5)
        assert attainable_in_window(corpus, Capacity(per_week=70, weeks=8)) == []

    def test_no_ordering_can_exceed_the_ceiling(self):
        """Which is what makes it a ceiling rather than an estimate."""
        corpus = generate(CorpusSpec(findings=4000, distinct_cves=1200, seed=8))
        capacity = Capacity(per_week=40, weeks=26)
        ceiling = len(attainable_in_window(corpus, capacity))
        for name, candidate in ORDERINGS.items():
            order = candidate(corpus, capacity)
            outcome = score(corpus, name, order, run(corpus, order, capacity), capacity)
            assert outcome.in_scope_remediated_in_window <= ceiling, name


class TestScoring:
    def test_kev_coverage_is_a_share_of_the_kev_findings(self):
        corpus = generate(CorpusSpec(findings=2000, distinct_cves=600, seed=9))
        capacity = Capacity(per_week=40, weeks=26)
        order = ORDERINGS["kev-then-epss"](corpus, capacity)
        outcome = score(corpus, "kev-then-epss", order, run(corpus, order, capacity), capacity)
        assert outcome.kev_coverage == pytest.approx(outcome.kev_remediated / outcome.kev_findings)

    def test_effort_to_cover_is_none_when_the_programme_never_got_there(self):
        """Rather than the horizon. Did not reach it and reached it on the
        last day are different answers, and averaging them hides the first."""
        corpus = generate(CorpusSpec(findings=3000, distinct_cves=900, seed=10))
        capacity = Capacity(per_week=5, weeks=2)
        order = ORDERINGS["cvss"](corpus, capacity)
        outcome = score(corpus, "cvss", order, run(corpus, order, capacity), capacity)
        assert outcome.effort_to_90pc_kev is None

    def test_effort_to_cover_is_reported_when_it_was_reached(self):
        corpus = generate(CorpusSpec(findings=3000, distinct_cves=900, seed=10))
        capacity = Capacity(per_week=100, weeks=52)
        order = ORDERINGS["kev-then-epss"](corpus, capacity)
        outcome = score(corpus, "kev-then-epss", order, run(corpus, order, capacity), capacity)
        assert outcome.effort_to_90pc_kev is not None
        assert outcome.effort_to_90pc_kev <= capacity.total

    def test_exposure_score_is_probability_times_criticality(self):
        corpus = build(count=1, epss=0.4)
        assert exposure_score(corpus, corpus.findings[0]) == pytest.approx(0.4 * 0.5)

    def test_a_zero_capacity_horizon_scores_zero_everywhere(self):
        corpus = generate(CorpusSpec(findings=500, distinct_cves=200, seed=11))
        capacity = Capacity(per_week=0.001, weeks=1)
        order = ORDERINGS["cvss"](corpus, capacity)
        outcome = score(corpus, "cvss", order, run(corpus, order, capacity), capacity)
        assert outcome.kev_coverage == 0.0
        assert outcome.window_attainment == 0.0


class TestCoverageCurve:
    def test_it_is_monotone_and_ends_at_full_coverage(self):
        corpus = generate(CorpusSpec(findings=2000, distinct_cves=600, seed=12))
        capacity = Capacity(per_week=40, weeks=26)
        order = ORDERINGS["kev-then-epss"](corpus, capacity)
        effort, share = coverage_curve(corpus, order, corpus.kev_findings)
        assert list(share) == sorted(share)
        assert share[-1] == pytest.approx(1.0, abs=0.02)
        assert list(effort) == sorted(effort)

    def test_an_empty_order_gives_a_degenerate_curve(self):
        corpus = build(count=3)
        effort, share = coverage_curve(corpus, (), corpus.findings)
        assert list(effort) == [0.0] and list(share) == [0.0]

    def test_the_curve_separates_orderings_that_a_single_number_would_not(self):
        """One ordering can win early and lose late, and a coverage figure at
        one capacity hides that completely."""
        corpus = generate(CorpusSpec(findings=3000, distinct_cves=900, seed=13))
        capacity = Capacity(per_week=40, weeks=26)
        curves = {}
        for name in ("cvss", "kev-then-epss"):
            order = ORDERINGS[name](corpus, capacity)
            curves[name] = coverage_curve(corpus, order, corpus.kev_findings)
        early_cvss = curves["cvss"][1][5]
        early_kev = curves["kev-then-epss"][1][5]
        assert early_kev > early_cvss
