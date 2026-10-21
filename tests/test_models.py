import datetime as dt

import pytest

from pob.models import (
    PCI_CRITICAL_WINDOW_DAYS,
    PCI_OTHER_WINDOW_DAYS,
    Corpus,
    Finding,
    Severity,
    Vulnerability,
    severity_from_cvss,
)

TODAY = dt.date(2026, 10, 21)


def vuln(cve="CVE-2026-0001", cvss=9.8, epss=0.5, kev=False, released=None):
    return Vulnerability(cve, cvss, epss, kev, released or dt.date(2026, 10, 1))


def finding(cve="CVE-2026-0001", asset="host-1", criticality=0.5):
    return Finding(f"F-{cve}-{asset}", cve, asset, criticality, dt.date(2026, 10, 5))


class TestSeverityBands:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (10.0, Severity.CRITICAL),
            (9.0, Severity.CRITICAL),
            (8.9, Severity.HIGH),
            (7.0, Severity.HIGH),
            (6.9, Severity.MEDIUM),
            (4.0, Severity.MEDIUM),
            (3.9, Severity.LOW),
            (0.1, Severity.LOW),
            (0.0, Severity.NONE),
        ],
    )
    def test_the_cvss_v3_1_qualitative_scale(self, score, expected):
        """These bands are from the CVSS v3.1 specification, which is a
        published mapping rather than a choice made here."""
        assert severity_from_cvss(score) is expected

    @pytest.mark.parametrize(
        ("band", "in_scope"),
        [
            (Severity.CRITICAL, True),
            (Severity.HIGH, True),
            (Severity.MEDIUM, False),
            (Severity.LOW, False),
            (Severity.NONE, False),
        ],
    )
    def test_only_critical_and_high_fall_in_the_one_month_window(self, band, in_scope):
        """PCI DSS v4.0 requirement 6.3.3 puts critical and high security
        patches inside one month and leaves the rest to the entity."""
        assert band.in_pci_scope is in_scope


class TestWindows:
    def test_the_window_runs_from_patch_release_not_from_discovery(self):
        """The detail most tooling gets wrong. A finding discovered on day 25
        of its window has five days left, not thirty."""
        released = TODAY - dt.timedelta(days=25)
        corpus = Corpus((finding(),), {"CVE-2026-0001": vuln(released=released)}, as_of=TODAY)
        assert corpus.days_since_patch(corpus.findings[0]) == 25
        assert corpus.days_remaining(corpus.findings[0]) == PCI_CRITICAL_WINDOW_DAYS - 25

    def test_a_closed_window_reports_negative_days_rather_than_zero(self):
        """Reporting it as zero would hide how much of a backlog was already
        out of compliance before the programme started."""
        released = TODAY - dt.timedelta(days=200)
        corpus = Corpus((finding(),), {"CVE-2026-0001": vuln(released=released)}, as_of=TODAY)
        assert corpus.days_remaining(corpus.findings[0]) == PCI_CRITICAL_WINDOW_DAYS - 200

    def test_a_medium_severity_finding_gets_the_longer_example_window(self):
        corpus = Corpus(
            (finding(),),
            {"CVE-2026-0001": vuln(cvss=5.0, released=TODAY - dt.timedelta(days=10))},
            as_of=TODAY,
        )
        assert corpus.days_remaining(corpus.findings[0]) == PCI_OTHER_WINDOW_DAYS - 10


class TestCorpusIntegrity:
    def test_a_finding_with_no_vulnerability_record_is_refused(self):
        """Silently dropping it would change the denominator of every
        measurement."""
        with pytest.raises(ValueError, match="no vulnerability record"):
            Corpus((finding(cve="CVE-2026-9999"),), {"CVE-2026-0001": vuln()}, as_of=TODAY)

    def test_the_error_says_how_many_and_gives_examples(self):
        findings = tuple(finding(cve=f"CVE-2026-{index:04d}") for index in range(5))
        with pytest.raises(ValueError, match="5 finding"):
            Corpus(findings, {}, as_of=TODAY)

    def test_kev_findings_selects_by_the_vulnerability_record(self):
        corpus = Corpus(
            (finding(cve="CVE-2026-0001"), finding(cve="CVE-2026-0002")),
            {
                "CVE-2026-0001": vuln("CVE-2026-0001", kev=True),
                "CVE-2026-0002": vuln("CVE-2026-0002", kev=False),
            },
            as_of=TODAY,
        )
        assert [f.cve for f in corpus.kev_findings] == ["CVE-2026-0001"]


class TestSeverityAndProbabilityAreDifferentThings:
    def test_a_vulnerability_carries_both_separately(self):
        """The distinction the whole project rests on. A severity and a
        probability are not the same kind of number, and a record that put them
        in one column would invite an ordering that treats them as
        interchangeable."""
        record = vuln(cvss=9.8, epss=0.001)
        assert record.cvss == 9.8
        assert record.epss == 0.001
        assert record.cvss_severity is Severity.CRITICAL

    def test_a_critical_severity_can_carry_a_negligible_probability(self):
        """And the reverse. This is the case the comparison exists to find."""
        severe_but_quiet = vuln(cvss=9.8, epss=0.00002)
        mild_but_active = vuln(cvss=5.1, epss=0.81)
        assert severe_but_quiet.cvss_severity is Severity.CRITICAL
        assert mild_but_active.cvss_severity is Severity.MEDIUM
        assert mild_but_active.epss > severe_but_quiet.epss
