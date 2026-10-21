"""The types the whole benchmark is expressed in.

One distinction runs through this file and it is the thing the project exists
to make measurable: a severity and a probability are not the same kind of
number, and a tool that puts them in the same column invites an ordering that
treats them as interchangeable.

CVSS is a severity: how bad it would be if exploited, on a scale somebody
designed. EPSS is a probability: how likely exploitation activity is to be
observed in the next thirty days, estimated daily from evidence. Multiplying
them is not meaningless, but adding them is, and sorting by whichever is larger
is nonsense. They are separate fields with separate types here so that any code
combining them has to say how.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from enum import StrEnum

# PCI DSS v4.0 requirement 6.3.3 states that critical or high security patches
# are installed within one month of release. The window therefore starts at
# patch availability, not at the scan that found the finding, which is the
# detail most tooling gets wrong: a finding discovered on day 25 of its window
# has five days left, not thirty.
PCI_CRITICAL_WINDOW_DAYS = 30

# The same requirement leaves everything else to "an appropriate time frame as
# determined by the entity", giving three months as an example. Three months is
# used here as the example it is, not as a requirement.
PCI_OTHER_WINDOW_DAYS = 90


class Severity(StrEnum):
    """A risk ranking band.

    PCI DSS v4.0 requirement 6.3.1 asks for a ranking "based on industry best
    practices and consideration of potential impact" and identifies, at
    minimum, everything high or critical. It does not name CVSS or any other
    scoring system, which is the opening this project measures: the band a
    finding lands in is a choice the entity makes, and ranking by exploitation
    probability is a defensible way to make it rather than a departure from the
    standard.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

    @property
    def in_pci_scope(self) -> bool:
        """Whether this band falls under the one month window."""
        return self in (Severity.CRITICAL, Severity.HIGH)


def severity_from_cvss(score: float) -> Severity:
    """The CVSS v3.1 qualitative rating for a base score.

    These bands are from the CVSS v3.1 specification's qualitative severity
    rating scale, which is a published mapping rather than a choice made here.
    """
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.NONE


@dataclass(frozen=True)
class Vulnerability:
    """What is known about one CVE, independent of where it is installed."""

    cve: str
    cvss: float
    # A probability of exploitation activity being observed in the next thirty
    # days. Not a severity, not a score out of ten, and not comparable to one.
    epss: float
    # Membership of CISA's Known Exploited Vulnerabilities catalogue, which is
    # evidence of exploitation rather than an estimate of it. A CVE can be in
    # the catalogue with a low EPSS, because EPSS asks about the next thirty
    # days and the catalogue records that it has happened at all.
    in_kev: bool
    patch_released: dt.date

    @property
    def cvss_severity(self) -> Severity:
        return severity_from_cvss(self.cvss)


@dataclass(frozen=True)
class Finding:
    """One vulnerability on one host, which is the unit of remediation work.

    The distinction from a Vulnerability is the whole reason an ordering can be
    wrong. A CVE with a high probability on one development host is less work
    and less exposure than a moderate one on four hundred payment terminals,
    and an ordering that sorts CVEs rather than findings cannot see that.
    """

    finding_id: str
    cve: str
    asset_id: str
    # How exposed this host is, on a scale the entity sets. Present because
    # neither CVSS nor EPSS knows anything about it, and because an ordering
    # that ignores it is making an assumption rather than avoiding one.
    asset_criticality: float
    first_seen: dt.date
    # Remediation effort in whatever unit the programme counts in: usually
    # host reboots or change windows rather than CVEs.
    effort: float = 1.0


@dataclass(frozen=True)
class Corpus:
    """A set of findings and what is known about the CVEs in them."""

    findings: tuple[Finding, ...]
    vulnerabilities: dict[str, Vulnerability]
    # The day the programme starts work. Every window and age is measured from
    # the patch release date against this, so a corpus carries its own "now"
    # rather than reading the clock and becoming unreproducible.
    as_of: dt.date

    def __post_init__(self) -> None:
        missing = {finding.cve for finding in self.findings} - set(self.vulnerabilities)
        if missing:
            example = sorted(missing)[:3]
            raise ValueError(
                f"{len(missing)} finding(s) reference a CVE with no vulnerability record, for example {example}. "
                f"A finding whose CVE is unknown cannot be ranked by any ordering, and silently dropping it "
                f"would change the denominator of every measurement."
            )

    @property
    def kev_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if self.vulnerabilities[f.cve].in_kev)

    def days_since_patch(self, finding: Finding) -> int:
        return (self.as_of - self.vulnerabilities[finding.cve].patch_released).days

    def days_remaining(self, finding: Finding) -> int:
        """Days left in this finding's PCI window, which may be negative.

        Negative means the window closed before the programme started. That is
        a real and common state, and reporting it as zero would hide how much
        of a backlog was already out of compliance on day one.
        """
        vulnerability = self.vulnerabilities[finding.cve]
        window = PCI_CRITICAL_WINDOW_DAYS if vulnerability.cvss_severity.in_pci_scope else PCI_OTHER_WINDOW_DAYS
        return window - self.days_since_patch(finding)
