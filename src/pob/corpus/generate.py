"""Generates a finding corpus, with every parameter declared.

**Everything this produces is a simulation.** The live feed path exists in
``pob.feeds`` and could not be run while this was built, because the
environment it was written in cannot reach epss.cyentia.com or cisa.gov. So
nothing in this repository is a measurement of the real CVE population, and
every figure derived from it says so.

That makes the parameters load bearing, so they are declared rather than
buried, and split into the two kinds that matter.

**One is sourced.** FIRST's EPSS model documentation states that 3,735 of
139,473 CVSS 3.x CVEs score at or above 0.1, which is about 2.7%. The
generated EPSS distribution is calibrated to that figure, so the shape of the
long tail is anchored to something published rather than chosen to make a
point.

**The rest are choices**, and the most important of them is the correlation
between severity and exploitation probability. Every conclusion this project
reaches depends on it: at a correlation of 1 the two orderings are the same
ordering and there is nothing to measure, and at 0 they are unrelated. Rather
than pick a value and build an argument on it, the benchmark sweeps it and
reports whether the conclusion survives the range. A simulation whose result
holds across the plausible span of its least known parameter is worth
something; one tuned to a single value is worth nothing.

The mechanism is a latent variable, which is what makes the correlation a
single interpretable dial. An unobserved "how attackable is this" drives EPSS
and KEV membership directly, and drives CVSS only in proportion to the
correlation parameter, with the remainder coming from an independent "how bad
would it be" that nothing about exploitation knows.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from math import sqrt

import numpy as np

from pob.models import Corpus, Finding, Vulnerability

# The share of CVEs at or above EPSS 0.1, from FIRST's EPSS model
# documentation: 3,735 of 139,473 CVSS 3.x CVEs, which is 2.68%. The one
# distributional figure in this file that is not a choice.
SOURCED_SHARE_ABOVE_0_1 = 0.0268
SOURCED_SHARE_CITATION = "first.org/epss/model, 3,735 of 139,473 CVSS 3.x CVEs at or above 0.1"

# Chosen, not sourced: the median EPSS score. FIRST publishes the share at or
# above 0.1 and not a median, so this is a declared parameter. It is needed
# because one anchor is not enough to fix a distribution: calibrating on the
# 0.1 threshold alone forced a power curve so steep that over half the
# population landed on a floor of 1e-5, which is not what a real score
# distribution looks like and, worse, created a mass of ties that destroyed the
# rank correlation the whole sweep depends on.
CHOSEN_MEDIAN_EPSS = 0.0005

# The z score of the 1 - 0.0268 quantile of a standard normal, used to solve
# the lognormal width from the two anchors above.
_Z_AT_SOURCED_SHARE = 1.9305


# Abramowitz and Stegun 7.1.26, which approximates the error function to
# within 1.5e-7. Used instead of math.erf because math.erf is scalar and
# np.vectorize around it is a Python level loop: on the arrays this file
# builds that turned a test suite from seconds into minutes. 1.5e-7 is several
# orders of magnitude finer than needed to map a percentile onto a CVSS score
# reported to one decimal place.
_ERF_P = 0.3275911
_ERF_A = (0.254829592, -0.284496736, 1.421413741, -1.453152027, 1.061405429)


def _erf(values: np.ndarray) -> np.ndarray:
    sign = np.sign(values)
    x = np.abs(values)
    t = 1.0 / (1.0 + _ERF_P * x)
    series = t * (_ERF_A[0] + t * (_ERF_A[1] + t * (_ERF_A[2] + t * (_ERF_A[3] + t * _ERF_A[4]))))
    return sign * (1.0 - series * np.exp(-(x**2)))


def _normal_cdf(values: np.ndarray) -> np.ndarray:
    """The standard normal CDF.

    Phi(x) = (1 + erf(x / sqrt(2))) / 2, with a vectorised erf rather than
    scipy for one function.
    """
    return 0.5 * (1.0 + _erf(np.asarray(values, dtype=np.float64) / sqrt(2.0)))


@dataclass
class CorpusSpec:
    """Everything that decides what the generated corpus looks like.

    Each field says whether it is sourced or chosen, because a reader deciding
    how much to believe a result needs to know which parameters were measured
    and which were picked.
    """

    findings: int = 5_000
    distinct_cves: int = 800
    assets: int = 400

    # Sourced: calibrates the EPSS tail. See SOURCED_SHARE_CITATION.
    share_epss_above_0_1: float = SOURCED_SHARE_ABOVE_0_1

    # Chosen, and the parameter everything depends on. Swept by the benchmark
    # rather than argued for. Published work on the CVSS and EPSS relationship
    # describes it as weak, so the default sits low, and the sweep is what the
    # conclusions actually rest on.
    #
    # This is the LATENT rank correlation, and three distinctions matter.
    #
    # It is a rank correlation, not a Pearson one. The EPSS mapping is steeply
    # monotone and Pearson correlation is not preserved under a transform like
    # that: a latent correlation of 0.25 shows up as a Pearson correlation near
    # 0.06 on the generated scores. Rank correlation is preserved by a monotone
    # map, so the dial means something stable.
    #
    # It is latent, so the realized rank correlation is lower. CVSS is reported
    # to one decimal place, and the ties that creates flatten Spearman: 0.25
    # here comes out around 0.15 on the scores, and 0.8 comes out around 0.73.
    # describe_corpus reports the realized figure next to this one rather than
    # leaving a reader to discover the gap.
    cvss_epss_correlation: float = 0.25

    # Chosen: the CVSS marginal. Scanner output skews to medium and high
    # because that is what gets reported, so this is a beta on 0 to 10 with a
    # mean near 7. Plausible rather than measured.
    cvss_beta_a: float = 4.0
    cvss_beta_b: float = 1.8

    # Chosen: KEV membership. The catalogue records that exploitation has
    # happened, so membership concentrates among the most attackable CVEs, but
    # not perfectly: an entry from four years ago may see very little activity
    # in the next thirty days, and that case, in the catalogue with a low EPSS,
    # is exactly where an EPSS only ordering fails.
    kev_share: float = 0.04
    kev_latent_weight: float = 0.75

    # Chosen: how findings spread over CVEs and assets. A few CVEs appear on
    # much of the estate, which is what makes an ordering that sorts CVEs
    # rather than findings able to be wrong.
    cve_concentration_alpha: float = 1.2
    asset_concentration_alpha: float = 0.8

    # Chosen: patch ages. A real backlog holds findings whose window closed
    # long ago, so this reaches well past thirty days.
    patch_age_days_mean: float = 120.0
    patch_age_days_max: int = 1_460

    as_of: dt.date = field(default_factory=lambda: dt.date(2026, 10, 21))
    seed: int = 7

    def __post_init__(self) -> None:
        if self.findings <= 0 or self.distinct_cves <= 0 or self.assets <= 0:
            raise ValueError("findings, distinct_cves and assets must be positive")
        if not 0.0 <= self.cvss_epss_correlation <= 1.0:
            raise ValueError("cvss_epss_correlation must be between 0 and 1")
        if not 0.0 < self.share_epss_above_0_1 < 1.0:
            raise ValueError("share_epss_above_0_1 must be between 0 and 1")
        if not 0.0 <= self.kev_share <= 1.0:
            raise ValueError("kev_share must be between 0 and 1")
        if self.distinct_cves > self.findings:
            raise ValueError("a corpus cannot hold more distinct CVEs than findings")

    def describe(self) -> dict:
        """The spec, split by how much each parameter should be believed."""
        return {
            "sourced": {
                "share_epss_above_0_1": self.share_epss_above_0_1,
                "citation": SOURCED_SHARE_CITATION,
            },
            "chosen": {
                "cvss_epss_correlation": self.cvss_epss_correlation,
                "cvss_beta_a": self.cvss_beta_a,
                "cvss_beta_b": self.cvss_beta_b,
                "kev_share": self.kev_share,
                "kev_latent_weight": self.kev_latent_weight,
                "cve_concentration_alpha": self.cve_concentration_alpha,
                "asset_concentration_alpha": self.asset_concentration_alpha,
                "patch_age_days_mean": self.patch_age_days_mean,
            },
            "scale": {
                "findings": self.findings,
                "distinct_cves": self.distinct_cves,
                "assets": self.assets,
            },
            "seed": self.seed,
        }


def _epss_from_latent(latent: np.ndarray, share_above: float, median: float = CHOSEN_MEDIAN_EPSS) -> np.ndarray:
    """Map a standard normal latent to EPSS through a fitted lognormal.

    Lognormal in the score, which is to say normal in log10 of it, fitted
    through two anchors: the median, which is declared, and the share at or
    above 0.1, which is sourced. Two anchors are the minimum that fixes a two
    parameter distribution, and an earlier version used only the sourced one,
    which left the other end of the curve free to go somewhere absurd. It did.

    Being a strictly monotone function of the latent, this preserves rank
    order, so the correlation parameter means what it claims and produces no
    ties to flatten it.
    """
    mu = np.log10(median)
    # P(log10(epss) >= -1) = share_above, so (-1 - mu) / sigma is the z score
    # of the 1 - share_above quantile.
    z = _Z_AT_SOURCED_SHARE if abs(share_above - SOURCED_SHARE_ABOVE_0_1) < 1e-9 else _z_for(1 - share_above)
    sigma = (-1.0 - mu) / z
    return np.clip(10.0 ** (mu + sigma * latent), 1e-6, 1.0)


def _z_for(percentile: float, steps: int = 20_001) -> float:
    """The standard normal quantile, by inverting the CDF on a grid.

    Only used when a caller overrides the sourced share, which the benchmark
    does in its sensitivity sweep. Inverting on a grid rather than adding
    scipy for one call.
    """
    grid = np.linspace(-6.0, 6.0, steps)
    return float(np.interp(percentile, _normal_cdf(grid), grid))


def _beta_quantile(percentiles: np.ndarray, a: float, b: float, steps: int = 20_000) -> np.ndarray:
    """The beta quantile function, by inverting its CDF on a grid.

    numpy samples from a beta but has no quantile function, and scipy is not
    worth a dependency for one inversion. A fixed grid is accurate to 1/steps,
    which at twenty thousand steps is finer than the single decimal place a
    CVSS score is reported to.
    """
    grid = np.linspace(1e-9, 1.0 - 1e-9, steps)
    density = grid ** (a - 1.0) * (1.0 - grid) ** (b - 1.0)
    cdf = np.cumsum(density)
    cdf /= cdf[-1]
    return np.interp(percentiles, cdf, grid)


def _zipf_draws(total: int, buckets: int, alpha: float, rng: np.random.Generator) -> np.ndarray:
    """Spread ``total`` items over ``buckets`` with a Zipf weight."""
    ranks = np.arange(1, buckets + 1, dtype=np.float64)
    weights = ranks ** (-alpha)
    weights /= weights.sum()
    return rng.choice(buckets, size=total, p=weights)


def generate(spec: CorpusSpec) -> Corpus:
    """Build a simulated corpus from a spec."""
    rng = np.random.default_rng(spec.seed)
    count = spec.distinct_cves

    exploitability = rng.standard_normal(count)
    impact = rng.standard_normal(count)
    rho = spec.cvss_epss_correlation
    cvss_latent = rho * exploitability + np.sqrt(max(0.0, 1.0 - rho**2)) * impact

    epss = _epss_from_latent(exploitability, spec.share_epss_above_0_1)
    cvss = np.round(10.0 * _beta_quantile(_normal_cdf(cvss_latent), spec.cvss_beta_a, spec.cvss_beta_b), 1)

    kev_score = spec.kev_latent_weight * exploitability + (1.0 - spec.kev_latent_weight) * rng.standard_normal(count)
    in_kev = kev_score >= np.quantile(kev_score, 1.0 - spec.kev_share)

    ages = np.minimum(rng.exponential(spec.patch_age_days_mean, size=count), spec.patch_age_days_max)

    vulnerabilities: dict[str, Vulnerability] = {}
    cve_ids: list[str] = []
    for index in range(count):
        cve = f"CVE-2026-{index + 1000:05d}"
        cve_ids.append(cve)
        vulnerabilities[cve] = Vulnerability(
            cve=cve,
            cvss=float(cvss[index]),
            epss=float(epss[index]),
            in_kev=bool(in_kev[index]),
            patch_released=spec.as_of - dt.timedelta(days=int(ages[index])),
        )

    cve_draws = _zipf_draws(spec.findings, count, spec.cve_concentration_alpha, rng)
    asset_draws = _zipf_draws(spec.findings, spec.assets, spec.asset_concentration_alpha, rng)
    criticality = rng.beta(2.0, 5.0, size=spec.assets)

    findings: list[Finding] = []
    seen: set[tuple[int, int]] = set()
    index = 0
    # Drawing exactly `findings` pairs and discarding the collisions produced a
    # corpus a third smaller than asked for, because both draws are
    # concentrated and collide often. The loop now keeps drawing until the
    # requested number of distinct pairs exists, so a spec that says five
    # thousand findings produces five thousand and every result is comparable
    # across specs rather than across whatever survived.
    while len(findings) < spec.findings:
        if index >= len(cve_draws):
            cve_draws = _zipf_draws(spec.findings, count, spec.cve_concentration_alpha, rng)
            asset_draws = _zipf_draws(spec.findings, spec.assets, spec.asset_concentration_alpha, rng)
            index = 0
        pair = (int(cve_draws[index]), int(asset_draws[index]))
        index += 1
        # Checked before the collision test, not after it. After it the guard
        # is unreachable: once every pair has been seen, every draw hits the
        # collision branch and continues, so the loop spins forever. The test
        # named for this was, in fact, looping.
        if len(seen) >= count * spec.assets:
            raise ValueError(
                f"a corpus of {spec.findings} distinct findings is impossible with "
                f"{count} CVEs over {spec.assets} assets, which allow at most "
                f"{count * spec.assets}"
            )
        # One CVE appears at most once per asset. A duplicate is the same
        # remediation, and counting it twice would inflate every coverage
        # figure the benchmark reports.
        if pair in seen:
            continue
        seen.add(pair)
        cve_index, asset_index = pair
        cve = cve_ids[cve_index]
        age = (spec.as_of - vulnerabilities[cve].patch_released).days
        findings.append(
            Finding(
                finding_id=f"F{len(findings):08d}",
                cve=cve,
                asset_id=f"asset-{asset_index:05d}",
                asset_criticality=float(criticality[asset_index]),
                # A finding cannot be first seen before its patch existed.
                first_seen=vulnerabilities[cve].patch_released
                + dt.timedelta(days=int(rng.integers(0, max(1, age + 1)))),
            )
        )

    # Only the CVEs that actually appear, so a coverage denominator is the
    # corpus rather than the catalogue it was drawn from.
    used = {finding.cve for finding in findings}
    return Corpus(
        findings=tuple(findings),
        vulnerabilities={cve: record for cve, record in vulnerabilities.items() if cve in used},
        as_of=spec.as_of,
    )


def describe_corpus(corpus: Corpus) -> dict:
    """What the generated corpus actually contains.

    Reported alongside every result rather than inferred from the spec,
    because the two differ. The EPSS calibration holds on the CVEs drawn, and
    a corpus keeps only the CVEs that appear in at least one finding, so the
    realized share at or above 0.1 is not the target. Across twelve seeds at
    1,500 CVEs it ran from 0.015 to 0.031 against a target of 0.027, which is a
    spread wide enough that a single seed result should not be believed. The
    benchmark averages over seeds for that reason, and this is what lets a
    reader check the corpus rather than take the spec's word for it.
    """
    records = list(corpus.vulnerabilities.values())
    epss = np.array([record.epss for record in records])
    cvss = np.array([record.cvss for record in records])
    kev = np.array([record.in_kev for record in records])

    ranks_epss = np.argsort(np.argsort(epss))
    ranks_cvss = np.argsort(np.argsort(cvss))
    realized = float(np.corrcoef(ranks_cvss, ranks_epss)[0, 1]) if len(records) > 2 else 0.0

    return {
        "findings": len(corpus.findings),
        "distinct_cves": len(records),
        "distinct_assets": len({finding.asset_id for finding in corpus.findings}),
        "share_epss_above_0_1": round(float((epss >= 0.1).mean()), 4),
        "median_epss": round(float(np.median(epss)), 6),
        "p95_epss": round(float(np.percentile(epss, 95)), 4),
        "mean_cvss": round(float(cvss.mean()), 2),
        "share_cvss_at_least_7": round(float((cvss >= 7.0).mean()), 4),
        "kev_cves": int(kev.sum()),
        "kev_findings": len(corpus.kev_findings),
        # The realized rank correlation, which is lower than the parameter
        # because CVSS is reported to one decimal place and the resulting ties
        # flatten it. The parameter is the latent correlation; this is what
        # came out the other side, and a reader comparing them should see both.
        "realized_cvss_epss_rank_correlation": round(realized, 3),
        "kev_cves_below_epss_0_1": int((kev & (epss < 0.1)).sum()),
        "findings_already_past_window": sum(1 for finding in corpus.findings if corpus.days_remaining(finding) < 0),
    }
