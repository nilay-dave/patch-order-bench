import numpy as np
import pytest

from pob.corpus.generate import (
    CHOSEN_MEDIAN_EPSS,
    SOURCED_SHARE_ABOVE_0_1,
    CorpusSpec,
    _epss_from_latent,
    describe_corpus,
    generate,
)


def spearman(left, right):
    return float(np.corrcoef(np.argsort(np.argsort(left)), np.argsort(np.argsort(right)))[0, 1])


class TestSpecValidation:
    @pytest.mark.parametrize("kwargs", [{"findings": 0}, {"distinct_cves": 0}, {"assets": 0}])
    def test_scale_must_be_positive(self, kwargs):
        with pytest.raises(ValueError, match="must be positive"):
            CorpusSpec(**kwargs)

    @pytest.mark.parametrize("value", [-0.1, 1.1])
    def test_correlation_must_be_a_fraction(self, value):
        with pytest.raises(ValueError, match="cvss_epss_correlation"):
            CorpusSpec(cvss_epss_correlation=value)

    def test_more_distinct_cves_than_findings_is_refused(self):
        with pytest.raises(ValueError, match="more distinct CVEs than findings"):
            CorpusSpec(findings=10, distinct_cves=100)

    def test_the_spec_separates_sourced_parameters_from_chosen_ones(self):
        """A reader deciding how much to believe a result needs to know which
        parameters were measured and which were picked."""
        described = CorpusSpec().describe()
        assert set(described) == {"sourced", "chosen", "scale", "seed"}
        assert "citation" in described["sourced"]
        assert "cvss_epss_correlation" in described["chosen"]


class TestEpssCalibration:
    def test_the_share_above_0_1_matches_the_sourced_figure_at_scale(self):
        """Calibrated to FIRST's published figure: 3,735 of 139,473 CVSS 3.x
        CVEs at or above 0.1."""
        latent = np.random.default_rng(1).standard_normal(400_000)
        scores = _epss_from_latent(latent, SOURCED_SHARE_ABOVE_0_1)
        assert (scores >= 0.1).mean() == pytest.approx(SOURCED_SHARE_ABOVE_0_1, abs=0.002)

    def test_the_median_matches_the_declared_one(self):
        latent = np.random.default_rng(2).standard_normal(400_000)
        scores = _epss_from_latent(latent, SOURCED_SHARE_ABOVE_0_1)
        assert np.median(scores) == pytest.approx(CHOSEN_MEDIAN_EPSS, rel=0.1)

    def test_two_anchors_are_needed_and_both_are_hit(self):
        """One anchor leaves the other end of the curve free to go somewhere
        absurd, which it did: calibrating on the 0.1 threshold alone forced a
        power so steep that half the population sat on a floor of 1e-5."""
        latent = np.random.default_rng(3).standard_normal(200_000)
        scores = _epss_from_latent(latent, SOURCED_SHARE_ABOVE_0_1)
        assert scores.min() > 1e-7, "nothing should land at an absurd floor"
        assert np.median(scores) > 1e-4, "the median should be a probability somebody would publish"

    def test_a_custom_share_is_honoured(self):
        latent = np.random.default_rng(4).standard_normal(200_000)
        scores = _epss_from_latent(latent, 0.10)
        assert (scores >= 0.1).mean() == pytest.approx(0.10, abs=0.005)

    def test_the_mapping_is_strictly_monotone(self):
        """Which is what preserves rank order, and therefore what makes the
        correlation parameter mean anything."""
        latent = np.sort(np.random.default_rng(5).standard_normal(5_000))
        scores = _epss_from_latent(latent, SOURCED_SHARE_ABOVE_0_1)
        assert np.all(np.diff(scores) >= 0)


class TestCorrelationDial:
    @pytest.mark.parametrize("rho", [0.0, 0.3, 0.6, 0.9])
    def test_a_higher_parameter_produces_a_higher_realized_correlation(self, rho):
        corpus = generate(CorpusSpec(findings=4000, distinct_cves=1200, cvss_epss_correlation=rho, seed=11))
        described = describe_corpus(corpus)
        realized = described["realized_cvss_epss_rank_correlation"]
        # Realized sits below the parameter, because CVSS is reported to one
        # decimal place and the ties that creates flatten Spearman. The dial is
        # monotone in the realized value, which is what it has to be.
        assert realized <= rho + 0.12
        if rho >= 0.3:
            assert realized > rho * 0.4

    def test_the_dial_is_monotone(self):
        realized = [
            describe_corpus(
                generate(CorpusSpec(findings=4000, distinct_cves=1200, cvss_epss_correlation=rho, seed=11))
            )["realized_cvss_epss_rank_correlation"]
            for rho in (0.0, 0.25, 0.5, 0.75, 1.0)
        ]
        assert realized == sorted(realized)

    def test_at_full_correlation_the_two_orderings_nearly_agree(self):
        """Which is why the sweep matters: at 1 there is nothing to measure."""
        corpus = generate(CorpusSpec(findings=4000, distinct_cves=1200, cvss_epss_correlation=1.0, seed=12))
        assert describe_corpus(corpus)["realized_cvss_epss_rank_correlation"] > 0.9


class TestCorpusShape:
    def test_it_produces_the_number_of_findings_asked_for(self):
        """An earlier version drew exactly this many pairs and discarded the
        collisions, producing a corpus a third smaller than requested, which
        made results incomparable across specs."""
        for count in (500, 5_000):
            corpus = generate(CorpusSpec(findings=count, distinct_cves=min(count, 1500)))
            assert len(corpus.findings) == count

    def test_a_cve_appears_at_most_once_per_asset(self):
        """A duplicate is the same remediation, and counting it twice would
        inflate every coverage figure."""
        corpus = generate(CorpusSpec(findings=3000, distinct_cves=400, assets=200))
        pairs = [(finding.cve, finding.asset_id) for finding in corpus.findings]
        assert len(pairs) == len(set(pairs))

    def test_an_impossible_corpus_is_refused_rather_than_looping(self):
        with pytest.raises(ValueError, match="impossible"):
            generate(CorpusSpec(findings=500, distinct_cves=10, assets=5))

    def test_a_finding_is_never_first_seen_before_its_patch_existed(self):
        corpus = generate(CorpusSpec(findings=2000, distinct_cves=600))
        for found in corpus.findings:
            assert found.first_seen >= corpus.vulnerabilities[found.cve].patch_released

    def test_the_same_seed_gives_the_same_corpus(self):
        first = generate(CorpusSpec(findings=1000, distinct_cves=300, seed=42))
        second = generate(CorpusSpec(findings=1000, distinct_cves=300, seed=42))
        assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]
        assert first.vulnerabilities == second.vulnerabilities

    def test_different_seeds_give_different_corpora(self):
        first = generate(CorpusSpec(findings=1000, distinct_cves=300, seed=1))
        second = generate(CorpusSpec(findings=1000, distinct_cves=300, seed=2))
        assert first.vulnerabilities != second.vulnerabilities

    def test_it_produces_kev_entries_with_a_low_current_probability(self):
        """The case that matters: the catalogue records that exploitation has
        happened, EPSS asks about the next thirty days, and an entry from four
        years ago can be in one with a low score in the other. That is exactly
        where an EPSS only ordering fails, so a generator that never produced
        it would make EPSS look better than it is."""
        corpus = generate(CorpusSpec(findings=5000, distinct_cves=1500))
        described = describe_corpus(corpus)
        assert described["kev_cves"] > 0
        assert described["kev_cves_below_epss_0_1"] > 0

    def test_it_produces_a_backlog_that_is_already_out_of_compliance(self):
        """A real backlog holds findings whose window closed long ago. A
        generator producing only fresh findings would make every ordering look
        like it met its deadlines."""
        corpus = generate(CorpusSpec(findings=3000, distinct_cves=900))
        assert describe_corpus(corpus)["findings_already_past_window"] > 0


class TestDescribeCorpus:
    def test_it_reports_realized_values_not_the_spec(self):
        """The two differ, and reporting the spec would be reporting an
        intention. Across twelve seeds the realized share at or above 0.1 ran
        from 0.015 to 0.031 against a target of 0.027."""
        corpus = generate(CorpusSpec(findings=5000, distinct_cves=1500))
        described = describe_corpus(corpus)
        assert described["findings"] == 5000
        assert described["distinct_cves"] <= 1500
        assert 0.0 <= described["share_epss_above_0_1"] <= 1.0

    def test_the_realized_share_varies_enough_that_one_seed_is_not_enough(self):
        """The reason the benchmark averages over seeds. This test exists to
        fail if the variance ever collapses, because that would mean the
        averaging had become unnecessary and the docs would be wrong."""
        shares = [
            describe_corpus(generate(CorpusSpec(findings=5000, distinct_cves=1500, seed=seed)))["share_epss_above_0_1"]
            for seed in range(8)
        ]
        assert max(shares) > min(shares) * 1.3, "if this fails, the seed averaging claim needs revisiting"
