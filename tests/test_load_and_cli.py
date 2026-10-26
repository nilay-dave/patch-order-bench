import datetime as dt
import json

import pytest

from pob.cli import main
from pob.corpus.load import ColumnMap, ImportError_, columns, load

EXPORT = """\
CVE ID,Host,CVSS Base,EPSS,KEV,Patch Date,Criticality
CVE-2026-0001,host-a,9.8,0.91,Known,2026-08-01,0.9
CVE-2026-0002,host-a,5.1,0.0004,,2026-09-15,0.9
CVE-2026-0001,host-b,9.8,0.91,Known,2026-08-01,0.2
CVE-2026-0001,host-a,9.8,0.91,Known,2026-08-01,0.9
,host-c,7.0,0.1,,2026-01-01,0.5
CVE-2026-0003,host-c,not-a-number,0.1,,2026-01-01,0.5
CVE-2026-0004,host-d,7.7,2.5,,2026-01-01,0.5
"""

FULL_MAP = {
    "cve": "CVE ID",
    "asset": "Host",
    "cvss": "CVSS Base",
    "epss": "EPSS",
    "kev": "KEV",
    "patch_released": "Patch Date",
    "asset_criticality": "Criticality",
}


@pytest.fixture
def export(tmp_path):
    path = tmp_path / "scan.csv"
    path.write_text(EXPORT, encoding="utf-8")
    return path


class TestColumns:
    def test_it_lists_the_header(self, export):
        assert columns(export)[:3] == ["CVE ID", "Host", "CVSS Base"]

    def test_an_empty_file_is_refused(self, tmp_path):
        empty = tmp_path / "empty.csv"
        empty.write_text("", encoding="utf-8")
        with pytest.raises(ImportError_, match="empty"):
            columns(empty)


class TestImport:
    def test_a_mapped_export_becomes_a_corpus(self, export):
        corpus, report = load(export, ColumnMap(**FULL_MAP), as_of=dt.date(2026, 10, 21))
        assert report.findings == 3
        assert report.distinct_cves == 2
        assert {f.asset_id for f in corpus.findings} == {"host-a", "host-b"}

    def test_a_wrong_column_name_is_refused_with_the_real_columns(self, export):
        """A mapping that names a column wrongly would import successfully with
        that field empty, and every measurement downstream would be computed
        over nulls."""
        with pytest.raises(ImportError_) as caught:
            load(export, ColumnMap(cve="cve", asset="Host", cvss="CVSS Base"))
        assert "'CVE ID'" in str(caught.value)
        assert "cve -> 'cve'" in str(caught.value)

    def test_a_duplicate_cve_and_asset_pair_is_dropped_and_counted(self, export):
        _, report = load(export, ColumnMap(**FULL_MAP))
        assert report.duplicates_dropped == 1

    def test_a_blank_cve_or_asset_is_skipped_with_a_reason(self, export):
        _, report = load(export, ColumnMap(**FULL_MAP))
        assert any("blank CVE or asset" in reason for reason in report.rows_skipped)

    def test_an_unparseable_cvss_is_skipped_with_its_line(self, export):
        _, report = load(export, ColumnMap(**FULL_MAP))
        assert any("line 7" in reason and "not a number" in reason for reason in report.rows_skipped)

    def test_an_epss_outside_zero_to_one_is_skipped(self, export):
        """It is a probability. Clamping would put a fabricated number into
        every measurement that followed."""
        _, report = load(export, ColumnMap(**FULL_MAP))
        assert any("not a probability" in reason for reason in report.rows_skipped)

    def test_kev_values_are_matched_case_folded_against_the_declared_set(self, export):
        corpus, _ = load(export, ColumnMap(**FULL_MAP))
        assert corpus.vulnerabilities["CVE-2026-0001"].in_kev is True
        assert corpus.vulnerabilities["CVE-2026-0002"].in_kev is False

    def test_a_missing_epss_column_defaults_and_says_so(self, export):
        """A corpus imported without EPSS is explicitly incomplete rather than
        silently treated as having a probability of zero."""
        _, report = load(export, ColumnMap(cve="CVE ID", asset="Host", cvss="CVSS Base"))
        assert report.defaulted["epss"] > 0
        assert "defaulted epss" in report.summary()

    def test_a_missing_criticality_defaults_to_a_half_not_to_one(self, tmp_path):
        """So an unscored estate does not look uniformly critical."""
        path = tmp_path / "s.csv"
        path.write_text("CVE ID,Host,CVSS Base\nCVE-2026-0001,host-a,9.8\n", encoding="utf-8")
        corpus, report = load(path, ColumnMap(cve="CVE ID", asset="Host", cvss="CVSS Base"))
        assert corpus.findings[0].asset_criticality == 0.5
        assert report.defaulted["asset_criticality"] == 1

    @pytest.mark.parametrize("value", ["2026-08-01", "08/01/2026"])
    def test_common_date_formats_are_read(self, tmp_path, value):
        path = tmp_path / "s.csv"
        path.write_text(f"CVE ID,Host,CVSS Base,Patch\nCVE-2026-0001,host-a,9.8,{value}\n", encoding="utf-8")
        corpus, _ = load(
            path,
            ColumnMap(cve="CVE ID", asset="Host", cvss="CVSS Base", patch_released="Patch"),
            as_of=dt.date(2026, 10, 21),
        )
        assert corpus.vulnerabilities["CVE-2026-0001"].patch_released.year == 2026

    def test_an_export_with_no_usable_rows_is_refused_with_the_first_problems(self, tmp_path):
        path = tmp_path / "s.csv"
        path.write_text("CVE ID,Host,CVSS Base\n,host-a,9.8\n,host-b,9.8\n", encoding="utf-8")
        with pytest.raises(ImportError_, match="First problems"):
            load(path, ColumnMap(cve="CVE ID", asset="Host", cvss="CVSS Base"))

    def test_there_are_no_vendor_presets(self):
        """A preset for Qualys or Nessus would assert what their export columns
        are called, and this was written where neither vendor's documentation
        could be checked."""
        import pob.corpus.load as module

        assert not any(name.upper() in dir(module) for name in ("QUALYS", "NESSUS"))


class TestCli:
    def test_compare_prints_every_ordering(self, capsys):
        assert main(["compare", "--findings", "800", "--cves", "300"]) == 0
        out = capsys.readouterr().out
        for name in ("cvss", "epss", "kev-then-epss", "random", "window-first"):
            assert name in out

    def test_compare_warns_that_a_generated_corpus_is_simulated(self, capsys):
        main(["compare", "--findings", "500", "--cves", "200"])
        assert "simulated corpus" in capsys.readouterr().err

    def test_compare_on_an_imported_export_does_not_warn(self, export, tmp_path, capsys):
        mapping = tmp_path / "map.json"
        mapping.write_text(json.dumps(FULL_MAP), encoding="utf-8")
        main(["compare", "--csv", str(export), "--map", str(mapping)])
        captured = capsys.readouterr()
        assert "simulated corpus" not in captured.err
        assert "imported:" in captured.err

    def test_compare_writes_json_when_asked(self, tmp_path, capsys):
        out = tmp_path / "nested" / "compare.json"
        main(["compare", "--findings", "600", "--cves", "200", "--json", str(out)])
        capsys.readouterr()
        document = json.loads(out.read_text(encoding="utf-8"))
        assert document["simulated"] is True
        assert "kev-then-epss" in document["orderings"]
        assert "blind_to" in document["orderings"]["cvss"]

    def test_csv_without_a_map_explains_why_there_are_no_presets(self, export, capsys):
        assert main(["compare", "--csv", str(export)]) == 2
        assert "no vendor presets on purpose" in capsys.readouterr().err

    def test_columns_prints_the_header_and_a_starter_mapping(self, export, capsys):
        assert main(["columns", str(export)]) == 0
        out = capsys.readouterr().out
        assert "'CVE ID'" in out
        assert '"cve"' in out

    def test_rank_prints_the_top_and_what_the_ordering_cannot_see(self, capsys):
        assert main(["rank", "--findings", "600", "--cves", "200", "--top", "3"]) == 0
        out = capsys.readouterr().out
        assert "blind to:" in out
        assert out.count("CVE-2026-") >= 3

    def test_an_unknown_ordering_is_refused_by_the_parser(self):
        with pytest.raises(SystemExit):
            main(["rank", "--ordering", "severity"])

    def test_generate_describes_the_spec_and_the_realized_corpus(self, capsys):
        assert main(["generate", "--findings", "600", "--cves", "200"]) == 0
        document = json.loads(capsys.readouterr().out)
        assert "sourced" in document["spec"]
        assert "realized_cvss_epss_rank_correlation" in document["realized"]

    def test_fetch_reports_the_feed_error_rather_than_a_traceback(self, tmp_path, capsys):
        # The failure is forced by the autouse block_outbound_network fixture in
        # conftest.py, not by the sandbox happening to lack egress. Before that
        # fixture existed this exited 2 only where the network was blocked, and
        # returned 0 (a real, successful fetch) on a CI runner with internet.
        assert main(["fetch", "--to", str(tmp_path / "feeds")]) == 2
        assert "feed error" in capsys.readouterr().err

    def test_chart_writes_an_image(self, tmp_path, capsys):
        out = tmp_path / "curve.png"
        assert main(["chart", "--findings", "500", "--cves", "200", "--seeds", "2", "--out", str(out)]) == 0
        capsys.readouterr()
        assert out.is_file() and out.stat().st_size > 5_000

    def test_a_missing_file_is_reported_without_a_traceback(self, capsys):
        assert main(["columns", "/nonexistent/scan.csv"]) == 2
        assert "no such file" in capsys.readouterr().err

    def test_no_command_exits_two(self):
        with pytest.raises(SystemExit) as caught:
            main([])
        assert caught.value.code == 2
