"""Tests for the live feed path, which has never been run against the feeds.

The environment this was built in cannot reach epss.cyentia.com, cisa.gov or
api.first.org. So these test the parsing against fixtures matching the
published formats, which is what is testable, and no test here reaches a
network. The caveat is in the module docstring and in the readme, because it is
the single most important thing to know about this project.
"""

import datetime as dt
import gzip

import pytest

from pob.feeds.fetch import EPSS_URL, KEV_URL, FeedError, fetch, parse_epss, parse_kev

EPSS_FIXTURE = (
    b"#model_version:v2026.03.14,score_date:2026-10-21T00:00:00+0000\n"
    b"cve,epss,percentile\n"
    b"CVE-2026-0001,0.97231,0.99982\n"
    b"CVE-2026-0002,0.00009,0.03812\n"
    b"CVE-2026-0003,0.11000,0.97400\n"
)

KEV_FIXTURE = (
    b"cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,"
    b"requiredAction,dueDate,knownRansomwareCampaignUse,notes\n"
    b"CVE-2026-0001,Acme,Widget,Widget RCE,2026-10-01,A description,Apply updates,"
    b"2026-10-22,Known,\n"
    b"CVE-2026-0007,Globex,Gadget,Gadget bypass,2026-09-15,Another,Apply updates,"
    b"2026-10-06,Unknown,\n"
)


class TestEpssParsing:
    def test_the_published_columns_are_read(self):
        rows = parse_epss(EPSS_FIXTURE)
        assert [row.cve for row in rows] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
        assert rows[0].epss == pytest.approx(0.97231)
        assert rows[0].percentile == pytest.approx(0.99982)

    def test_a_gzipped_payload_is_decompressed(self):
        """The published file is gzipped, and the same parser handles both so a
        reader can hold an uncompressed copy without a second code path."""
        assert len(parse_epss(gzip.compress(EPSS_FIXTURE))) == 3

    def test_the_leading_comment_line_is_skipped_not_taken_as_a_header(self):
        """A parser that took it as the header would read every column name as
        a model string and then fail on every row about a missing column,
        which is a confusing way to learn the file starts with a comment."""
        rows = parse_epss(EPSS_FIXTURE)
        assert all(row.cve.startswith("CVE-") for row in rows)

    def test_a_file_with_no_comment_line_still_parses(self):
        without = b"\n".join(EPSS_FIXTURE.split(b"\n")[1:])
        assert len(parse_epss(without)) == 3

    def test_an_empty_feed_is_refused(self):
        with pytest.raises(FeedError, match="empty"):
            parse_epss(b"")

    def test_a_feed_of_only_comments_is_refused(self):
        with pytest.raises(FeedError, match="nothing but comments"):
            parse_epss(b"#model_version:v1\n#another comment\n")

    def test_missing_columns_are_named_with_the_published_format(self):
        with pytest.raises(FeedError, match=r"missing column\(s\) \['epss', 'percentile'\]"):
            parse_epss(b"cve,something\nCVE-2026-0001,1\n")

    @pytest.mark.parametrize("value", ["2.5", "-0.1"])
    def test_a_score_outside_zero_to_one_is_refused(self, value):
        """It is a probability. A value outside the range means the format
        changed or the file is not what it claims, and silently clamping it
        would put a fabricated number into every downstream measurement."""
        with pytest.raises(FeedError, match="not a probability"):
            parse_epss(f"cve,epss,percentile\nCVE-2026-0001,{value},0.5\n".encode())

    def test_an_unparseable_number_names_its_line(self):
        with pytest.raises(FeedError, match="line 2"):
            parse_epss(b"cve,epss,percentile\nCVE-2026-0001,not-a-number,0.5\n")

    def test_a_payload_that_claims_to_be_gzip_and_is_not_is_refused(self):
        with pytest.raises(FeedError, match="looked gzipped"):
            parse_epss(b"\x1f\x8b" + b"not actually gzip")


class TestKevParsing:
    def test_the_published_columns_are_read(self):
        rows = parse_kev(KEV_FIXTURE)
        assert [row.cve for row in rows] == ["CVE-2026-0001", "CVE-2026-0007"]
        assert rows[0].date_added == dt.date(2026, 10, 1)
        assert rows[0].due_date == dt.date(2026, 10, 22)

    def test_column_names_are_matched_without_case_or_separators(self):
        """A consumer that pinned the exact camel case spelling would break on
        a cosmetic change to somebody else's file."""
        relaxed = b"CVE_ID,Date Added,Due Date\nCVE-2026-0001,2026-10-01,2026-10-22\n"
        rows = parse_kev(relaxed)
        assert rows[0].cve == "CVE-2026-0001"
        assert rows[0].due_date == dt.date(2026, 10, 22)

    def test_a_byte_order_mark_is_tolerated(self):
        assert len(parse_kev(b"\xef\xbb\xbf" + KEV_FIXTURE)) == 2

    def test_a_missing_due_date_is_none_rather_than_an_error(self):
        """Not every entry carries one, and refusing the whole catalogue over
        one blank cell would make the feed unusable."""
        rows = parse_kev(b"cveID,dateAdded,dueDate\nCVE-2026-0001,2026-10-01,\n")
        assert rows[0].due_date is None

    def test_an_unreadable_due_date_is_none_rather_than_an_error(self):
        rows = parse_kev(b"cveID,dateAdded,dueDate\nCVE-2026-0001,2026-10-01,not a date\n")
        assert rows[0].due_date is None

    def test_a_missing_cve_column_names_the_published_one(self):
        with pytest.raises(FeedError, match="carries cveID"):
            parse_kev(b"vendorProject,product\nAcme,Widget\n")

    def test_an_empty_feed_is_refused(self):
        with pytest.raises(FeedError, match="empty"):
            parse_kev(b"")

    def test_a_header_with_no_rows_is_refused(self):
        with pytest.raises(FeedError, match="header and no vulnerabilities"):
            parse_kev(b"cveID,dateAdded,dueDate\n")

    def test_a_row_with_a_blank_cve_is_skipped_not_fatal(self):
        rows = parse_kev(b"cveID,dateAdded,dueDate\n,2026-10-01,\nCVE-2026-0002,2026-10-01,\n")
        assert [row.cve for row in rows] == ["CVE-2026-0002"]


class TestFetching:
    def test_the_urls_are_the_published_ones(self):
        assert EPSS_URL.startswith("https://epss.cyentia.com/")
        assert KEV_URL.startswith("https://www.cisa.gov/")

    def test_a_fetch_failure_says_what_an_egress_restricted_environment_looks_like(self, tmp_path):
        """The message exists because this is the failure a reader of this
        repository is most likely to hit, and "URLError" alone does not tell
        them whether the feed moved or their network blocked it."""
        with pytest.raises(FeedError, match="egress restricted"):
            fetch(tmp_path, epss_url="https://127.0.0.1:1/epss.csv.gz")

    def test_bytes_are_written_before_being_parsed(self, tmp_path, monkeypatch):
        """A fetcher that parses in memory and discards the response on error
        makes the one thing a reader needs unavailable."""
        from pob.feeds import fetch as module

        payloads = {"epss": gzip.compress(EPSS_FIXTURE), "kev": KEV_FIXTURE}
        monkeypatch.setattr(
            module, "_get", lambda url: payloads["epss"] if "epss" in url else payloads["kev"]
        )
        counts = fetch(tmp_path)
        assert counts == {"epss_rows": 3, "kev_rows": 2}
        assert (tmp_path / "epss.csv.gz").read_bytes() == payloads["epss"]
        assert (tmp_path / "kev.csv").read_bytes() == payloads["kev"]

    def test_the_user_agent_identifies_the_tool_rather_than_impersonating_a_browser(self):
        """These are public feeds offered for exactly this use, and a consumer
        pretending to be Chrome is how a polite one becomes abusive."""
        from pob.feeds.fetch import USER_AGENT

        assert "patch-order-bench" in USER_AGENT
        assert "Mozilla" not in USER_AGENT
