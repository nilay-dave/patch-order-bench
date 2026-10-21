"""The live path: real EPSS scores and the real KEV catalogue.

**This code has never been run against the live feeds.** The environment it was
written in cannot reach epss.cyentia.com, cisa.gov or api.first.org: all three
return a connection failure through the egress proxy. So it is written from the
published formats, its parsing is tested against fixtures that match those
formats, and no number anywhere in this repository came through it.

That is stated here rather than in a footnote because it is the single most
important caveat about the project. Every figure published is a measurement of
the algorithm on a simulated corpus. Running ``pob fetch`` somewhere with
egress turns that into a measurement of the real CVE population, and until
somebody does, the conclusions are about the shape of the problem rather than
about this year's vulnerabilities.

The formats, from the vendors' own documentation:

**EPSS**, from FIRST: a gzipped CSV with a comment line carrying the model
version and publication date, then a header, then one row per CVE with the
columns cve, epss and percentile. ``epss`` is the probability of exploitation
activity being observed in the next thirty days; ``percentile`` is the share of
scored vulnerabilities at or below that score.

**KEV**, from CISA: a CSV of the catalogue, one row per vulnerability, carrying
the CVE identifier, the date it was added, and the remediation due date set for
federal agencies under BOD 22-01.

Only the standard library is used to fetch. requests would be the obvious
choice and is not a dependency here for one reason: this path cannot be
exercised in the environment it was written in, so the fewer moving parts
between the published format and the parser, the smaller the surface for a bug
nobody can catch.
"""

from __future__ import annotations

import csv
import datetime as dt
import gzip
import io
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

# A plain identifier rather than something that impersonates a browser. These
# are public feeds offered for exactly this use, and a scraper pretending to be
# Chrome is how a polite consumer becomes an abusive one.
USER_AGENT = "patch-order-bench (https://github.com/__GITHUB_USERNAME__/patch-order-bench)"
TIMEOUT_SECONDS = 60


class FeedError(Exception):
    """A feed could not be fetched or could not be read."""


@dataclass(frozen=True)
class EpssRow:
    cve: str
    epss: float
    percentile: float


@dataclass(frozen=True)
class KevRow:
    cve: str
    date_added: dt.date
    due_date: dt.date | None


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            return response.read()
    except urllib.error.HTTPError as exc:
        raise FeedError(f"{url}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise FeedError(
            f"{url}: could not be reached ({exc.reason}). This is also what an egress restricted "
            f"environment looks like, which is where this repository was built: see the module "
            f"docstring, and fetch the feeds somewhere with outbound access."
        ) from exc
    except TimeoutError as exc:
        raise FeedError(f"{url}: timed out after {TIMEOUT_SECONDS}s") from exc


def parse_epss(payload: bytes) -> list[EpssRow]:
    """Parse the EPSS CSV, gzipped or not.

    The leading comment line carrying the model version is skipped rather than
    treated as a header. A parser that took it as the header would read every
    column name as a model string and then fail on every row with a message
    about a missing column, which is a confusing way to learn that the file
    starts with a comment.
    """
    if payload[:2] == b"\x1f\x8b":
        try:
            payload = gzip.decompress(payload)
        except OSError as exc:
            raise FeedError(f"EPSS feed looked gzipped and was not readable: {exc}") from exc

    text = payload.decode("utf-8", errors="replace")
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise FeedError("EPSS feed was empty")

    body = [line for line in lines if not line.lstrip().startswith("#")]
    if not body:
        raise FeedError("EPSS feed held nothing but comments")

    reader = csv.DictReader(body)
    missing = {"cve", "epss", "percentile"} - set(reader.fieldnames or [])
    if missing:
        raise FeedError(
            f"EPSS feed is missing column(s) {sorted(missing)}; found {reader.fieldnames}. "
            f"The published format is cve, epss, percentile."
        )

    rows: list[EpssRow] = []
    for number, record in enumerate(reader, start=2):
        try:
            epss = float(record["epss"])
            percentile = float(record["percentile"])
        except (TypeError, ValueError) as exc:
            raise FeedError(f"EPSS feed line {number}: {record} is not parseable: {exc}") from exc
        if not 0.0 <= epss <= 1.0:
            raise FeedError(f"EPSS feed line {number}: {epss} is not a probability")
        rows.append(EpssRow(cve=record["cve"].strip(), epss=epss, percentile=percentile))
    return rows


def parse_kev(payload: bytes) -> list[KevRow]:
    """Parse the KEV catalogue CSV.

    Column names are matched case insensitively and without separators,
    because the published header uses camel case and a consumer that pinned
    the exact spelling would break on a cosmetic change to somebody else's
    file.
    """
    text = payload.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise FeedError("KEV feed was empty")

    def column(*candidates: str) -> str | None:
        normalised = {name.lower().replace(" ", "").replace("_", ""): name for name in reader.fieldnames or []}
        for candidate in candidates:
            found = normalised.get(candidate)
            if found is not None:
                return found
        return None

    cve_column = column("cveid", "cve")
    added_column = column("dateadded", "added")
    due_column = column("duedate", "due")
    if cve_column is None:
        raise FeedError(f"KEV feed has no CVE column; found {reader.fieldnames}. The published format carries cveID.")

    rows: list[KevRow] = []
    for number, record in enumerate(reader, start=2):
        cve = (record.get(cve_column) or "").strip()
        if not cve:
            continue
        rows.append(
            KevRow(
                cve=cve,
                date_added=_date(record.get(added_column) if added_column else None, number),
                due_date=_optional_date(record.get(due_column) if due_column else None),
            )
        )
    if not rows:
        raise FeedError("KEV feed held a header and no vulnerabilities")
    return rows


def _date(value: str | None, line: int) -> dt.date:
    parsed = _optional_date(value)
    if parsed is None:
        raise FeedError(f"KEV feed line {line}: {value!r} is not a date")
    return parsed


def _optional_date(value: str | None) -> dt.date | None:
    if not value or not value.strip():
        return None
    try:
        return dt.date.fromisoformat(value.strip())
    except ValueError:
        return None


def fetch(destination: Path, *, epss_url: str = EPSS_URL, kev_url: str = KEV_URL) -> dict[str, int]:
    """Fetch both feeds and write them to ``destination``.

    Written to disk as received, before parsing, so a parse failure leaves the
    bytes behind to look at. A fetcher that parses in memory and discards the
    response on error makes the one thing a reader needs unavailable.
    """
    destination.mkdir(parents=True, exist_ok=True)
    epss_bytes = _get(epss_url)
    (destination / "epss.csv.gz").write_bytes(epss_bytes)
    kev_bytes = _get(kev_url)
    (destination / "kev.csv").write_bytes(kev_bytes)

    return {"epss_rows": len(parse_epss(epss_bytes)), "kev_rows": len(parse_kev(kev_bytes))}
