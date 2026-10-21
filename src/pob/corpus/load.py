"""Imports a scanner export, with the column mapping declared rather than guessed.

Scanner API integrations are out of scope. A corpus arrives as an exported CSV,
which every scanner can produce and which needs no credentials, no network and
no agreement about an API version.

**There are no vendor presets, and that is deliberate.** A preset named for
Qualys or Nessus would have to assert what their export columns are called, and
this was written in an environment that cannot reach either vendor's
documentation to check. A mapping that names a column wrongly fails in the
worst available way: the import succeeds, the field is empty, and every
measurement downstream is computed over nulls. So the mapping is the caller's
to declare, and the error messages are built to make declaring it quick.

``columns`` in a CSV nobody has seen before is one command, and a mapping that
misses a column says which columns the file actually has.
"""

from __future__ import annotations

import csv
import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path

from pob.models import Corpus, Finding, Vulnerability


class ImportError_(Exception):
    """A scanner export that cannot be read as a corpus."""


@dataclass(frozen=True)
class ColumnMap:
    """Which column in the export holds which field.

    ``cve``, ``asset`` and ``cvss`` are required because nothing can be ranked
    without them. ``epss`` and ``kev`` are optional and usually absent, since
    most scanners do not carry them: ``pob fetch`` supplies those, and a corpus
    imported without them is explicitly incomplete rather than silently
    treated as having an EPSS of zero.
    """

    cve: str
    asset: str
    cvss: str
    epss: str | None = None
    kev: str | None = None
    patch_released: str | None = None
    first_seen: str | None = None
    asset_criticality: str | None = None
    effort: str | None = None
    # Values in the kev column that mean yes, compared case folded. Declared
    # because exports disagree: true, yes, 1 and Known all appear.
    kev_true_values: tuple[str, ...] = ("true", "yes", "1", "y", "known")
    # Used for every finding whose row carries no criticality. 0.5 rather than
    # 1.0, so an unscored estate does not look uniformly critical.
    default_asset_criticality: float = 0.5

    def required(self) -> dict[str, str]:
        return {"cve": self.cve, "asset": self.asset, "cvss": self.cvss}

    def optional(self) -> dict[str, str]:
        return {
            name: column
            for name, column in {
                "epss": self.epss,
                "kev": self.kev,
                "patch_released": self.patch_released,
                "first_seen": self.first_seen,
                "asset_criticality": self.asset_criticality,
                "effort": self.effort,
            }.items()
            if column is not None
        }


@dataclass
class ImportReport:
    """What the import found, and what it had to fall back on.

    Reported rather than logged, because an import that quietly defaults half
    its fields produces a corpus that looks complete and measures something
    else.
    """

    rows: int = 0
    findings: int = 0
    distinct_cves: int = 0
    duplicates_dropped: int = 0
    rows_skipped: list[str] = field(default_factory=list)
    defaulted: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        parts = [f"{self.findings} findings over {self.distinct_cves} CVEs from {self.rows} rows"]
        if self.duplicates_dropped:
            parts.append(f"{self.duplicates_dropped} duplicate CVE and asset pairs dropped")
        if self.rows_skipped:
            parts.append(f"{len(self.rows_skipped)} rows skipped")
        for name, count in sorted(self.defaulted.items()):
            parts.append(f"{count} rows defaulted {name}")
        return "; ".join(parts)


def columns(path: Path) -> list[str]:
    """The column names in an export, for working out a mapping."""
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        try:
            return next(reader)
        except StopIteration:
            raise ImportError_(f"{path} is empty") from None


def load(path: Path, mapping: ColumnMap, *, as_of: dt.date | None = None) -> tuple[Corpus, ImportReport]:
    """Read a scanner export into a corpus."""
    as_of = as_of or dt.date.today()
    report = ImportReport()

    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        present = set(reader.fieldnames or [])
        if not present:
            raise ImportError_(f"{path} has no header row")

        wanted = {**mapping.required(), **mapping.optional()}
        missing = {name: column for name, column in wanted.items() if column not in present}
        if missing:
            described = ", ".join(f"{name} -> {column!r}" for name, column in sorted(missing.items()))
            raise ImportError_(
                f"{path} has no column(s) for {described}. The file's columns are: "
                f"{sorted(present)}. A mapping that names a column wrongly would import successfully "
                f"with that field empty, so this refuses instead."
            )

        vulnerabilities: dict[str, Vulnerability] = {}
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for number, row in enumerate(reader, start=2):
            report.rows += 1
            cve = (row.get(mapping.cve) or "").strip().upper()
            asset = (row.get(mapping.asset) or "").strip()
            if not cve or not asset:
                report.rows_skipped.append(f"line {number}: blank CVE or asset")
                continue

            try:
                cvss = float(row[mapping.cvss])
            except (TypeError, ValueError):
                report.rows_skipped.append(f"line {number}: CVSS {row.get(mapping.cvss)!r} is not a number")
                continue
            if not 0.0 <= cvss <= 10.0:
                report.rows_skipped.append(f"line {number}: CVSS {cvss} is outside 0 to 10")
                continue

            epss = _optional_float(row, mapping.epss)
            if epss is None:
                report.defaulted["epss"] = report.defaulted.get("epss", 0) + 1
                epss = 0.0
            elif not 0.0 <= epss <= 1.0:
                report.rows_skipped.append(f"line {number}: EPSS {epss} is not a probability")
                continue

            kev = False
            if mapping.kev is not None:
                kev = (row.get(mapping.kev) or "").strip().lower() in mapping.kev_true_values

            released = _optional_date(row, mapping.patch_released)
            if released is None:
                report.defaulted["patch_released"] = report.defaulted.get("patch_released", 0) + 1
                released = as_of

            first_seen = _optional_date(row, mapping.first_seen) or released
            criticality = _optional_float(row, mapping.asset_criticality)
            if criticality is None:
                report.defaulted["asset_criticality"] = report.defaulted.get("asset_criticality", 0) + 1
                criticality = mapping.default_asset_criticality
            effort = _optional_float(row, mapping.effort) or 1.0

            if cve not in vulnerabilities:
                vulnerabilities[cve] = Vulnerability(cve, cvss, epss, kev, released)

            if (cve, asset) in seen:
                report.duplicates_dropped += 1
                continue
            seen.add((cve, asset))

            findings.append(
                Finding(
                    finding_id=f"{cve}@{asset}",
                    cve=cve,
                    asset_id=asset,
                    asset_criticality=criticality,
                    first_seen=min(first_seen, as_of),
                    effort=effort,
                )
            )

    if not findings:
        raise ImportError_(
            f"{path} produced no findings from {report.rows} rows. "
            + ("First problems: " + "; ".join(report.rows_skipped[:3]) if report.rows_skipped else "")
        )

    report.findings = len(findings)
    report.distinct_cves = len(vulnerabilities)
    return Corpus(tuple(findings), vulnerabilities, as_of=as_of), report


def _optional_float(row: dict, column: str | None) -> float | None:
    if column is None:
        return None
    raw = (row.get(column) or "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _optional_date(row: dict, column: str | None) -> dt.date | None:
    if column is None:
        return None
    raw = (row.get(column) or "").strip()
    if not raw:
        return None
    # ISO first, then the two orderings a spreadsheet most often produces.
    for parse in (dt.date.fromisoformat, lambda v: dt.datetime.strptime(v, "%m/%d/%Y").date(),
                  lambda v: dt.datetime.strptime(v, "%d/%m/%Y").date()):
        try:
            return parse(raw[:10] if len(raw) >= 10 and parse is dt.date.fromisoformat else raw)
        except ValueError:
            continue
    return None
