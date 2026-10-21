# Security policy

## Reporting a vulnerability

Report privately through GitHub's
[security advisory form](https://github.com/__GITHUB_USERNAME__/patch-order-bench/security/advisories/new)
rather than in a public issue. You should get a first response within a week.

## Scope

This is an offline analysis tool. It reads files you point it at, and it opens a
network connection in exactly one place: `pob fetch`, which downloads the EPSS
scores and the CISA KEV catalogue over HTTPS from the URLs recorded in
`docs/sources.md`. Nothing else in the package makes a request, and nothing
sends your data anywhere.

Issues that are in scope include anything that makes the tool execute data it
read, write outside the path it was given, or send a scanner export somewhere it
should not go.

## A note on what you feed it

A scanner export is a map of what is unpatched on your estate, which makes it
one of the more sensitive files your organisation holds. This tool does not copy
it: there is no cache, no database, and no temporary spool, which is one of the
reasons recorded in
[ADR 002](docs/adr/adr-002-no-persistence-layer.md). Output goes only where you
point it with `--out` or `--json`.

Treat `docs/metrics.json` in a fork of this repository the same way. In this
repository it holds simulated figures; in yours it could hold a summary of your
real backlog.
