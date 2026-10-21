# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

First release.

### Added

- Eight remediation orderings, each declaring what it is blind to, scored on
  KEV coverage, window attainment, exposure removed, and effort to reach 90
  percent of the known exploited findings.
- A corpus generator whose one sourced parameter is separated from its declared
  choices in `CorpusSpec.describe()`, and which reports realized values next to
  the targets it was asked for.
- A capacity aware attainability ceiling, so window attainment is a share of
  what is reachable rather than of the backlog.
- `pob` command line: `fetch`, `columns`, `generate`, `rank`, `compare`,
  `chart`.
- A scanner export importer that takes a column mapping and ships no vendor
  presets.
- A benchmark of four experiments, including a sensitivity sweep over the one
  parameter the conclusion depends on, writing `docs/metrics.json`.
- `docs/results.md`, generated from the metrics file, with `--check` in CI.

### Known limitations

- Every published figure is a simulation. The live feed path has never been run
  against the real EPSS and KEV endpoints.
- Findings are not clustered by patch, which is the omission most likely to
  change the conclusions. See `docs/limitations.md`.
