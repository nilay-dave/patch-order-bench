## What this changes

<!-- The behaviour that is different afterwards. -->

## Why

<!-- What was wrong, or what this makes possible. If it is a fix, how it was
found matters as much as what it was. -->

## Checks

- [ ] `make check` passes
- [ ] If a published number moved: `make bench` and `make report` were rerun and
      the regenerated files are in this pull request
- [ ] If a new parameter was added: it is either sourced in `docs/sources.md` or
      declared a choice in `CorpusSpec.describe()`
- [ ] If a result depends on a new assumption: it is swept in the benchmark
      rather than argued for
- [ ] No em dashes or en dashes anywhere, including this description
