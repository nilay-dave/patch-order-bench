# Contributing

## Running the checks

```bash
make install
make check
```

`make check` runs everything CI runs except the benchmark: house style, the
published number check, the dependency check, the generated results page,
format, lint and the tests. It takes a few seconds. Run it before opening a pull
request and the CI result will not surprise you.

## The rules that are not negotiable

**Every published number is tagged and checked.** A figure in the README or
under `docs/` carries the metrics path it came from:

```markdown
<!--number:headline.orderings.cvss.kev_coverage-->0.382<!--/number-->
```

`tools/check_numbers.py` compares each one against `docs/metrics.json` and fails
the build on drift. If you change something that moves a number, run
`make bench` and then `make report`, and commit the regenerated files with the
change that caused them.

**Results pages are generated, not written.** `docs/results.md` comes from
`tools/generate_results_doc.py`. Edit the generator, not the output. CI checks
the output is current.

**A simulated figure is labelled as one.** This project has no measurements of a
real backlog. If you add an experiment, its output says so, in the metrics file
and wherever it is published. A simulated number presented as a measured one is
the one failure this repository cannot absorb.

**No em dashes or en dashes**, anywhere: code, comments, commit messages, docs.
`tools/check_dashes.py` enforces it across every tracked text file.

**Verify and commit are separate steps.** Run the tests, read the result, then
commit. Chaining them with `&&` puts the commit first in the shell's plan and
this repository has a commit that proves it.

## Adding an ordering

An ordering is a decision about what to ignore, so `Ordering` requires a
`summary` and a `blind_to`. Both are published. "Blind to nothing" is not an
acceptable value, and if it seems like one, the ordering has a hidden assumption
worth finding before the pull request.

A new ordering needs a test that pins its behaviour on a corpus small enough to
reason about by hand, and it should be scored in the benchmark alongside the
others rather than presented on its own.

## Changing the generator

The corpus generator decides every result in this project, so changes to it get
more scrutiny than changes to anything else.

- A new parameter is either sourced, with the source in `docs/sources.md`, or
  declared a choice in `CorpusSpec.describe()`. There is no third category.
- If a result depends on the new parameter, sweep it in the benchmark rather
  than arguing for a value.
- Report realized values next to targets. A generator does not necessarily
  produce what it was asked for, and the comparison runs on what it produced.

## Commit messages

Conventional Commits, subject under 72 characters, and a body explaining why
rather than what. A `fix` commit says what was wrong and how it was found. The
history is part of what this repository is for.
