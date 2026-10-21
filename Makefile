# Every target here is one a reviewer can run. The CI workflow runs the same
# ones rather than a parallel set of inline commands, so a green build and a
# clean checkout mean the same thing.

PY := python3

.PHONY: help install test lint cover bench report chart check provenance clean

help:
	@echo "install     install the package and its development extras"
	@echo "test        run the test suite"
	@echo "lint        ruff, format check and lint"
	@echo "cover       test suite with a coverage floor"
	@echo "bench       run the benchmark and rewrite docs/metrics.json (about a minute)"
	@echo "report      regenerate docs/results.md and the chart from docs/metrics.json"
	@echo "check       every verification gate CI runs, without the benchmark"
	@echo "provenance  the portfolio provenance audit"

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff format --check .
	$(PY) -m ruff check .

cover:
	$(PY) -m pytest -q --cov=pob --cov-report=term-missing --cov-fail-under=90

bench:
	$(PY) benchmark/run_benchmark.py --out docs/metrics.json

report:
	$(PY) tools/generate_results_doc.py
	$(PY) -m pob.cli chart --out docs/img/coverage.png

chart:
	$(PY) -m pob.cli chart --out docs/img/coverage.png

# The gates, in the order that fails fastest. check_numbers reads the committed
# metrics file rather than rerunning the benchmark, so this stays quick enough
# to run before every commit.
check:
	$(PY) tools/check_dashes.py
	$(PY) tools/check_tables.py
	$(PY) tools/check_numbers.py
	$(PY) tools/check_dependencies.py
	$(PY) tools/generate_results_doc.py --check
	$(PY) -m ruff format --check .
	$(PY) -m ruff check .
	$(PY) -m pytest -q

provenance:
	$(PY) scripts/provenance_check.py

clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov build dist
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
