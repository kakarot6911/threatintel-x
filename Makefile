PY ?= .venv/bin/python
BIN = .venv/bin

.PHONY: install demo serve test lint type security check docker world clean

install:            ## create venv and install with dev extras
	uv venv --python 3.12 .venv && uv pip install --python $(PY) -e ".[dev]"

world:              ## regenerate the deterministic synthetic dataset
	$(PY) scripts/build_synthetic_world.py

demo:               ## run the synthetic end-to-end demo into data/threatintel.db
	$(BIN)/threatintel demo

serve:              ## run API + TAXII + workbench on http://127.0.0.1:8000
	$(BIN)/threatintel serve

test:               ## run the test suite with coverage
	$(BIN)/pytest --cov=threatintel --cov-report=term-missing

lint:
	$(BIN)/ruff check src tests scripts && $(BIN)/ruff format --check src tests scripts

type:
	$(BIN)/mypy

security:           ## static security analysis + dependency audit
	$(BIN)/bandit -q -r src && $(BIN)/pip-audit --progress-spinner off --skip-editable

check: lint type security test   ## everything CI runs

eval-real:          ## blind attribution evaluation on the real-data DB
	TIX_DATABASE_URL=sqlite:///$(CURDIR)/data/threatintel-real.db $(PY) scripts/evaluate_attribution.py

docker:
	docker build -t threatintel-x:local .

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov data/threatintel.db*
