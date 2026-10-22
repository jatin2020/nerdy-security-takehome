.PHONY: help setup test run demo clean

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
UVICORN := $(VENV)/bin/uvicorn

help:
	@echo "Security Alert Triage Service — Available Commands:"
	@echo "  make setup   - Create virtual environment and install dependencies"
	@echo "  make test    - Execute behavioral and unit test suite with pytest"
	@echo "  make run     - Start local HTTP service on http://localhost:8000"
	@echo "  make demo    - Run end-to-end reproducible scenarios walkthrough"
	@echo "  make clean   - Remove cache directories and temporary files"

setup:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

test:
	$(PYTEST) -v

run:
	$(UVICORN) src.main:app --host 0.0.0.0 --port 8000 --reload

demo:
	$(PYTHON) scripts/run_demo.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -rf .coverage
