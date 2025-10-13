VENV?=.venv
PYTHON=$(VENV)/Scripts/python.exe
PIP=$(VENV)/Scripts/pip.exe

.PHONY: venv install dev test

venv:
	python -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e .[dev]

install:
	$(PIP) install -e .

dev:
	$(PYTHON) -m uvicorn fastmcp.main:app --reload

test:
	$(PYTHON) -m pytest -q
