ifeq ($(OS),Windows_NT)
  BIN := .venv/Scripts
  PY_BOOT ?= python
else
  BIN := .venv/bin
  PY_BOOT ?= python3
endif

.PHONY: setup test api

setup:
	$(PY_BOOT) -m venv .venv
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -r requirements.txt
	$(BIN)/python -m pip install -e .

test:
	$(BIN)/python -m pytest

api:
	$(BIN)/python -m uvicorn api.main:app --reload
