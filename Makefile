# Makefile for Protocol-Aware Network Digital Twin & Security Verification Engine

.PHONY: help setup build-engine test-engine test-api test-web typecheck lint run-api run-web test-all check-all clean

VENV ?= .venv
PYTHON ?= $(VENV)/Scripts/python
PYTEST ?= $(VENV)/Scripts/pytest
RUFF ?= $(VENV)/Scripts/ruff

# Fallback for Linux/macOS paths
ifeq ($(OS),Windows_NT)
	PYTHON_BIN := $(PYTHON)
	PYTEST_BIN := $(PYTEST)
	RUFF_BIN := $(RUFF)
else
	PYTHON_BIN := $(VENV)/bin/python
	PYTEST_BIN := $(VENV)/bin/pytest
	RUFF_BIN := $(VENV)/bin/ruff
endif

help:
	@echo "Protocol Digital Twin Platform Commands:"
	@echo "  setup         - Prepare environment, install dependencies, build engine"
	@echo "  build-engine  - Build C++20 engine with CMake"
	@echo "  test-engine   - Run C++ doctest test suite"
	@echo "  test-api      - Run pytest backend test suite"
	@echo "  test-web      - Run Vitest frontend test suite"
	@echo "  typecheck     - Run TypeScript strict type-check"
	@echo "  lint          - Run Ruff linter on Python code"
	@echo "  run-api       - Start FastAPI backend server"
	@echo "  run-web       - Start React development server"
	@echo "  test-all      - Run all automated tests"
	@echo "  check-all     - Run full quality gates (lint + typecheck + tests)"

setup:
	python -m venv $(VENV)
	$(PYTHON_BIN) -m pip install --upgrade pip
	$(PYTHON_BIN) -m pip install -r apps/api/requirements-dev.txt
	$(PYTHON_BIN) -m pip install -e packages/contracts/python
	$(PYTHON_BIN) -m pip install -e apps/api
	cd apps/web && npm install
	cmake -B build/engine -S engine/protocol
	cmake --build build/engine --config Release

build-engine:
	cmake -B build/engine -S engine/protocol
	cmake --build build/engine --config Release

test-engine:
	ctest --test-dir build/engine -C Release --output-on-failure

test-api:
	$(PYTEST_BIN) apps/api/tests tests/integration

test-web:
	cd apps/web && npm run test

typecheck:
	cd apps/web && npm run typecheck

lint:
	$(RUFF_BIN) check apps/api packages/contracts/python

run-api:
	$(PYTHON_BIN) -m uvicorn network_twin.main:app --host 127.0.0.1 --port 8000 --reload

run-web:
	cd apps/web && npm run dev

test-all: test-engine test-api typecheck test-web

check-all: lint typecheck test-all
