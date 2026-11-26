PYTHON ?= python3
PIP ?= $(PYTHON) -m pip

# Keep bytecode out of src/ (a test asserts the source tree has no .pyc files).
export PYTHONPYCACHEPREFIX := $(CURDIR)/build/pycache

.PHONY: help install test compile wheel benchmark docker-build clean ci

help:
	@echo "install       Install the project and development dependencies"
	@echo "compile       Compile source, tests, and scripts"
	@echo "test          Run the complete pytest suite"
	@echo "wheel         Build a wheel without resolving dependencies"
	@echo "benchmark     Run offline synthetic microbenchmarks"
	@echo "docker-build  Build the hardened Docker image"
	@echo "clean         Remove generated build and test artifacts"
install:
	$(PIP) install -e ".[browser,dev]"

compile:
	$(PYTHON) -m compileall -q src tests scripts

test: compile
	$(PYTHON) -m pytest -q

wheel:
	$(PIP) wheel . --no-deps --no-build-isolation --wheel-dir dist

benchmark:
	$(PYTHON) scripts/benchmark_local.py

docker-build:
	docker build -t security-analyzer:local .

clean:
	rm -rf build dist .pytest_cache src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

ci: clean compile test wheel