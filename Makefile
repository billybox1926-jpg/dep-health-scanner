.PHONY: install quality format lint test all

install:
	pip install -e ".[dev]"

format:
	ruff format src/ tests/

lint:
	ruff check src/ tests/

test:
	pytest

quality: format lint test

all: quality
