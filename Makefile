.DEFAULT_GOAL = help

.PHONY: help
help: ## Display this help screen
	@grep -E '^[a-z.A-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: venv
venv: ## Setup python venv using uv
	uv venv

.PHONY: install
install: venv ## Install prod dependencies
	uv sync

.PHONY: dev
dev: venv ## Install dev dependencies
	uv sync --extra dev

.PHONY: test
test: dev ## Run pytest
	uv run pytest

.PHONY: clean
clean: ## Remove venv and cache
	rm -rf .venv
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -name "*.egg-info" -type d -exec rm -rf {} +
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete

.PHONY: lint
lint: dev ## Run linting tools
	uv run black --check .
	uv run isort --check-only .
	uv run flake8 .

.PHONY: format
format: dev ## Format code
	uv run black .
	uv run isort .
