.DEFAULT_GOAL = help

.PHONY: help
help: ## Display this help screen
	@grep -E '^[a-z.A-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: venv
venv: ## Setup python venv and symlink (uses direnv)
	direnv reload

.PHONY: install
install: venv ## Install prod dependencies
	poetry install

.PHONY: dev
dev: venv ## Install dev dependencies
	poetry install --with dev

.PHONY: test
test: dev ## Run pytest
	pytest

.PHONY: clean
clean: ## Remove venv and symlink
	rm -rf .direnv venv
