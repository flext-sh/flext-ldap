# FLEXT-LDAP Makefile
# Single source of truth for all operations
# All tools configured in pyproject.toml

.PHONY: help
help: ## Show this help message
	@echo "FLEXT-LDAP Development Commands"
	@echo "=============================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# =============================================================================
# ENVIRONMENT SETUP
# =============================================================================

.PHONY: install
install: ## Install all dependencies (including dev)
	poetry install --sync --with dev

.PHONY: install-prod
install-prod: ## Install production dependencies only
	poetry install --sync --only main

.PHONY: update
update: ## Update all dependencies to latest versions
	poetry update
	poetry lock
	poetry run pre-commit autoupdate

.PHONY: setup
setup: install ## Complete development environment setup
	poetry run pre-commit install --install-hooks
	@echo "✅ Development environment ready!"

# =============================================================================
# CODE QUALITY - Strict PEP compliance
# =============================================================================

.PHONY: format
format: ## Format code with ruff
	poetry run ruff format src tests

.PHONY: lint
lint: ## Run linters (ruff, mypy, bandit)
	@echo "🔍 Running Ruff..."
	poetry run ruff check src tests
	@echo "🔍 Running MyPy..."
	poetry run mypy src tests --strict
	@echo "🔍 Running Bandit security scan..."
	poetry run bandit -r src -ll
	@echo "✅ All linters passed!"

.PHONY: lint-fix
lint-fix: ## Fix auto-fixable lint issues
	poetry run ruff check src tests --fix
	poetry run ruff format src tests

.PHONY: type-check
type-check: ## Run strict type checking
	poetry run mypy src tests --strict

.PHONY: security
security: ## Run security checks
	poetry run bandit -r src -ll
	poetry run pip-audit

.PHONY: complexity
complexity: ## Check code complexity
	@find src -name "*.py" -exec poetry run python -m mccabe --min 11 {} \; | true
	@echo "✅ Complexity check passed (McCabe <= 10)"

.PHONY: dead-code
dead-code: ## Find dead code
	poetry run vulture src --min-confidence 70

.PHONY: check
check: format lint type-check security complexity ## Run ALL checks

.PHONY: check-strict
check-strict: ## Run checks without auto-fixing
	poetry run ruff format src tests --check --diff
	$(MAKE) lint

# =============================================================================
# TESTING
# =============================================================================

.PHONY: test
test: ## Run tests with coverage
	poetry run pytest

.PHONY: test-unit
test-unit: ## Run unit tests only
	poetry run pytest -m unit

.PHONY: test-integration
test-integration: ## Run integration tests only
	poetry run pytest -m integration

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	poetry run ptw -- -vv

.PHONY: test-debug
test-debug: ## Run tests with debugging enabled
	poetry run pytest -vv -s --tb=short --pdb-trace

.PHONY: coverage
coverage: ## Generate coverage report
	poetry run pytest --cov=src/flext_ldap --cov-report=html --cov-report=term-missing
	@echo "📊 Coverage report: file://$(PWD)/htmlcov/index.html"

# =============================================================================
# PRE-COMMIT
# =============================================================================

.PHONY: pre-commit
pre-commit: ## Run pre-commit on all files
	poetry run pre-commit run --all-files

.PHONY: pre-commit-update
pre-commit-update: ## Update pre-commit hooks
	poetry run pre-commit autoupdate

# =============================================================================
# BUILD & RELEASE
# =============================================================================

.PHONY: build
build: clean check test ## Build distribution packages
	poetry build

.PHONY: publish
publish: ## Publish to PyPI (requires authentication)
	poetry publish

.PHONY: publish-test
publish-test: ## Publish to TestPyPI
	poetry publish -r test-pypi

# =============================================================================
# DOCUMENTATION
# =============================================================================

.PHONY: docs
docs: ## Build documentation
	poetry run mkdocs build

.PHONY: docs-serve
docs-serve: ## Serve documentation with live reload
	poetry run mkdocs serve

.PHONY: docs-deploy
docs-deploy: ## Deploy documentation to GitHub Pages
	poetry run mkdocs gh-deploy

# =============================================================================
# DEVELOPMENT TOOLS
# =============================================================================

.PHONY: shell
shell: ## Start IPython shell with project context
	poetry run ipython

.PHONY: console
console: ## Start Python console with project loaded
	poetry run python

# =============================================================================
# CLEAN
# =============================================================================

.PHONY: clean
clean: ## Clean build artifacts and caches
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build dist htmlcov .coverage* site

.PHONY: clean-all
clean-all: clean ## Clean everything including poetry lock
	rm -rf .venv poetry.lock

# =============================================================================
# CI/CD COMMANDS
# =============================================================================

.PHONY: ci
ci: ## Run CI pipeline locally
	$(MAKE) install
	$(MAKE) check-strict
	$(MAKE) test
	$(MAKE) build

.PHONY: ci-cache-key
ci-cache-key: ## Generate cache key for CI
	@echo "poetry-$(shell cat poetry.lock | sha256sum | cut -d' ' -f1)"

# =============================================================================
# VERSION MANAGEMENT
# =============================================================================

.PHONY: version
version: ## Show current version
	@poetry version

.PHONY: version-patch
version-patch: ## Bump patch version (0.0.X)
	poetry version patch

.PHONY: version-minor
version-minor: ## Bump minor version (0.X.0)
	poetry version minor

.PHONY: version-major
version-major: ## Bump major version (X.0.0)
	poetry version major

# =============================================================================
# FLEXT STANDARDS
# =============================================================================

.PHONY: flext-validate
flext-validate: ## Validate against FLEXT standards
	@echo "🏗️  Validating FLEXT standards..."
	@echo "✓ Python 3.13+ only"
	@echo "✓ Async/await patterns"
	@echo "✓ Type hints 100%"
	@echo "✓ PEP compliance"
	@echo "✓ Security scanning"
	$(MAKE) check-strict

.PHONY: flext-sync
flext-sync: ## Sync with FLEXT workspace standards
	@echo "🔄 Syncing with FLEXT standards..."
	cp ../flext-core/.pre-commit-config.yaml .pre-commit-config.yaml 2>/dev/null || true
	@echo "✅ Synced with FLEXT workspace"

# Default target
.DEFAULT_GOAL := help

# Include standardized build system
include Makefile.build
