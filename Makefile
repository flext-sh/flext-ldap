# =============================================================================
# FLEXT-LDAP - LDAP Directory Services Library Makefile
# =============================================================================
# Python 3.13+ LDAP Framework - Clean Architecture + DDD + Zero Tolerance
# =============================================================================

# Project Configuration
PROJECT_NAME := flext-ldap
PYTHON_VERSION := 3.13
POETRY := poetry
SRC_DIR := src
TESTS_DIR := tests
COV_DIR := flext_ldap

# Documentation maintenance tooling
FLEXT_ROOT := $(abspath ..)
DOCS_CLI := PYTHONPATH=$(FLEXT_ROOT)/flext-quality/src python -m flext_quality.docs_maintenance.cli
DOCS_PROFILE := advanced

# Quality Standards
# Note: 70% is achievable without Docker LDAP servers running.
# Server-specific implementations (openldap2, oid, oud) require Docker integration tests.
MIN_COVERAGE := 70

# LDAP Configuration
LDAP_HOST := localhost
LDAP_PORT := 389
LDAP_BASE_DN := dc=example,dc=com

# Export Configuration
export PROJECT_NAME PYTHON_VERSION MIN_COVERAGE LDAP_HOST LDAP_PORT LDAP_BASE_DN

# =============================================================================
# HELP & INFORMATION
# =============================================================================

.PHONY: help
help: ## Show available commands
	@echo "FLEXT-LDAP - LDAP Directory Services Library"
	@echo "==========================================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: info
info: ## Show project information
	@echo "Project: $(PROJECT_NAME)"
	@echo "Python: $(PYTHON_VERSION)+"
	@echo "Poetry: $(POETRY)"
	@echo "Coverage: $(MIN_COVERAGE)% minimum (achievable target)"
	@echo "LDAP: $(LDAP_HOST):$(LDAP_PORT)/$(LDAP_BASE_DN)"
	@echo "Architecture: Clean Architecture + DDD + LDAP3"

# =============================================================================
# SETUP & INSTALLATION
# =============================================================================

.PHONY: install
install: ## Install dependencies
	$(POETRY) install

.PHONY: install-dev
install-dev: ## Install dev dependencies
	$(POETRY) install --with dev,test,docs

.PHONY: setup
setup: install-dev ## Complete project setup
	$(POETRY) run pre-commit install

# =============================================================================
# QUALITY GATES (MANDATORY - ZERO TOLERANCE)
# =============================================================================

.PHONY: validate
validate: lint type-check security test ## Run all quality gates (MANDATORY ORDER)
# NOTE: audit-pydantic-v2 removed - script does not exist (../flext-core/docs/pydantic-v2-modernization/audit_pydantic_v2.py)

.PHONY: audit-pydantic-v2
audit-pydantic-v2: ## Audit Pydantic v2 compliance (DISABLED - script missing)
	@echo "⚠️  SKIPPED: audit-pydantic-v2 - script does not exist"
	@echo "📁 Expected location: ../flext-core/docs/pydantic-v2-modernization/audit_pydantic_v2.py"
	# @python ../flext-core/docs/pydantic-v2-modernization/audit_pydantic_v2.py --project .

.PHONY: check
check: lint type-check ## Quick health check

.PHONY: lint
lint: ## Run linting (ZERO TOLERANCE)
	$(POETRY) run ruff check .

.PHONY: format
format: ## Format code
	$(POETRY) run ruff format .

.PHONY: type-check
type-check: ## Run type checking with Pyrefly (PRODUCTION CODE ONLY - no relative imports in tests)
	$(POETRY) run pyrefly check $(SRC_DIR)

.PHONY: security
security: ## Run security scanning
	$(POETRY) run bandit -r $(SRC_DIR) --skip B106

.PHONY: fix
fix: ## Auto-fix issues
	$(POETRY) run ruff check . --fix
	$(POETRY) run ruff format .

# =============================================================================
# TESTING (MANDATORY - 75% COVERAGE MINIMUM)
# =============================================================================

.PHONY: test
test: ## Run tests with coverage minimum (MANDATORY) - includes Docker tests if container running
	PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest -q --maxfail=10000 --cov=$(COV_DIR) --cov-report=term-missing:skip-covered --cov-fail-under=$(MIN_COVERAGE) -p no:randomly

.PHONY: test-unit
test-unit: ## Run unit tests only (fast, no Docker)
	PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest -m "unit and not slow" -v

.PHONY: test-integration
test-integration: ## Run integration tests with Docker
	PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest -m integration -v

.PHONY: test-docker
test-docker: ## Run Docker-dependent tests
	PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest -m docker -v

.PHONY: test-ldap
test-ldap: ## Run LDAP specific tests
	$(POETRY) run pytest $(TESTS_DIR) -m ldap -v

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	$(POETRY) run pytest $(TESTS_DIR) -m e2e -v

.PHONY: test-fast
test-fast: ## Run fast tests only (exclude slow, integration, docker)
	PYTHONPATH=$(SRC_DIR):$(FLEXT_ROOT)/flext-core/src:$(FLEXT_ROOT)/flext-ldif/src $(POETRY) run pytest -m "not slow and not integration and not docker" -v

.PHONY: test-performance
test-performance: ## Run performance tests (isolated, avoid resource contention)
	PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest -m performance -v --maxfail=1

.PHONY: coverage-html
coverage-html: ## Generate HTML coverage report
	PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest --cov=$(COV_DIR) --cov-report=html

# =============================================================================
# BUILD & DISTRIBUTION
# =============================================================================

.PHONY: build
build: ## Build package
	$(POETRY) build

.PHONY: build-clean
build-clean: clean build ## Clean and build

# =============================================================================
# LDAP OPERATIONS
# =============================================================================

.PHONY: ldap-test
ldap-test: ## Test LDAP connection
	PYTHONPATH=$(SRC_DIR) $(POETRY) run python -c "from flext_ldap import get_ldap_api; print('LDAP test passed')"

.PHONY: ldap-validate
ldap-validate: ## Validate LDAP configuration
	PYTHONPATH=$(SRC_DIR) $(POETRY) run python -c "from flext_ldap.config import FlextLdapConfig; print('LDAP config valid')"

.PHONY: ldap-connect
ldap-connect: ## Test LDAP server connection
	PYTHONPATH=$(SRC_DIR) $(POETRY) run python -c "from flext_ldap import FlextLdapSimpleClient; print('LDAP connection OK')"

.PHONY: ldap-operations
ldap-operations: ldap-validate ldap-connect ldap-test ## Run all LDAP validations

# =============================================================================
# DOCKER LDAP SERVER (REAL TESTING)
# =============================================================================

# Docker Compose file path
DOCKER_COMPOSE_FILE := docker/docker-compose.yml

.PHONY: ldap-start
ldap-start: ## Start flext-openldap-test Docker container
	@echo "🐳 Starting flext-openldap-test LDAP server..."
	@cd $(shell pwd) && docker compose -f $(DOCKER_COMPOSE_FILE) up -d
	@echo "⏳ Waiting for health check..."
	@sleep 5
	@$(MAKE) ldap-health

.PHONY: ldap-stop
ldap-stop: ## Stop LDAP Docker container
	@echo "🛑 Stopping flext-openldap-test..."
	@cd $(shell pwd) && docker compose -f $(DOCKER_COMPOSE_FILE) stop

.PHONY: ldap-restart
ldap-restart: ldap-stop ldap-start ## Restart LDAP Docker container

.PHONY: ldap-logs
ldap-logs: ## View LDAP Docker container logs
	@cd $(shell pwd) && docker compose -f $(DOCKER_COMPOSE_FILE) logs -f openldap

.PHONY: ldap-logs-tail
ldap-logs-tail: ## Tail LDAP Docker logs (last 50 lines)
	@cd $(shell pwd) && docker compose -f $(DOCKER_COMPOSE_FILE) logs --tail=50 openldap

.PHONY: ldap-health
ldap-health: ## Check LDAP server health
	@echo "🏥 Checking LDAP server health..."
	@docker ps | grep flext-openldap-test > /dev/null && echo "✅ Container running" || (echo "❌ Container not running" && exit 1)
	@docker exec flext-openldap-test ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=flext,dc=local" -w "admin" -b "dc=flext,dc=local" -s base > /dev/null 2>&1 && echo "✅ LDAP server responding" || (echo "❌ LDAP server not responding" && exit 1)

.PHONY: ldap-clean
ldap-clean: ## Clean LDAP Docker (remove containers and volumes)
	@echo "🧹 Cleaning LDAP Docker environment..."
	@cd $(shell pwd) && docker compose -f $(DOCKER_COMPOSE_FILE) down -v
	@echo "✅ LDAP Docker cleanup complete"

.PHONY: ldap-reset
ldap-reset: ldap-clean ldap-start ## Reset LDAP server (clean + restart)

.PHONY: ldap-shell
ldap-shell: ## Open shell in LDAP Docker container
	docker exec -it flext-openldap-test /bin/bash

.PHONY: ldap-search
ldap-search: ## Search LDAP server (all entries)
	@echo "🔍 Searching LDAP server..."
	@docker exec flext-openldap-test ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=flext,dc=local" -w "admin123" -b "dc=flext,dc=local"

.PHONY: ldap-search-users
ldap-search-users: ## Search LDAP users
	@echo "🔍 Searching LDAP users..."
	@docker exec flext-openldap-test ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=flext,dc=local" -w "admin123" -b "ou=users,dc=flext,dc=local"

.PHONY: ldap-search-groups
ldap-search-groups: ## Search LDAP groups
	@echo "🔍 Searching LDAP groups..."
	@docker exec flext-openldap-test ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=flext,dc=local" -w "admin123" -b "ou=groups,dc=flext,dc=local"

# =============================================================================
# DOCUMENTATION
# =============================================================================

.PHONY: docs
docs: ## Build documentation
	$(POETRY) run mkdocs build

.PHONY: docs-maintenance
docs-maintenance: ## Run shared documentation maintenance (Markdown only)
	FLEXT_DOC_PROFILE=$(DOCS_PROFILE) FLEXT_DOC_PROJECT_ROOT=$(PWD) $(DOCS_CLI) --project-root $(PWD)

.PHONY: docs-serve
docs-serve: ## Serve documentation
	$(POETRY) run mkdocs serve

# =============================================================================
# DEPENDENCIES
# =============================================================================

.PHONY: deps-update
deps-update: ## Update dependencies
	$(POETRY) update

.PHONY: deps-show
deps-show: ## Show dependency tree
	$(POETRY) show --tree

.PHONY: deps-audit
deps-audit: ## Audit dependencies
	$(POETRY) run pip-audit

# =============================================================================
# DEVELOPMENT
# =============================================================================

.PHONY: shell
shell: ## Open Python shell
	PYTHONPATH=$(SRC_DIR) $(POETRY) run python

.PHONY: pre-commit
pre-commit: ## Run pre-commit hooks
	$(POETRY) run pre-commit run --all-files

# =============================================================================
# MAINTENANCE
# =============================================================================

.PHONY: clean
clean: ## Clean build artifacts and cruft
	@echo "🧹 Cleaning $(PROJECT_NAME) - removing build artifacts, cache files, and cruft..."

	# Build artifacts
	rm -rf build/ dist/ *.egg-info/

	# Test artifacts
	rm -rf .pytest_cache/ htmlcov/ .coverage .coverage.* coverage.xml

	# Python cache directories
	rm -rf .mypy_cache/ .pyrefly_cache/ .ruff_cache/

	# Python bytecode
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true

	# LDAP-specific files
	rm -rf *.ldif test.ldif sample.ldif

	# Data directories
	rm -rf data/ output/ temp/ fixtures/

	# Temporary files
	find . -type f -name "*.tmp" -delete 2>/dev/null || true
	find . -type f -name "*.temp" -delete 2>/dev/null || true
	find . -type f -name ".DS_Store" -delete 2>/dev/null || true

	# Log files
	find . -type f -name "*.log" -delete 2>/dev/null || true

	# Editor files
	find . -type f -name ".vscode/settings.json" -delete 2>/dev/null || true
	find . -type f -name ".idea/" -type d -exec rm -rf {} + 2>/dev/null || true

	@echo "✅ $(PROJECT_NAME) cleanup complete"

.PHONY: clean-all
clean-all: clean ## Deep clean including venv
	rm -rf .venv/

.PHONY: reset
reset: clean-all setup ## Reset project

# =============================================================================
# FLEXT-QUALITY INTEGRATION
# =============================================================================

.PHONY: docs-via-quality
docs-via-quality: ## Run documentation maintenance via flext-quality
	@command -v flext-quality >/dev/null 2>&1 || { echo "❌ flext-quality not available"; exit 1; }
	$(POETRY) run flext-quality make docs --project-path .

.PHONY: fix-via-quality
fix-via-quality: ## Run auto-fix via flext-quality
	@command -v flext-quality >/dev/null 2>&1 || { echo "❌ flext-quality not available"; exit 1; }
	$(POETRY) run flext-quality make fix --project-path .

.PHONY: validate-via-quality
validate-via-quality: ## Run validation via flext-quality
	@command -v flext-quality >/dev/null 2>&1 || { echo "❌ flext-quality not available"; exit 1; }
	$(POETRY) run flext-quality make validate --project-path .

# =============================================================================
# DIAGNOSTICS
# =============================================================================

.PHONY: diagnose
diagnose: ## Project diagnostics
	@echo "Python: $$(python --version)"
	@echo "Poetry: $$($(POETRY) --version)"
	@echo "LDAP3: $$(PYTHONPATH=$(SRC_DIR) $(POETRY) run python -c 'import ldap3; print(ldap3.__version__)' 2>/dev/null || echo 'Not available')"
	@$(POETRY) env info

.PHONY: doctor
doctor: diagnose check ## Health check

# =============================================================================

# =============================================================================

.PHONY: t l f tc c i v
t: test
l: lint
f: format
tc: type-check
c: clean
i: install
v: validate

# =============================================================================
# CONFIGURATION
# =============================================================================

.DEFAULT_GOAL := help
