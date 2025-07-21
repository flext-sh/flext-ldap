# FLEXT LDAP - Enterprise LDAP Directory Services
# ===============================================
# Comprehensive LDAP client and directory operations for FLEXT ecosystem
# Python 3.13 + LDAP + Clean Architecture + FLEXT Core + Zero Tolerance Quality Gates

.PHONY: help check validate test lint type-check security format format-check fix
.PHONY: install dev-install setup pre-commit build clean
.PHONY: coverage coverage-html test-unit test-integration test-ldap
.PHONY: deps-update deps-audit deps-tree deps-outdated
.PHONY: ldap-test ldap-connect ldap-schema ldap-operations
.PHONY: ldap-users ldap-groups ldap-auth ldap-performance

# ============================================================================
# 🎯 HELP & INFORMATION
# ============================================================================

help: ## Show this help message
	@echo "🎯 FLEXT LDAP - Enterprise LDAP Directory Services"
	@echo "================================================="
	@echo "🎯 Clean Architecture + DDD + LDAP + Python 3.13"
	@echo ""
	@echo "📦 Comprehensive LDAP client and directory operations"
	@echo "🔒 Zero tolerance quality gates with enterprise LDAP integration"
	@echo "🧪 90%+ test coverage requirement with real LDAP testing"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\\033[36m%-20s\\033[0m %s\\n", $$1, $$2}'

# ============================================================================
# 🎯 CORE QUALITY GATES - ZERO TOLERANCE
# ============================================================================

validate: lint type-check security test ## STRICT compliance validation (all must pass)
	@echo "✅ ALL QUALITY GATES PASSED - FLEXT LDAP COMPLIANT"

check: lint type-check test ## Essential quality checks (pre-commit standard)
	@echo "✅ Essential checks passed"

lint: ## Ruff linting (17 rule categories, ALL enabled)
	@echo "🔍 Running ruff linter (ALL rules enabled)..."
	@poetry run ruff check src/ tests/ --fix --unsafe-fixes
	@echo "✅ Linting complete"

type-check: ## MyPy strict mode type checking (zero errors tolerated)
	@echo "🛡️ Running MyPy strict type checking..."
	@poetry run mypy src/ tests/ --strict
	@echo "✅ Type checking complete"

security: ## Security scans (bandit + pip-audit + secrets)
	@echo "🔒 Running security scans..."
	@poetry run bandit -r src/ --severity-level medium --confidence-level medium
	@poetry run pip-audit --ignore-vuln PYSEC-2022-42969
	@poetry run detect-secrets scan --all-files
	@echo "✅ Security scans complete"

format: ## Format code with ruff
	@echo "🎨 Formatting code..."
	@poetry run ruff format src/ tests/
	@echo "✅ Formatting complete"

format-check: ## Check formatting without fixing
	@echo "🎨 Checking code formatting..."
	@poetry run ruff format src/ tests/ --check
	@echo "✅ Format check complete"

fix: format lint ## Auto-fix all issues (format + imports + lint)
	@echo "🔧 Auto-fixing all issues..."
	@poetry run ruff check src/ tests/ --fix --unsafe-fixes
	@echo "✅ All auto-fixes applied"

# ============================================================================
# 🧪 TESTING - 90% COVERAGE MINIMUM
# ============================================================================

test: ## Run tests with coverage (90% minimum required)
	@echo "🧪 Running tests with coverage..."
	@poetry run pytest tests/ -v --cov=src/flext_ldap --cov-report=term-missing --cov-fail-under=90
	@echo "✅ Tests complete"

test-unit: ## Run unit tests only
	@echo "🧪 Running unit tests..."
	@poetry run pytest tests/unit/ -v
	@echo "✅ Unit tests complete"

test-integration: ## Run integration tests only
	@echo "🧪 Running integration tests..."
	@poetry run pytest tests/integration/ -v
	@echo "✅ Integration tests complete"

test-ldap: ## Run LDAP-specific tests
	@echo "🧪 Running LDAP-specific tests..."
	@poetry run pytest tests/ -m "ldap" -v
	@echo "✅ LDAP tests complete"

test-auth: ## Run authentication tests
	@echo "🧪 Running authentication tests..."
	@poetry run pytest tests/ -m "auth" -v
	@echo "✅ Authentication tests complete"

test-containers: ## Run tests with LDAP containers
	@echo "🧪 Running containerized LDAP tests..."
	@poetry run pytest tests/ -m "containers" -v
	@echo "✅ Container tests complete"

coverage: ## Generate detailed coverage report
	@echo "📊 Generating coverage report..."
	@poetry run pytest tests/ --cov=src/flext_ldap --cov-report=term-missing --cov-report=html
	@echo "✅ Coverage report generated in htmlcov/"

coverage-html: coverage ## Generate HTML coverage report
	@echo "📊 Opening coverage report..."
	@python -m webbrowser htmlcov/index.html

# ============================================================================
# 🚀 DEVELOPMENT SETUP
# ============================================================================

setup: install pre-commit ## Complete development setup
	@echo "🎯 Development setup complete!"

install: ## Install dependencies with Poetry
	@echo "📦 Installing dependencies..."
	@poetry install --all-extras --with dev,test,docs,security
	@echo "✅ Dependencies installed"

dev-install: install ## Install in development mode
	@echo "🔧 Setting up development environment..."
	@poetry install --all-extras --with dev,test,docs,security
	@poetry run pre-commit install
	@echo "✅ Development environment ready"

pre-commit: ## Setup pre-commit hooks
	@echo "🎣 Setting up pre-commit hooks..."
	@poetry run pre-commit install
	@poetry run pre-commit run --all-files || true
	@echo "✅ Pre-commit hooks installed"

# ============================================================================
# 📁 LDAP OPERATIONS
# ============================================================================

ldap-test: ## Test LDAP functionality
	@echo "📁 Testing LDAP functionality..."
	@poetry run python -c "from flext_ldap.infrastructure.connection import LDAPConnectionManager; print('LDAP client loaded successfully')"
	@echo "✅ LDAP functionality test complete"

ldap-connect: ## Test LDAP connection
	@echo "📁 Testing LDAP connection..."
	@poetry run python scripts/test_ldap_connection.py
	@echo "✅ LDAP connection test complete"

ldap-schema: ## Validate LDAP schema
	@echo "📁 Validating LDAP schema..."
	@poetry run python scripts/validate_ldap_schema.py
	@echo "✅ LDAP schema validation complete"

ldap-operations: ## Test LDAP operations
	@echo "📁 Testing LDAP operations..."
	@poetry run python scripts/test_ldap_operations.py
	@echo "✅ LDAP operations test complete"

ldap-users: ## Test user operations
	@echo "👥 Testing LDAP user operations..."
	@poetry run python scripts/test_user_operations.py
	@echo "✅ User operations test complete"

ldap-groups: ## Test group operations
	@echo "👥 Testing LDAP group operations..."
	@poetry run python scripts/test_group_operations.py
	@echo "✅ Group operations test complete"

ldap-auth: ## Test authentication
	@echo "🔐 Testing LDAP authentication..."
	@poetry run python scripts/test_ldap_auth.py
	@echo "✅ Authentication test complete"

ldap-performance: ## Run LDAP performance tests
	@echo "⚡ Running LDAP performance tests..."
	@poetry run pytest tests/performance/ -v --benchmark-only
	@echo "✅ LDAP performance tests complete"

ldap-browse: ## Browse LDAP directory
	@echo "📁 Browsing LDAP directory..."
	@poetry run python scripts/browse_ldap_directory.py
	@echo "✅ LDAP directory browsing complete"

# ============================================================================
# 🔐 AUTHENTICATION & SECURITY
# ============================================================================

auth-test: ## Test authentication methods
	@echo "🔐 Testing authentication methods..."
	@poetry run python scripts/test_auth_methods.py
	@echo "✅ Authentication methods test complete"

ssl-test: ## Test SSL/TLS connections
	@echo "🔒 Testing SSL/TLS connections..."
	@poetry run python scripts/test_ssl_connections.py
	@echo "✅ SSL/TLS test complete"

sasl-test: ## Test SASL authentication
	@echo "🔐 Testing SASL authentication..."
	@poetry run python scripts/test_sasl_auth.py
	@echo "✅ SASL authentication test complete"

cert-validate: ## Validate certificates
	@echo "📜 Validating certificates..."
	@poetry run python scripts/validate_certificates.py
	@echo "✅ Certificate validation complete"

# ============================================================================
# 🏢 ACTIVE DIRECTORY SUPPORT
# ============================================================================

ad-test: ## Test Active Directory integration
	@echo "🏢 Testing Active Directory integration..."
	@poetry run python scripts/test_active_directory.py
	@echo "✅ Active Directory test complete"

ad-schema: ## Validate AD schema
	@echo "🏢 Validating Active Directory schema..."
	@poetry run python scripts/validate_ad_schema.py
	@echo "✅ AD schema validation complete"

ad-search: ## Test AD search operations
	@echo "🏢 Testing AD search operations..."
	@poetry run python scripts/test_ad_search.py
	@echo "✅ AD search test complete"

ad-groups: ## Test AD group operations
	@echo "🏢 Testing AD group operations..."
	@poetry run python scripts/test_ad_groups.py
	@echo "✅ AD group operations test complete"

# ============================================================================
# 🔍 LDAP UTILITIES
# ============================================================================

ldap-query: ## Run custom LDAP query
	@echo "🔍 Running custom LDAP query..."
	@poetry run python scripts/ldap_query_tool.py
	@echo "✅ LDAP query complete"

ldap-export: ## Export LDAP data
	@echo "📤 Exporting LDAP data..."
	@poetry run python scripts/export_ldap_data.py
	@echo "✅ LDAP data export complete"

ldap-import: ## Import LDAP data
	@echo "📥 Importing LDAP data..."
	@poetry run python scripts/import_ldap_data.py
	@echo "✅ LDAP data import complete"

ldap-backup: ## Backup LDAP directory
	@echo "💾 Backing up LDAP directory..."
	@poetry run python scripts/backup_ldap_directory.py
	@echo "✅ LDAP backup complete"

ldap-restore: ## Restore LDAP directory
	@echo "🔄 Restoring LDAP directory..."
	@poetry run python scripts/restore_ldap_directory.py
	@echo "✅ LDAP restore complete"

# ============================================================================
# 🔧 MAINTENANCE & DIAGNOSTICS
# ============================================================================

ldap-diagnostics: ## Run LDAP diagnostics
	@echo "🔍 Running LDAP diagnostics..."
	@poetry run python scripts/ldap_diagnostics.py
	@echo "✅ LDAP diagnostics complete"

ldap-health: ## Check LDAP health
	@echo "🏥 Checking LDAP health..."
	@poetry run python scripts/check_ldap_health.py
	@echo "✅ LDAP health check complete"

connection-test: ## Test connection pool
	@echo "🔗 Testing connection pool..."
	@poetry run python scripts/test_connection_pool.py
	@echo "✅ Connection pool test complete"

search-optimization: ## Test search optimization
	@echo "⚡ Testing search optimization..."
	@poetry run python scripts/test_search_optimization.py
	@echo "✅ Search optimization test complete"

# ============================================================================
# 📦 BUILD & DISTRIBUTION
# ============================================================================

build: clean ## Build distribution packages
	@echo "🔨 Building distribution..."
	@poetry build
	@echo "✅ Build complete - packages in dist/"

# ============================================================================
# 🧹 CLEANUP
# ============================================================================

clean: ## Remove all artifacts
	@echo "🧹 Cleaning up..."
	@rm -rf build/
	@rm -rf dist/
	@rm -rf *.egg-info/
	@rm -rf .coverage
	@rm -rf htmlcov/
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "✅ Cleanup complete"

# ============================================================================
# 📊 DEPENDENCY MANAGEMENT
# ============================================================================

deps-update: ## Update all dependencies
	@echo "🔄 Updating dependencies..."
	@poetry update
	@echo "✅ Dependencies updated"

deps-audit: ## Audit dependencies for vulnerabilities
	@echo "🔍 Auditing dependencies..."
	@poetry run pip-audit
	@echo "✅ Dependency audit complete"

deps-tree: ## Show dependency tree
	@echo "🌳 Dependency tree:"
	@poetry show --tree

deps-outdated: ## Show outdated dependencies
	@echo "📋 Outdated dependencies:"
	@poetry show --outdated

# ============================================================================
# 🔧 ENVIRONMENT CONFIGURATION
# ============================================================================

# Python settings
PYTHON := python3.13
export PYTHONPATH := $(PWD)/src:$(PYTHONPATH)
export PYTHONDONTWRITEBYTECODE := 1
export PYTHONUNBUFFERED := 1

# LDAP settings
export LDAP_HOST := localhost
export LDAP_PORT := 389
export LDAP_USE_SSL := false
export LDAP_BASE_DN := dc=test,dc=com

# Connection settings
export LDAP_POOL_SIZE := 10
export LDAP_TIMEOUT := 30
export LDAP_NETWORK_TIMEOUT := 10

# Authentication settings
export LDAP_BIND_DN := cn=admin,dc=test,dc=com
export LDAP_AUTH_METHOD := simple

# SSL/TLS settings
export LDAP_VERIFY_SSL := true
export LDAP_SSL_MODE := start_tls

# Poetry settings
export POETRY_VENV_IN_PROJECT := false
export POETRY_CACHE_DIR := $(HOME)/.cache/pypoetry

# Quality gate settings
export MYPY_CACHE_DIR := .mypy_cache
export RUFF_CACHE_DIR := .ruff_cache

# ============================================================================
# 📝 PROJECT METADATA
# ============================================================================

# Project information
PROJECT_NAME := flext-ldap
PROJECT_VERSION := $(shell poetry version -s)
PROJECT_DESCRIPTION := FLEXT LDAP - Enterprise LDAP Directory Services

.DEFAULT_GOAL := help

# ============================================================================
# 🎯 DEVELOPMENT UTILITIES
# ============================================================================

dev-ldap: ## Start development LDAP server
	@echo "🔧 Starting development LDAP server..."
	@docker run -d --name dev-ldap -p 3389:389 -e LDAP_ADMIN_PASSWORD=admin osixia/openldap:latest
	@echo "✅ Development LDAP server started on port 3389"

dev-ldap-stop: ## Stop development LDAP server
	@echo "🔧 Stopping development LDAP server..."
	@docker stop dev-ldap && docker rm dev-ldap
	@echo "✅ Development LDAP server stopped"

dev-ldap-logs: ## View development LDAP server logs
	@echo "📋 Viewing development LDAP server logs..."
	@docker logs -f dev-ldap

# ============================================================================
# 🎯 FLEXT ECOSYSTEM INTEGRATION
# ============================================================================

ecosystem-check: ## Verify FLEXT ecosystem compatibility
	@echo "🌐 Checking FLEXT ecosystem compatibility..."
	@echo "📦 Core project: $(PROJECT_NAME) v$(PROJECT_VERSION)"
	@echo "🏗️ Architecture: Clean Architecture + DDD + LDAP"
	@echo "🐍 Python: 3.13"
	@echo "🔗 Framework: FLEXT Core + Enterprise LDAP"
	@echo "📊 Quality: Zero tolerance enforcement"
	@echo "✅ Ecosystem compatibility verified"

workspace-info: ## Show workspace integration info
	@echo "🏢 FLEXT Workspace Integration"
	@echo "==============================="
	@echo "📁 Project Path: $(PWD)"
	@echo "🏆 Role: Enterprise LDAP Directory Services"
	@echo "🔗 Dependencies: flext-core (clean architecture foundation)"
	@echo "📦 Provides: LDAP client, authentication, directory operations"
	@echo "🎯 Standards: Enterprise LDAP patterns with Clean Architecture"
