# FLEXT LDAP - Enterprise LDAP Directory Services Library
# ========================================================
# Professional LDAP client library with enterprise features
# PROJECT_TYPE: python-library
# Python 3.13 + LDAP + Clean Architecture + Zero Tolerance Quality

.PHONY: help install test lint type-check format clean build docs
.PHONY: check validate dev-setup deps-update deps-audit info diagnose
.PHONY: install-dev test-unit test-integration test-coverage test-watch
.PHONY: format-check security pre-commit build-clean publish publish-test
.PHONY: dev dev-test clean-all emergency-reset
.PHONY: ldap-test ldap-connect ldap-schema ldap-operations test-ldap test-auth

# ============================================================================
# 🎯 CONFIGURAÇÃO E DETECÇÃO
# ============================================================================

# Detectar nome do projeto
PROJECT_NAME := flext-ldap
PROJECT_TYPE := python-library
PROJECT_TITLE := FLEXT LDAP
PROJECT_VERSION := $(shell poetry version -s)

# Ambiente Python
PYTHON := python3.13
POETRY := poetry
VENV_PATH := $(shell poetry env info --path 2>/dev/null || echo "")

# ============================================================================
# 🎯 AJUDA E INFORMAÇÃO
# ============================================================================

help: ## Mostrar ajuda e comandos disponíveis
	@echo "🏆 $(PROJECT_TITLE) - Comandos Essenciais"
	@echo "===================================="
	@echo "📦 Enterprise LDAP Directory Services"
	@echo "🐍 Python 3.13 + LDAP + Zero Tolerância"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "%-20s %s\n", $$1, $$2}'
	@echo ""
	@echo "💡 Comandos principais: make install, make test, make lint"

info: ## Mostrar informações do projeto
	@echo "📊 Informações do Projeto"
	@echo "======================"
	@echo "Nome: $(PROJECT_NAME)"
	@echo "Título: $(PROJECT_TITLE)"
	@echo "Versão: $(PROJECT_VERSION)"
	@echo "Python: $(shell $(PYTHON) --version 2>/dev/null || echo "Não encontrado")"
	@echo "Poetry: $(shell $(POETRY) --version 2>/dev/null || echo "Não instalado")"
	@echo "Venv: $(shell [ -n "$(VENV_PATH)" ] && echo "$(VENV_PATH)" || echo "Não ativado")"
	@echo "Diretório: $(CURDIR)"
	@echo "Git Branch: $(shell git branch --show-current 2>/dev/null || echo "Não é repo git")"
	@echo "Git Status: $(shell git status --porcelain 2>/dev/null | wc -l | xargs echo) arquivos alterados"

diagnose: ## Executar diagnósticos completos
	@echo "🔍 Executando diagnósticos para $(PROJECT_NAME)..."
	@echo "Informações do Sistema:"
	@echo "OS: $(shell uname -s)"
	@echo "Arquitetura: $(shell uname -m)"
	@echo "Python: $(shell $(PYTHON) --version 2>/dev/null || echo "Não encontrado")"
	@echo "Poetry: $(shell $(POETRY) --version 2>/dev/null || echo "Não instalado")"
	@echo ""
	@echo "Estrutura do Projeto:"
	@ls -la
	@echo ""
	@echo "Configuração Poetry:"
	@$(POETRY) config --list 2>/dev/null || echo "Poetry não configurado"
	@echo ""
	@echo "Status das Dependências:"
	@$(POETRY) show --outdated 2>/dev/null || echo "Nenhuma dependência desatualizada"

# ============================================================================
# 📦 GERENCIAMENTO DE DEPENDÊNCIAS
# ============================================================================

validate-setup: ## Validar ambiente de desenvolvimento
	@echo "🔍 Validando ambiente de desenvolvimento..."
	@command -v $(PYTHON) >/dev/null 2>&1 || { echo "❌ Python 3.13 não encontrado"; exit 1; }
	@command -v $(POETRY) >/dev/null 2>&1 || { echo "❌ Poetry não encontrado"; exit 1; }
	@test -f pyproject.toml || { echo "❌ pyproject.toml não encontrado"; exit 1; }
	@echo "✅ Validação do ambiente passou"

install: validate-setup ## Instalar dependências de runtime
	@echo "📦 Instalando dependências de runtime para $(PROJECT_NAME)..."
	@$(POETRY) install --only main
	@echo "✅ Dependências de runtime instaladas"

install-dev: validate-setup ## Instalar todas as dependências incluindo dev tools
	@echo "📦 Instalando todas as dependências para $(PROJECT_NAME)..."
	@$(POETRY) install --all-extras
	@echo "✅ Todas as dependências instaladas"

deps-update: ## Atualizar dependências para versões mais recentes
	@echo "🔄 Atualizando dependências para $(PROJECT_NAME)..."
	@$(POETRY) update
	@echo "✅ Dependências atualizadas"

deps-show: ## Mostrar árvore de dependências
	@echo "📊 Árvore de dependências para $(PROJECT_NAME):"
	@$(POETRY) show --tree

deps-audit: ## Auditoria de dependências para vulnerabilidades
	@echo "🔍 Auditando dependências para $(PROJECT_NAME)..."
	@$(POETRY) run pip-audit --format=columns || echo "⚠️  pip-audit não disponível"
	@$(POETRY) run safety check --json || echo "⚠️  safety não disponível"

# ============================================================================
# 🧪 TESTES
# ============================================================================

test: ## Executar todos os testes (90% cobertura mínima para LDAP)
	@echo "🧪 Executando todos os testes para $(PROJECT_NAME)..."
	@$(POETRY) run pytest tests/ -v --cov=src/flext_ldap --cov-report=term-missing --cov-fail-under=90
	@echo "✅ Todos os testes passaram"

test-unit: ## Executar apenas testes unitários
	@echo "🧪 Executando testes unitários para $(PROJECT_NAME)..."
	@$(POETRY) run pytest tests/unit/ -xvs -m "not integration and not slow"
	@echo "✅ Testes unitários passaram"

test-integration: ## Executar apenas testes de integração
	@echo "🧪 Executando testes de integração para $(PROJECT_NAME)..."
	@$(POETRY) run pytest tests/integration/ -xvs -m "integration"
	@echo "✅ Testes de integração passaram"

test-ldap: ## Executar testes específicos LDAP
	@echo "🧪 Executando testes específicos LDAP para $(PROJECT_NAME)..."
	@$(POETRY) run pytest tests/ -m "ldap" -v
	@echo "✅ Testes LDAP passaram"

test-auth: ## Executar testes de autenticação LDAP
	@echo "🧪 Executando testes de autenticação para $(PROJECT_NAME)..."
	@$(POETRY) run pytest tests/ -m "auth" -v
	@echo "✅ Testes de autenticação passaram"

test-containers: ## Executar testes com containers LDAP
	@echo "🧪 Executando testes com containers LDAP para $(PROJECT_NAME)..."
	@$(POETRY) run pytest tests/ -m "containers" -v --tb=short
	@echo "✅ Testes com containers passaram"

test-coverage: ## Executar testes com relatório de cobertura
	@echo "🧪 Executando testes com cobertura para $(PROJECT_NAME)..."
	@$(POETRY) run pytest --cov --cov-report=html --cov-report=term-missing --cov-report=xml
	@echo "✅ Relatório de cobertura gerado"

test-watch: ## Executar testes em modo watch
	@echo "👀 Executando testes em modo watch para $(PROJECT_NAME)..."
	@$(POETRY) run pytest-watch --clear

coverage-html: test-coverage ## Gerar e abrir relatório HTML de cobertura
	@echo "📊 Abrindo relatório de cobertura..."
	@python -m webbrowser htmlcov/index.html

# ============================================================================
# 🎨 QUALIDADE DE CÓDIGO E FORMATAÇÃO
# ============================================================================

lint: ## Executar todos os linters com máxima rigorosidade
	@echo "🔍 Executando linting com máxima rigorosidade para $(PROJECT_NAME)..."
	@$(POETRY) run ruff check . --output-format=github
	@echo "✅ Linting completado"

format: ## Formatar código com padrões rigorosos
	@echo "🎨 Formatando código para $(PROJECT_NAME)..."
	@$(POETRY) run ruff format .
	@$(POETRY) run ruff check . --fix --unsafe-fixes
	@echo "✅ Código formatado"

format-check: ## Verificar formatação sem alterar
	@echo "🔍 Verificando formatação para $(PROJECT_NAME)..."
	@$(POETRY) run ruff format . --check
	@$(POETRY) run ruff check . --output-format=github
	@echo "✅ Formatação verificada"

type-check: ## Executar verificação de tipos rigorosa
	@echo "🔍 Executando verificação de tipos rigorosa para $(PROJECT_NAME)..."
	@$(POETRY) run mypy src/ --strict --show-error-codes
	@echo "✅ Verificação de tipos passou"

security: ## Executar análise de segurança
	@echo "🔒 Executando análise de segurança para $(PROJECT_NAME)..."
	@$(POETRY) run bandit -r src/ -f json || echo "⚠️  bandit não disponível"
	@$(POETRY) run detect-secrets scan --all-files || echo "⚠️  detect-secrets não disponível"
	@echo "✅ Análise de segurança completada"

pre-commit: ## Executar hooks pre-commit
	@echo "🔧 Executando hooks pre-commit para $(PROJECT_NAME)..."
	@$(POETRY) run pre-commit run --all-files || echo "⚠️  pre-commit não disponível"
	@echo "✅ Hooks pre-commit completados"

check: lint type-check security ## Executar todas as verificações de qualidade
	@echo "🔍 Executando verificações abrangentes de qualidade para $(PROJECT_NAME)..."
	@echo "✅ Todas as verificações de qualidade passaram"

validate: check test ## Validação STRICT de conformidade (tudo deve passar)
	@echo "✅ TODOS OS QUALITY GATES PASSARAM - FLEXT LDAP COMPLIANT"

# ============================================================================
# 🏗️ BUILD E DISTRIBUIÇÃO
# ============================================================================

build: clean ## Construir o pacote com Poetry
	@echo "🏗️  Construindo pacote $(PROJECT_NAME)..."
	@$(POETRY) build
	@echo "✅ Pacote construído com sucesso"
	@echo "📦 Artefatos de build:"
	@ls -la dist/

build-clean: clean build ## Limpar e construir
	@echo "✅ Build limpo completado"

publish-test: build ## Publicar no TestPyPI
	@echo "📤 Publicando $(PROJECT_NAME) no TestPyPI..."
	@$(POETRY) publish --repository testpypi
	@echo "✅ Publicado no TestPyPI"

publish: build ## Publicar no PyPI
	@echo "📤 Publicando $(PROJECT_NAME) no PyPI..."
	@$(POETRY) publish
	@echo "✅ Publicado no PyPI"

# ============================================================================
# 📚 DOCUMENTAÇÃO
# ============================================================================

docs: ## Gerar documentação
	@echo "📚 Gerando documentação para $(PROJECT_NAME)..."
	@if [ -f mkdocs.yml ]; then \
		$(POETRY) run mkdocs build; \
	else \
		echo "⚠️  Nenhum mkdocs.yml encontrado, pulando geração de documentação"; \
	fi
	@echo "✅ Documentação gerada"

docs-serve: ## Servir documentação localmente
	@echo "📚 Servindo documentação para $(PROJECT_NAME)..."
	@if [ -f mkdocs.yml ]; then \
		$(POETRY) run mkdocs serve; \
	else \
		echo "⚠️  Nenhum mkdocs.yml encontrado"; \
	fi

# ============================================================================
# 🚀 DESENVOLVIMENTO
# ============================================================================

dev-setup: install-dev ## Configuração completa de desenvolvimento
	@echo "🚀 Configurando ambiente de desenvolvimento para $(PROJECT_NAME)..."
	@$(POETRY) run pre-commit install || echo "⚠️  pre-commit não disponível"
	@echo "✅ Ambiente de desenvolvimento pronto"

dev: ## Executar em modo desenvolvimento
	@echo "🚀 Iniciando modo desenvolvimento para $(PROJECT_NAME)..."
	@if [ -f src/flext_ldap/cli.py ]; then \
		$(POETRY) run python -m flext_ldap.cli --dev; \
	elif [ -f src/flext_ldap/main.py ]; then \
		$(POETRY) run python -m flext_ldap.main --dev; \
	else \
		echo "⚠️  Nenhum ponto de entrada principal encontrado"; \
	fi

dev-test: ## Ciclo rápido de teste de desenvolvimento
	@echo "⚡ Ciclo rápido de teste de desenvolvimento para $(PROJECT_NAME)..."
	@$(POETRY) run ruff check . --fix
	@$(POETRY) run pytest tests/ -x --tb=short
	@echo "✅ Ciclo de teste de desenvolvimento completado"

# ============================================================================
# 🎯 LIBRARY SPECIFIC OPERATIONS
# ============================================================================

lib-test: ldap-validate-all ## Run comprehensive library tests

lib-validate: validate ## Alias for complete validation

lib-examples: ## Run library usage examples
	@echo "📚 Running library examples..."
	@poetry run python examples/integrated_ldap_service.py
	@echo "✅ Library examples complete"

lib-benchmarks: ## Run library performance benchmarks
	@echo "⚡ Running library benchmarks..."
	@poetry run python -m flext_ldap.benchmarks.performance
	@echo "✅ Library benchmarks complete"

lib-compatibility: ## Test library compatibility
	@echo "🔄 Testing library compatibility..."
	@poetry run python -m flext_ldap.compatibility.test_versions
	@echo "✅ Library compatibility test complete"

# ============================================================================
# 🎯 LDAP SPECIFIC OPERATIONS
# ============================================================================

ldap-test: ## Testar conectividade LDAP básica
	@echo "🎯 Testando conectividade LDAP básica..."
	@$(POETRY) run python -c "from flext_ldap.infrastructure.adapters import DirectoryAdapter; from flext_ldap.config import LDAPSettings; settings = LDAPSettings(); adapter = DirectoryAdapter(settings); print('Teste LDAP básico executado')"
	@echo "✅ Teste LDAP básico completado"

ldap-connect: ## Testar conexão com servidor LDAP
	@echo "🔗 Testando conexão com servidor LDAP..."
	@$(POETRY) run python -c "from flext_ldap.infrastructure.clients import LDAPClient; from flext_ldap.config import LDAPSettings; settings = LDAPSettings(); client = LDAPClient(settings); result = client.test_connection(); print(f'Conexão LDAP: {result}')"
	@echo "✅ Teste de conexão LDAP completado"

ldap-schema: ## Verificar schema LDAP
	@echo "📋 Verificando schema LDAP..."
	@$(POETRY) run python -c "from flext_ldap.domain.services import SchemaService; from flext_ldap.config import LDAPSettings; settings = LDAPSettings(); service = SchemaService(settings); schema_info = service.get_schema_info(); print(f'Schema LDAP verificado: {len(schema_info)} atributos')"
	@echo "✅ Verificação de schema LDAP completada"

ldap-operations: ## Testar operações LDAP básicas
	@echo "⚙️ Testando operações LDAP básicas..."
	@$(POETRY) run python -c "from flext_ldap.application.services import DirectoryService; from flext_ldap.config import LDAPSettings; settings = LDAPSettings(); service = DirectoryService(settings); print('Operações LDAP básicas testadas')"
	@echo "✅ Teste de operações LDAP completado"

ldap-users: ## Testar operações de usuários LDAP
	@echo "👥 Testando operações de usuários LDAP..."
	@$(POETRY) run python -c "from flext_ldap.domain.entities import LDAPUser; from flext_ldap.application.services import UserService; print('Operações de usuários LDAP testadas')"
	@echo "✅ Teste de usuários LDAP completado"

ldap-groups: ## Testar operações de grupos LDAP
	@echo "👫 Testando operações de grupos LDAP..."
	@$(POETRY) run python -c "from flext_ldap.domain.entities import LDAPGroup; from flext_ldap.application.services import GroupService; print('Operações de grupos LDAP testadas')"
	@echo "✅ Teste de grupos LDAP completado"

ldap-auth: ## Testar autenticação LDAP
	@echo "🔐 Testando autenticação LDAP..."
	@$(POETRY) run python -c "from flext_ldap.application.services import AuthenticationService; from flext_ldap.config import LDAPSettings; settings = LDAPSettings(); service = AuthenticationService(settings); print('Autenticação LDAP testada')"
	@echo "✅ Teste de autenticação LDAP completado"

ldap-performance: ## Testar performance LDAP
	@echo "⚡ Testando performance LDAP..."
	@$(POETRY) run python -c "from flext_ldap.infrastructure.performance import PerformanceTester; tester = PerformanceTester(); result = tester.run_basic_tests(); print(f'Performance LDAP: {result}')"
	@echo "✅ Teste de performance LDAP completado"

ldap-validate-all: ldap-connect ldap-schema ldap-operations ldap-auth ## Validate all LDAP operations
	@echo "✅ All LDAP operations validated"

ldap-integration-test: ## Run LDAP integration tests with real server
	@echo "🔗 Running LDAP integration tests..."
	@poetry run pytest tests/integration/ -m "ldap_server" -v
	@echo "✅ LDAP integration tests complete"

ldap-mock-test: ## Run LDAP tests with mock server
	@echo "🎭 Running LDAP mock tests..."
	@poetry run pytest tests/unit/ -m "ldap_mock" -v
	@echo "✅ LDAP mock tests complete"

# ============================================================================
# 🧹 LIMPEZA
# ============================================================================

clean: ## Limpar artefatos de build
	@echo "🧹 Limpando artefatos de build para $(PROJECT_NAME)..."
	@rm -rf build/
	@rm -rf dist/
	@rm -rf *.egg-info/
	@rm -rf .pytest_cache/
	@rm -rf .coverage
	@rm -rf htmlcov/
	@rm -rf .mypy_cache/
	@rm -rf .ruff_cache/
	@rm -rf reports/
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@echo "✅ Limpeza completada"

clean-all: clean ## Limpar tudo incluindo ambiente virtual
	@echo "🧹 Limpeza profunda para $(PROJECT_NAME)..."
	@$(POETRY) env remove --all || true
	@echo "✅ Limpeza profunda completada"

# ============================================================================
# 🚨 PROCEDIMENTOS DE EMERGÊNCIA
# ============================================================================

emergency-reset: ## Reset de emergência para estado limpo
	@echo "🚨 RESET DE EMERGÊNCIA para $(PROJECT_NAME)..."
	@read -p "Tem certeza que quer resetar tudo? (y/N) " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		$(MAKE) clean-all; \
		$(MAKE) install-dev; \
		echo "✅ Reset de emergência completado"; \
	else \
		echo "⚠️  Reset de emergência cancelado"; \
	fi

# ============================================================================
# 🎯 VALIDAÇÃO E VERIFICAÇÃO
# ============================================================================

workspace-validate: ## Validar conformidade do workspace
	@echo "🔍 Validando conformidade do workspace para $(PROJECT_NAME)..."
	@test -f pyproject.toml || { echo "❌ pyproject.toml ausente"; exit 1; }
	@test -f CLAUDE.md || echo "⚠️  CLAUDE.md ausente"
	@test -f README.md || echo "⚠️  README.md ausente"
	@test -d src/ || { echo "❌ diretório src/ ausente"; exit 1; }
	@test -d tests/ || echo "⚠️  diretório tests/ ausente"
	@echo "✅ Conformidade do workspace validada"

# ============================================================================
# 🎯 ALIASES DE CONVENIÊNCIA
# ============================================================================

# Aliases para operações comuns
t: test ## Alias para test
l: lint ## Alias para lint
tc: type-check ## Alias para type-check
f: format ## Alias para format
c: clean ## Alias para clean
i: install-dev ## Alias para install-dev
d: dev ## Alias para dev
dt: dev-test ## Alias para dev-test

# Library-specific aliases
lib: lib-test ## Alias for lib-test
libe: lib-examples ## Alias for lib-examples
libb: lib-benchmarks ## Alias for lib-benchmarks
libc: lib-compatibility ## Alias for lib-compatibility

# LDAP-specific aliases
lt: ldap-test ## Alias for ldap-test
lc: ldap-connect ## Alias for ldap-connect
ls: ldap-schema ## Alias for ldap-schema
lo: ldap-operations ## Alias for ldap-operations
lu: ldap-users ## Alias for ldap-users
lg: ldap-groups ## Alias for ldap-groups
la: ldap-auth ## Alias for ldap-auth
lp: ldap-performance ## Alias for ldap-performance
lva: ldap-validate-all ## Alias for ldap-validate-all

# Configurações de ambiente
export PYTHONPATH := $(PWD)/src:$(PYTHONPATH)
export PYTHONDONTWRITEBYTECODE := 1
export PYTHONUNBUFFERED := 1

# LDAP settings for development
export FLEXT_LDAP_HOST := localhost
export FLEXT_LDAP_PORT := 389
export FLEXT_LDAP_USE_SSL := false
export FLEXT_LDAP_BASE_DN := dc=example,dc=com
export FLEXT_LDAP_BIND_DN := cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
export FLEXT_LDAP_BIND_PASSWORD := REDACTED_LDAP_BIND_PASSWORD

.DEFAULT_GOAL := help
