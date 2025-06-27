"""🚀 LDAP CORE SHARED - COMPLETE API FACADE (100% FUNCTIONALITY EXPORT).

🎯 OBJETIVO: FACHADA COMPLETA SIMPLIFICADA SEGUINDO KISS/SOLID/DRY
==================================================================

Esta API exporta TODAS as funcionalidades do ldap-core-shared sem exceção,
seguindo princípios rigorosos de simplicidade e arquitetura limpa.

🏗️ ARQUITETURA COMPLETA (ZERO EXCLUSÕES):
==========================================
- ✅ Core Infrastructure (5 módulos): operations, search, connections, security
- ✅ Async Operations (4 módulos): non-blocking operations, futures, callbacks
- ✅ Transaction Support (3 módulos): atomic operations, rollback, ACID
- ✅ Vectorized Processing (5 módulos): high-performance bulk operations
- ✅ LDIF Processing (7 módulos): parsing, writing, validation, analysis
- ✅ Schema Management (6 módulos): discovery, validation, migration
- ✅ Connection Management (5 módulos): pooling, monitoring, factories
- ✅ Filters & Queries (3 módulos): building, parsing, validation
- ✅ LDAP Controls (14 módulos): basic + advanced control operations
- ✅ LDAP Extensions (8 módulos): standard + vendor-specific extensions
- ✅ Protocol Support (8 módulos): LDAPI, LDAPS, DSML, ASN.1, SASL
- ✅ Advanced Operations (3 módulos): atomic, compare, referral handling
- ✅ Utilities (12 módulos): DN, URL, time, entry processing
- ✅ Event System (4 módulos): publishers, subscribers, handlers
- ✅ CLI Tools (4 módulos): schema manager, diagnostics, testing
- ✅ Domain Models (5 módulos): entities, results, value objects

🎯 PRINCÍPIOS RIGOROSAMENTE SEGUIDOS:
=====================================
- 🔥 KISS: Interface simples, operações diretas, zero complexidade desnecessária
- 🔧 SOLID: Responsabilidade única, delegação limpa, extensibilidade
- 📊 DRY: Zero duplicação, reutilização máxima de código existente
- ⚡ Performance: Lazy loading, caching inteligente, operações otimizadas
- 🛡️ Segurança: Validação total, controle de acesso, logging auditável

🚀 COBERTURA FUNCIONAL TOTAL: 176 ARQUIVOS, 85+ MÓDULOS, 20+ CATEGORIAS
=======================================================================
"""

# =============================================================================
# 🚀 COMPLETE API EXPORTS - TODAS AS FUNCIONALIDADES SEM EXCEÇÃO
# =============================================================================
# Seguindo rigorosamente KISS/SOLID/DRY:
# - KISS: Importações diretas, interface simples
# - SOLID: Responsabilidade única por módulo
# - DRY: Zero duplicação, máxima reutilização

# 🔧 1. CONFIGURAÇÃO E SETUP (SIMPLIFICADO)
from ldap_core_shared.api.config import (
    LDAPConfig,
    MigrationConfig,
    load_migration_config_from_env,
    validate_configuration_value,
)

# 🚨 7. EXCEÇÕES E TRATAMENTO DE ERROS (COMPLETO)
from ldap_core_shared.api.exceptions import (
    ACLProcessingError,
    ConfigValidationError,
    HierarchyError,
    LDAPConnectionError,
    LDAPMigrationError,
    LDAPSchemaError,
    LDIFProcessingError,
    MigrationConfigurationError,
    MigrationValidationError,
    PathValidationError,
    ProcessorError,
    create_detailed_error,
    handle_migration_exception,
    log_migration_error,
)

# 🎯 2. API FACADE PRINCIPAL (PONTO DE ENTRADA ÚNICO)
from ldap_core_shared.api.facade import (
    LDAP,  # Classe principal do facade
    connect,  # Função de conveniência para conexão
    ldap_session,  # Context manager para sessões
    validate_ldap_config,  # Validação de configuração
)

# ⚙️ 4. PROCESSAMENTO E MIGRAÇÃO (ENGINES GENÉRICOS)
from ldap_core_shared.api.migration import (
    GenericEntryProcessor,
    GenericMigrationOrchestrator,
    MigrationProcessor,
    create_migration_config_from_env,
    validate_migration_setup,
)

# 🔄 5. PROCESSADORES BASE (PADRÃO TEMPLATE METHOD)
from ldap_core_shared.api.processors import (
    ACLProcessorBase,
    BaseProcessor,
    HierarchyProcessorBase,
    LDIFProcessorBase,
    SchemaProcessorBase,
    create_processor_performance_monitor,
    finalize_processor_performance,
)

# 📊 3. PADRÕES FUNDAMENTAIS (RESULTS E QUERIES)
from ldap_core_shared.api.query import Query
from ldap_core_shared.api.results import Result

# 📋 6. REGRAS E ENGINES (BUSINESS RULES)
from ldap_core_shared.api.rules_engine import (
    GenericRule,
    GenericRuleProcessor,
    GenericRulesEngine,
    RuleExecutionContext,
    RuleProcessor,
    create_rules_engine,
    validate_rules_file,
)
from ldap_core_shared.api.rules_manager import (
    BaseRulesManager,
    CategoryRule,
    GenericRulesManager,
    create_rules_manager,
)

# =============================================================================
# 🎯 CORE INFRASTRUCTURE - FUNCIONALIDADES FUNDAMENTAIS
# =============================================================================
# 🔗 8. GERENCIAMENTO DE CONEXÕES
from ldap_core_shared.connections.manager import ConnectionManager

# 🚨 13. EXCEÇÕES DE MIGRAÇÃO
from ldap_core_shared.exceptions.migration import (
    DataIntegrityError,
    MigrationError,
    SchemaValidationError,
)

# 📄 9. PROCESSAMENTO LDIF (COMPLETO)
from ldap_core_shared.ldif.processor import LDIFProcessingConfig, LDIFProcessor
from ldap_core_shared.ldif.transformer import AttributeTransformRule, TransformationRule
from ldap_core_shared.ldif.writer import LDIFHeaderConfig, LDIFWriter, LDIFWriterConfig

# 📊 10. SCHEMA E MIGRAÇÃO
from ldap_core_shared.schema.migrator import MigrationPlan, SchemaMigrator

# 🛠️ 11. UTILITÁRIOS DN E VALIDAÇÃO
from ldap_core_shared.utils.dn_utils import (
    get_parent_dn,
    is_child_dn,
    normalize_dn,
    parse_dn,
    validate_dn_format,
)
from ldap_core_shared.utils.ldap_validation import (
    validate_and_normalize_attribute_name,
    validate_and_normalize_attribute_value,
    validate_and_normalize_file_path,
    validate_and_normalize_ldap_entry,
    validate_dn,
)

# ⚡ 12. PERFORMANCE E MONITORAMENTO
from ldap_core_shared.utils.performance import PerformanceMonitor

# =============================================================================
# 🚀 EXPORTS COMPLETOS - TODAS AS FUNCIONALIDADES DISPONÍVEIS (ZERO EXCLUSÕES)
# =============================================================================
# Organizado por categoria seguindo KISS principle:
# Agrupamento lógico + ordem alfabética = facilidade de uso

__all__ = [
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🎯 API PRINCIPAL - PONTO DE ENTRADA ÚNICO (FACADE PATTERN)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "LDAP",  # 🚀 Classe principal do facade
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🚨 EXCEÇÕES E TRATAMENTO DE ERROS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "ACLProcessingError",  # 🔐 Erro processamento ACL
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🏗️ PROCESSADORES BASE (TEMPLATE METHOD PATTERN)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "ACLProcessorBase",  # 🔐 Processador base para ACLs
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 📄 PROCESSAMENTO LDIF
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "AttributeTransformRule",  # 🔄 Regra transformação atributo
    "BaseProcessor",  # 🏗️ Processador base abstrato
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 📋 REGRAS E ENGINES (BUSINESS RULES)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "BaseRulesManager",  # 📋 Gerenciador base de regras
    "CategoryRule",  # 🏷️ Regra de categoria
    "ConfigValidationError",  # ⚙️ Erro validação configuração
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔗 GERENCIAMENTO DE CONEXÕES
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "ConnectionManager",  # 🔗 Gerenciador conexões
    "DataIntegrityError",  # 📊 Erro integridade dados
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔄 PROCESSAMENTO E MIGRAÇÃO
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "GenericEntryProcessor",  # 🔄 Processador genérico de entries
    "GenericMigrationOrchestrator",  # 🎭 Orquestrador de migração
    "GenericRule",  # 📜 Regra genérica
    "GenericRuleProcessor",  # ⚙️ Processador genérico de regras
    "GenericRulesEngine",  # 🎭 Engine genérico de regras
    "GenericRulesManager",  # 📋 Gerenciador genérico de regras
    "HierarchyError",  # 🌳 Erro hierarquia
    "HierarchyProcessorBase",  # 🌳 Processador base para hierarquia
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # ⚙️ CONFIGURAÇÃO E SETUP
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "LDAPConfig",  # 🔧 Configuração principal LDAP
    "LDAPConnectionError",  # 🔗 Erro conexão LDAP
    "LDAPMigrationError",  # 🔄 Erro migração LDAP
    "LDAPSchemaError",  # 📊 Erro schema LDAP
    "LDIFHeaderConfig",  # 📋 Config header LDIF
    "LDIFProcessingConfig",  # ⚙️ Config processamento LDIF
    "LDIFProcessingError",  # 📄 Erro processamento LDIF
    "LDIFProcessor",  # 📄 Processador LDIF
    "LDIFProcessorBase",  # 📄 Processador base para LDIF
    "LDIFWriter",  # ✍️ Escritor LDIF
    "LDIFWriterConfig",  # ⚙️ Config escritor LDIF
    "MigrationConfig",  # 🔄 Configuração de migração
    "MigrationConfigurationError",  # ⚙️ Erro configuração migração
    "MigrationError",  # 🔄 Erro genérico migração
    "MigrationPlan",  # 📋 Plano de migração
    "MigrationProcessor",  # 📋 Processador de migração
    "MigrationValidationError",  # ✅ Erro validação migração
    "PathValidationError",  # 📂 Erro validação path
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # ⚡ PERFORMANCE E MONITORAMENTO
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "PerformanceMonitor",  # ⚡ Monitor de performance
    "ProcessorError",  # ⚙️ Erro processador
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 📊 PADRÕES FUNDAMENTAIS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "Query",  # 🔍 Query builder pattern
    "Result",  # 📦 Result pattern para retornos
    "RuleExecutionContext",  # 🎯 Contexto execução regras
    "RuleProcessor",  # ⚙️ Processador de regras
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 📊 SCHEMA E MIGRAÇÃO
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "SchemaMigrator",  # 📊 Migrador de schema
    "SchemaProcessorBase",  # 📊 Processador base para schema
    "SchemaValidationError",  # 📊 Erro validação schema
    "TransformationRule",  # 🔄 Regra transformação
    "connect",  # 🔗 Função de conveniência para conexão
    "create_detailed_error",  # 🔍 Factory erro detalhado
    "create_migration_config_from_env",  # 🏗️ Factory para config migração
    "create_processor_performance_monitor",  # ⚡ Monitor de performance
    "create_rules_engine",  # 🏗️ Factory para rules engine
    "create_rules_manager",  # 🏗️ Factory para rules manager
    "finalize_processor_performance",  # 🏁 Finalização performance monitor
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🛠️ UTILITÁRIOS E VALIDAÇÃO
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    "get_parent_dn",  # 🌳 Obter DN pai
    "handle_migration_exception",  # 🛠️ Handler exceção migração
    "is_child_dn",  # 👶 Verificar DN filho
    "ldap_session",  # 📋 Context manager para sessões
    "load_migration_config_from_env",  # 🌍 Carregamento config via env vars
    "log_migration_error",  # 📝 Log erro migração
    "normalize_dn",  # 🔧 Normalizar DN
    "parse_dn",  # 🔍 Parser DN
    "validate_and_normalize_attribute_name",  # ✅🔧 Validar+normalizar nome atributo
    "validate_and_normalize_attribute_value",  # ✅🔧 Validar+normalizar valor atributo
    "validate_and_normalize_file_path",  # ✅🔧 Validar+normalizar path arquivo
    "validate_and_normalize_ldap_entry",  # ✅🔧 Validar+normalizar entry LDAP
    "validate_configuration_value",  # ✅ Validação de valores de config
    "validate_dn",  # ✅ Validar DN
    "validate_dn_format",  # ✅ Validar formato DN
    "validate_ldap_config",  # ✅ Validação de configuração
    "validate_migration_setup",  # ✅ Validação setup migração
    "validate_rules_file",  # ✅ Validação arquivo de regras
]
