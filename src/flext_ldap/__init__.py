"""FLEXT LDAP - Enterprise LDAP Directory Integration Library for FLEXT ecosystem.

This library provides comprehensive LDAP directory integration for the FLEXT ecosystem,
implementing enterprise-grade LDAP operations with Clean Architecture principles and
Domain-Driven Design patterns. Built on flext-core foundation for consistent error
handling and service management.

The library consolidates LDAP operations under SOLID design patterns with modern
async/await support, comprehensive error handling via FlextResult, and strong typing
for reliable directory service integration.

Architecture (Clean Architecture + DDD):
    - Application Layer: FlextLdapApi (primary interface) and FlextLdapService
    - Domain Layer: LDAP entities, value objects, and business rules
    - Infrastructure Layer: LDAP protocol implementation and connection management
    - Foundation Layer: FLEXT Core integration for error handling and configuration

Key Features:
    - Async LDAP Operations: Modern async/await support for non-blocking operations
    - Enterprise Security: SSL/TLS, SASL authentication, and credential management
    - Schema Discovery: Automatic LDAP schema introspection and validation
    - Connection Pooling: Efficient connection management with failover support
    - Type Safety: Strong typing with Pydantic models for all LDAP operations
    - Error Handling: FlextResult pattern for consistent error management
    - Migration Support: Tools for LDAP data migration and synchronization

Domain Entities:
    - FlextLdapUser: User account management with attributes and group membership
    - FlextLdapGroup: Group management with member operations
    - FlextLdapEntry: Generic LDAP entry operations for any object class
    - FlextLdapOrganizationalUnit: Organizational unit management

Value Objects:
    - FlextLdapDistinguishedName: Type-safe DN handling with validation
    - FlextLdapCreateUserRequest: User creation with validation
    - FlextLdapConnectionConfig: Connection configuration with security settings

Example:
    Modern LDAP operations with async/await pattern:

    >>> from flext_ldap import FlextLdapApi, FlextLdapCreateUserRequest
    >>> from flext_core import FlextResult
    >>>
    >>> # Initialize API with configuration
    >>> api = FlextLdapApi()
    >>>
    >>> # Async context manager for connection handling
    >>> async with api.connection(
    ...     server_url="ldaps://ldap.example.com:636",
    ...     bind_dn="cn=admin,dc=example,dc=com",
    ...     password="secure_password"
    ... ) as session:
    ...     # Type-safe user creation
    ...     user_request = FlextLdapCreateUserRequest(
    ...         dn="uid=john,ou=users,dc=example,dc=com",
    ...         uid="john",
    ...         cn="John Doe",
    ...         sn="Doe",
    ...         mail="john@example.com"
    ...     )
    ...     result = await api.create_user(session, user_request)
    ...     if result.is_success:
    ...         print(f"User created: {result.data.dn}")
    ...     else:
    ...         print(f"Creation failed: {result.error}")

    Search operations with filters:

    >>> # Search for users with FlextResult error handling
    >>> search_result = await api.search_users(
    ...     session,
    ...     base_dn="ou=users,dc=example,dc=com",
    ...     filter_expr="(mail=*@example.com)"
    ... )
    >>> if search_result.is_success:
    ...     users = search_result.data
    ...     print(f"Found {len(users)} users")

FLEXT-Core Integration:
    Built on flext-core foundation with FlextResult pattern, FlextEntity base classes,
    FlextContainer dependency injection, and centralized configuration management
    following enterprise standards and Clean Architecture principles.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import warnings

# ✅ FLEXT-CORE FOUNDATION
from flext_core import FlextLDAPConfig

# ✅ PRIMARY PUBLIC API - PRODUCTION GRADE
from flext_ldap.ldap_api import FlextLdapApi, get_ldap_api
# Backward-compat application namespace for tests importing flext_ldap.application.ldap_service
from flext_ldap.ldap_services import (
    FlextLdapApplicationService as _FlextLdapServiceImpl,
)
import sys as _sys
import types as _types
application = _types.ModuleType("flext_ldap.application")
application.ldap_service = _types.ModuleType("flext_ldap.application.ldap_service")  # type: ignore[attr-defined]
application.ldap_service.FlextLdapService = _FlextLdapServiceImpl
_sys.modules["flext_ldap.application"] = application
_sys.modules["flext_ldap.application.ldap_service"] = application.ldap_service
from flext_ldap.ldap_services import FlextLdapService

# ✅ CONFIGURATION - ENTERPRISE PATTERNS
from flext_ldap.ldap_config import FlextLdapConnectionConfig, FlextLdapSettings

# ✅ DOMAIN ENTITIES - RICH BUSINESS OBJECTS
from flext_ldap.ldap_models import FlextLdapEntry, FlextLdapGroup, FlextLdapUser

# ✅ INFRASTRUCTURE - FOR ADVANCED USAGE
from flext_ldap.ldap_infrastructure import FlextLdapClient
# Legacy import path compatibility for tests expecting flext_ldap.infrastructure.ldap_client
import types as _types
infrastructure = _types.ModuleType("flext_ldap.infrastructure")
infrastructure.__doc__ = (
    "FLEXT-LDAP Infrastructure Namespace.\n\n"
    "This namespace exposes infrastructure primitives and adapters used by\n"
    "FLEXT-LDAP, including connection manager, repositories, certificate\n"
    "validation and schema discovery services.\n\n"
    "Copyright (c) 2025 FLEXT Team. All rights reserved.\n"
    "SPDX-License-Identifier: MIT\n"
)
infrastructure.ldap_client = _types.ModuleType("flext_ldap.infrastructure.ldap_client")  # type: ignore[attr-defined]
infrastructure.ldap_client.FlextLdapClient = FlextLdapClient
import sys as _sys
_sys.modules["flext_ldap.infrastructure"] = infrastructure
_sys.modules["flext_ldap.infrastructure.ldap_client"] = infrastructure.ldap_client
from flext_ldap.ldap_infrastructure import (
    FlextLdapCertificateValidationService as _FlextLdapCertificateValidationService,
)
infrastructure.certificate_validator = _types.ModuleType(  # type: ignore[attr-defined]
    "flext_ldap.infrastructure.certificate_validator",
)
infrastructure.certificate_validator.FlextLdapCertificateValidationService = _FlextLdapCertificateValidationService
_sys.modules["flext_ldap.infrastructure.certificate_validator"] = (
    infrastructure.certificate_validator
)
from flext_ldap.ldap_infrastructure import (
    FlextLdapSecurityEventLogger as _FlextLdapSecurityEventLogger,
)
# Legacy compatibility - these classes were moved
_FlextLdapSecurityEvent: type | None = None
_FlextLdapSecurityEventData: type | None = None
_FlextLdapSecurityEventSeverity: type | None = None
_FlextLdapSecurityEventStatus: type | None = None
_FlextLdapSecurityEventType: type | None = None
infrastructure.security_event_logger = _types.ModuleType(  # type: ignore[attr-defined]
    "flext_ldap.infrastructure.security_event_logger",
)
infrastructure.security_event_logger.FlextLdapSecurityEventLogger = _FlextLdapSecurityEventLogger
infrastructure.security_event_logger.FlextLdapSecurityEvent = _FlextLdapSecurityEvent
infrastructure.security_event_logger.FlextLdapSecurityEventData = _FlextLdapSecurityEventData
infrastructure.security_event_logger.FlextLdapSecurityEventSeverity = _FlextLdapSecurityEventSeverity
infrastructure.security_event_logger.FlextLdapSecurityEventStatus = _FlextLdapSecurityEventStatus
infrastructure.security_event_logger.FlextLdapSecurityEventType = _FlextLdapSecurityEventType
_sys.modules["flext_ldap.infrastructure.security_event_logger"] = (
    infrastructure.security_event_logger
)
from flext_ldap.ldap_infrastructure import (
    FlextLDAPConnectionManager as _FlextLDAPConnectionManager,
)
infrastructure.connection_manager = _types.ModuleType(  # type: ignore[attr-defined]
    "flext_ldap.infrastructure.connection_manager",
)
infrastructure.connection_manager.FlextLDAPConnectionManager = _FlextLDAPConnectionManager
# Also expose configuration class for tests patching into this module
from flext_ldap.ldap_config import FlextLdapConnectionConfig as _ALConnCfg
infrastructure.connection_manager.FlextLdapConnectionConfig = _ALConnCfg
infrastructure.connection_manager.FlextLdapClient = FlextLdapClient
_sys.modules["flext_ldap.infrastructure.connection_manager"] = (
    infrastructure.connection_manager
)
from flext_ldap.ldap_infrastructure import (
    FlextLdapErrorCorrelationService as _FlextLdapErrorCorrelationService,
)
# Legacy compatibility - these classes were moved
_FlextLdapErrorEvent: type | None = None
_FlextLdapErrorEventData: type | None = None
_FlextLdapErrorPattern: type | None = None
_FlextLdapErrorPatternData: type | None = None
_FlextLdapErrorCategory: type | None = None
_FlextLdapErrorSeverity: type | None = None
infrastructure.error_correlation = _types.ModuleType(  # type: ignore[attr-defined]
    "flext_ldap.infrastructure.error_correlation",
)
infrastructure.error_correlation.FlextLdapErrorCorrelationService = _FlextLdapErrorCorrelationService
infrastructure.error_correlation.FlextLdapErrorEvent = _FlextLdapErrorEvent
infrastructure.error_correlation.FlextLdapErrorEventData = _FlextLdapErrorEventData
infrastructure.error_correlation.FlextLdapErrorPattern = _FlextLdapErrorPattern
infrastructure.error_correlation.FlextLdapErrorPatternData = _FlextLdapErrorPatternData
infrastructure.error_correlation.FlextLdapErrorCategory = _FlextLdapErrorCategory
infrastructure.error_correlation.FlextLdapErrorSeverity = _FlextLdapErrorSeverity
_sys.modules["flext_ldap.infrastructure.error_correlation"] = (
    infrastructure.error_correlation
)
from flext_ldap.ldap_infrastructure import (
    FlextLdapConnectionRepositoryImpl as _FlextLdapConnectionRepositoryImpl,
    FlextLdapUserRepositoryImpl as _FlextLdapUserRepositoryImpl,
)
infrastructure.repositories = _types.ModuleType(  # type: ignore[attr-defined]
    "flext_ldap.infrastructure.repositories",
)
infrastructure.repositories.FlextLdapConnectionRepositoryImpl = _FlextLdapConnectionRepositoryImpl
infrastructure.repositories.FlextLdapUserRepositoryImpl = _FlextLdapUserRepositoryImpl
_sys.modules["flext_ldap.infrastructure.repositories"] = infrastructure.repositories
from flext_ldap.ldap_infrastructure import (
    FlextLdapSchemaDiscoveryService as _FlextLdapSchemaDiscoveryService,
)
# Legacy compatibility - these classes were moved
_FlextLdapAttributeUsage: type | None = None
_FlextLdapObjectClassType: type | None = None
_FlextLdapSchemaAttribute: type | None = None
_FlextLdapSchemaAttributeData: type | None = None
_FlextLdapSchemaElementType: type | None = None
_FlextLdapSchemaObjectClass: type | None = None
_FlextLdapSchemaObjectClassData: type | None = None
_ValidationResult: type | None = None
infrastructure.schema_discovery = _types.ModuleType(  # type: ignore[attr-defined]
    "flext_ldap.infrastructure.schema_discovery",
)
infrastructure.schema_discovery.FlextLdapSchemaDiscoveryService = _FlextLdapSchemaDiscoveryService
infrastructure.schema_discovery.FlextLdapAttributeUsage = _FlextLdapAttributeUsage
infrastructure.schema_discovery.FlextLdapObjectClassType = _FlextLdapObjectClassType
infrastructure.schema_discovery.FlextLdapSchemaAttribute = _FlextLdapSchemaAttribute
infrastructure.schema_discovery.FlextLdapSchemaAttributeData = _FlextLdapSchemaAttributeData
infrastructure.schema_discovery.FlextLdapSchemaElementType = _FlextLdapSchemaElementType
infrastructure.schema_discovery.FlextLdapSchemaObjectClass = _FlextLdapSchemaObjectClass
infrastructure.schema_discovery.FlextLdapSchemaObjectClassData = _FlextLdapSchemaObjectClassData
infrastructure.schema_discovery.ValidationResult = _ValidationResult
_sys.modules["flext_ldap.infrastructure.schema_discovery"] = (
    infrastructure.schema_discovery
)

# ✅ VALIDATION UTILITIES - PUBLIC API
from flext_ldap.ldap_utils import (
    flext_ldap_sanitize_attribute_name,
    flext_ldap_validate_attribute_name,
    flext_ldap_validate_attribute_value,
    flext_ldap_validate_dn,
)

# ✅ VALUE OBJECTS - IMMUTABLE DATA STRUCTURES
from flext_ldap.ldap_models import (
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
)

# Legacy compatibility aliases
FlextLdapExtendedEntry = FlextLdapEntry
FlextLdapFilterValue = str  # Simple string for now
FlextLdapScopeEnum = str  # Simple string for now


# ✅ LEGACY CONSTANTS - TEST COMPATIBILITY
# Legacy compatibility - constants were consolidated
class FlextLdapConstants:
    """Legacy constants class for backward compatibility."""

    DEFAULT_PORT = 389
    DEFAULT_SSL_PORT = 636


# Backward-compat domain namespace for tests importing flext_ldap.domain.ports
domain = _types.ModuleType("flext_ldap.domain")
domain.ports = _types.ModuleType("flext_ldap.domain.ports")  # type: ignore[attr-defined]
domain.ports.__doc__ = (
    "FLEXT-LDAP Domain Ports.\n\n"
    "Backwards-compat service interfaces for Clean Architecture domain layer.\n\n"
    "Copyright (c) 2025 FLEXT Team. All rights reserved.\n"
    "SPDX-License-Identifier: MIT\n"
)
domain.specifications = _types.ModuleType("flext_ldap.domain.specifications")  # type: ignore[attr-defined]
domain.interfaces = _types.ModuleType("flext_ldap.domain.interfaces")  # type: ignore[attr-defined]
domain.repositories = _types.ModuleType("flext_ldap.domain.repositories")  # type: ignore[attr-defined]
domain.models = _types.ModuleType("flext_ldap.domain.models")  # type: ignore[attr-defined]
domain.events = _types.ModuleType("flext_ldap.domain.events")  # type: ignore[attr-defined]
domain.security = _types.ModuleType("flext_ldap.domain.security")  # type: ignore[attr-defined]
domain.exceptions = _types.ModuleType("flext_ldap.domain.exceptions")  # type: ignore[attr-defined]
_sys.modules["flext_ldap.domain"] = domain
_sys.modules["flext_ldap.domain.ports"] = domain.ports
_sys.modules["flext_ldap.domain.specifications"] = domain.specifications
_sys.modules["flext_ldap.domain.interfaces"] = domain.interfaces
_sys.modules["flext_ldap.domain.repositories"] = domain.repositories
_sys.modules["flext_ldap.domain.models"] = domain.models
_sys.modules["flext_ldap.domain.events"] = domain.events
_sys.modules["flext_ldap.domain.security"] = domain.security
_sys.modules["flext_ldap.domain.exceptions"] = domain.exceptions
# Map domain security symbols
# Legacy compatibility - CertificateValidationContext was moved
_CertificateValidationContext: type | None = None
domain.security.CertificateValidationContext = _CertificateValidationContext
from flext_ldap.ldap_exceptions import (
    FlextLdapUserError as _FlextLdapUserError,
)
domain.exceptions.FlextLdapUserError = _FlextLdapUserError

# Map current domain implementations to legacy domain.* module attributes
from flext_ldap.ldap_domain import (
    FlextLdapActiveUserSpecification,
    FlextLdapDistinguishedNameSpecification,
    FlextLdapEntrySpecification,
    FlextLdapFilterSpecification,
    FlextLdapGroupSpecification,
    FlextLdapNonEmptyGroupSpecification,
    FlextLdapSpecification,
    FlextLdapUserSpecification,
    FlextLdapValidEntrySpecification,
    FlextLdapValidPasswordSpecification,
)
# Map legacy ports (service interfaces) to modern abstract/service classes
# Legacy compatibility - these services were consolidated
_ALGroup: type | None = None
_ALSearch: type | None = None
_ALMigration: type | None = None
_ALSchema: type | None = None
domain.ports.FlextLdapUserService = FlextLdapService
domain.ports.FlextLdapMigrationService = _ALMigration
domain.ports.FlextLdapSearchService = _ALSearch
domain.ports.FlextLdapSchemaService = _ALSchema
domain.ports.FlextLdapGroupService = _ALGroup
domain.specifications.FlextLdapActiveUserSpecification = FlextLdapActiveUserSpecification
domain.specifications.FlextLdapDistinguishedNameSpecification = FlextLdapDistinguishedNameSpecification
domain.specifications.FlextLdapEntrySpecification = FlextLdapEntrySpecification
domain.specifications.FlextLdapFilterSpecification = FlextLdapFilterSpecification
domain.specifications.FlextLdapGroupSpecification = FlextLdapGroupSpecification
domain.specifications.FlextLdapNonEmptyGroupSpecification = FlextLdapNonEmptyGroupSpecification
domain.specifications.FlextLdapSpecification = FlextLdapSpecification
domain.specifications.FlextLdapUserSpecification = FlextLdapUserSpecification
domain.specifications.FlextLdapValidEntrySpecification = FlextLdapValidEntrySpecification
domain.specifications.FlextLdapValidPasswordSpecification = FlextLdapValidPasswordSpecification

# Backward-compat adapters namespace for tests importing flext_ldap.adapters.directory_adapter
adapters = _types.ModuleType("flext_ldap.adapters")
adapters.directory_adapter = _types.ModuleType(  # type: ignore[attr-defined]
    "flext_ldap.adapters.directory_adapter",
)
from flext_ldap.ldap_services import (
    FlextLdapDirectoryAdapter as _FlextLdapDirectoryAdapter,
    FlextLdapDirectoryService as _FlextLdapDirectoryService,
    FlextLdapDirectoryAdapterInterface as _FlextLdapDirectoryAdapterInterface,
    FlextLdapDirectoryServiceInterface as _FlextLdapDirectoryServiceInterface,
    FlextLdapDirectoryConnectionProtocol as _FlextLdapDirectoryConnectionProtocol,
    FlextLdapDirectoryEntryProtocol as _FlextLdapDirectoryEntryProtocol,
)
adapters.directory_adapter.FlextLdapDirectoryAdapter = _FlextLdapDirectoryAdapter
adapters.directory_adapter.FlextLdapDirectoryService = _FlextLdapDirectoryService
adapters.directory_adapter.FlextLdapDirectoryAdapterInterface = _FlextLdapDirectoryAdapterInterface
adapters.directory_adapter.FlextLdapDirectoryServiceInterface = _FlextLdapDirectoryServiceInterface
adapters.directory_adapter.FlextLdapDirectoryConnectionProtocol = _FlextLdapDirectoryConnectionProtocol
adapters.directory_adapter.FlextLdapDirectoryEntryProtocol = _FlextLdapDirectoryEntryProtocol
_sys.modules["flext_ldap.adapters"] = adapters
_sys.modules["flext_ldap.adapters.directory_adapter"] = adapters.directory_adapter

# Some tests patch flext_ldap.adapters.directory_adapter.FlextResult
from flext_core import FlextResult as _FlextResult
adapters.directory_adapter.FlextResult = _FlextResult

# Backward-compat patterns module expected by tests
patterns = _types.ModuleType("flext_ldap.patterns")
patterns.__doc__ = (
    "FLEXT-LDAP Patterns Module.\n\n"
    "Provides pattern aliases and documentation for legacy tests.\n\n"
    "Deprecated patterns will be removed in version 1.0.0.\n"
    "Copyright (c) 2025 FLEXT Team. All rights reserved.\n"
    "SPDX-License-Identifier: MIT\n"
)
_sys.modules["flext_ldap.patterns"] = patterns

# ✅ BACKWARD COMPATIBILITY - SIMPLE ALIASES
LDAPEntry = FlextLdapExtendedEntry
LDAPFilter = FlextLdapFilterValue
LDAPScope = FlextLdapScopeEnum


def __getattr__(name: str) -> object:
    """Legacy import handler with deprecation warnings."""
    # API class aliases - all map to FlextLdapApi
    if name in {
        "FlextLdapClient",
        "LDAPClient",
        "SimpleAPI",
        "FlextLdapAPIClient",
        "LDAPService",
    }:
        warnings.warn(
            f"🚨 DEPRECATED API: {name} is deprecated.\n"
            f"✅ MODERN SOLUTION: Use FlextLdapApi instead\n"
            f"💡 Import: from flext_ldap import FlextLdapApi\n"
            f"📖 Migration will be required in v1.0.0",
            DeprecationWarning,
            stacklevel=2,
        )
        return FlextLdapApi

    # Entity aliases - point to modern classes
    entity_mappings = {
        "LDAPUser": FlextLdapUser,
        "LDAPGroup": FlextLdapGroup,
        "CreateUserRequest": FlextLdapCreateUserRequest,
        "FlextLdapFilter": FlextLdapFilterValue,
        "FlextLdapScope": FlextLdapScopeEnum,
    }

    if name in entity_mappings:
        warnings.warn(
            f"🚨 DEPRECATED IMPORT: {name} is deprecated.\n"
            f"✅ MODERN SOLUTION: Use full class name from flext_ldap\n"
            f"💡 Available classes: {list(entity_mappings.values())}\n"
            f"📖 Legacy imports will be removed in v1.0.0",
            DeprecationWarning,
            stacklevel=2,
        )
        return entity_mappings[name]

    msg = f"module 'flext_ldap' has no attribute '{name}'"
    raise AttributeError(msg)


# ✅ CLEAN PUBLIC API - PRODUCTION GRADE
__all__: list[str] = [
    "FlextLDAPConfig", "FlextLdapApi", "FlextLdapConstants", "FlextLdapConnectionConfig",
    "FlextLdapCreateUserRequest", "FlextLdapDistinguishedName", "FlextLdapEntry",
    "FlextLdapExtendedEntry", "FlextLdapFilterValue", "FlextLdapGroup", "FlextLdapScopeEnum",
    "FlextLdapService", "FlextLdapSettings", "FlextLdapClient", "FlextLdapUser", "LDAPEntry",
    "LDAPFilter", "LDAPScope", "flext_ldap_sanitize_attribute_name",
    "flext_ldap_validate_attribute_name", "flext_ldap_validate_attribute_value",
    "flext_ldap_validate_dn", "get_ldap_api", "annotations", "FlextLdapActiveUserSpecification",
    "FlextLdapDistinguishedNameSpecification", "FlextLdapEntrySpecification",
    "FlextLdapFilterSpecification", "FlextLdapGroupSpecification", "FlextLdapNonEmptyGroupSpecification",
    "FlextLdapSpecification", "FlextLdapUserSpecification", "FlextLdapValidEntrySpecification",
    "FlextLdapValidPasswordSpecification", "application", "infrastructure", "domain", "adapters",
    "patterns",
]
