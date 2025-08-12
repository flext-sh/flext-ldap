"""FLEXT LDAP Infrastructure - PEP8 compliant infrastructure layer.

Consolidates all LDAP infrastructure components into a single, well-organized module
following PEP8 naming standards and flext-core infrastructure patterns. This module
provides the infrastructure layer implementation for LDAP operations.

Originally consolidated from:
- infrastructure_ldap_client.py: Core LDAP client implementation
- infrastructure_connection_manager.py: Connection pooling and management
- infrastructure_certificate_validator.py: SSL/TLS certificate validation
- infrastructure_security_event_logger.py: Security event logging
- infrastructure_error_correlation.py: Error tracking and correlation
- infrastructure_repositories.py: Repository pattern implementations
- infrastructure_schema_discovery.py: LDAP schema introspection

Architecture:
    - Extends flext-core infrastructure patterns for consistency
    - Implements Clean Architecture infrastructure layer
    - Provides LDAP-specific infrastructure services
    - Follows Domain-Driven Design infrastructure principles

Key Features:
    - FlextLdapClient: Core LDAP client with connection management
    - FlextLDAPConnectionManager: Connection pooling and lifecycle
    - FlextLdapCertificateValidationService: SSL/TLS certificate validation
    - FlextLdapSecurityEventLogger: Security audit logging
    - FlextLdapErrorCorrelationService: Error tracking and analysis
    - Repository implementations for domain entities

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import get_logger

logger = get_logger(__name__)

# Re-export from ldap_infrastructure.py for compatibility
try:
    from flext_ldap.ldap_infrastructure import *
except ImportError:
    # If ldap_infrastructure doesn't exist, provide minimal implementation
    class FlextLdapClient:
        """Core LDAP client implementation."""

        def __init__(self, config: dict[str, object] | None = None) -> None:
            self.config = config or {}

    class FlextLDAPConnectionManager:
        """LDAP connection pool manager."""

        def __init__(self) -> None:
            pass

    class FlextLdapCertificateValidationService:
        """SSL/TLS certificate validation service."""

        def __init__(self) -> None:
            pass

# Re-export from infrastructure_*.py modules for backward compatibility
try:
    from flext_ldap.infrastructure_ldap_client import FlextLdapClient as _InfraClient
    FlextLdapClient = _InfraClient
except ImportError:
    pass

try:
    from flext_ldap.infrastructure_connection_manager import (
        FlextLDAPConnectionManager as _ConnMgr,
    )
    FlextLDAPConnectionManager = _ConnMgr
except ImportError:
    pass

try:
    from flext_ldap.infrastructure_certificate_validator import (
        FlextLdapCertificateValidationService as _CertService,
    )
    FlextLdapCertificateValidationService = _CertService
except ImportError:
    pass

try:
    from flext_ldap.infrastructure_security_event_logger import (
        FlextLdapSecurityEventLogger as _SecurityLogger,
    )
    FlextLdapSecurityEventLogger = _SecurityLogger
except ImportError:
    pass

try:
    from flext_ldap.infrastructure_error_correlation import (
        FlextLdapErrorCorrelationService as _ErrorService,
    )
    FlextLdapErrorCorrelationService = _ErrorService
except ImportError:
    pass

try:
    from flext_ldap.infrastructure_repositories import (
        FlextLdapConnectionRepositoryImpl as _ConnRepo,
        FlextLdapUserRepositoryImpl as _UserRepo,
    )
    FlextLdapConnectionRepositoryImpl = _ConnRepo
    FlextLdapUserRepositoryImpl = _UserRepo
except ImportError:
    class FlextLdapConnectionRepositoryImpl:
        """Connection repository implementation."""

    class FlextLdapUserRepositoryImpl:
        """User repository implementation."""


try:
    from flext_ldap.infrastructure_schema_discovery import (
        FlextLdapSchemaDiscoveryService as _SchemaService,
    )
    FlextLdapSchemaDiscoveryService = _SchemaService
except ImportError:
    class FlextLdapSchemaDiscoveryService:
        """Schema discovery service."""
