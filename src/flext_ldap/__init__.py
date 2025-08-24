"""Enterprise LDAP directory integration library."""

from __future__ import annotations

import importlib.metadata

from flext_ldap.api import FlextLdapApi, get_ldap_api, create_ldap_api
from flext_ldap.constants import FlextLdapScope as _ConstantsLdapScope
from flext_ldap.constants import (
    FlextLdapProtocolConstants,
    FlextLdapConnectionConstants,
    FlextLdapAttributeConstants,
    FlextLdapObjectClassConstants,
    FlextLdapConstants,
)

# Import from new configuration module
from flext_ldap.configuration import (
    FlextLdapAuthConfig,
    FlextLdapConnectionConfig,
    FlextLdapLoggingConfig,
    FlextLdapSearchConfig,
    FlextLdapSettings,
    create_development_config,
    create_production_config,
    create_test_config,
)

# Import field definitions
from flext_ldap.fields import FlextLdapScopeEnum

# Import from reorganized modules
from flext_ldap.entities import (
    FlextLdapCreateUserRequest,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapUser,
    FlextLdapSearchRequest,
    FlextLdapSearchResponse,
)
from flext_ldap.value_objects import (
    FlextLdapDistinguishedName,
    FlextLdapFilter,
)

from flext_ldap.services import FlextLdapService

from flext_ldap.infrastructure import FlextLdapClient

from flext_ldap.container import get_ldap_container, reset_ldap_container

# Import missing exports that tests need
from flext_ldap.clients import SCOPE_MAP
from flext_ldap.domain import (
    EntityParameterBuilder,
    FlextLdapActiveUserSpecification,
    FlextLdapCompleteUserSpecification,
    FlextLdapDistinguishedNameSpecification,
    FlextLdapDomainFactory,
    FlextLdapDomainSpecification,
    FlextLdapEmailSpecification,
    FlextLdapGroupManagementService,
    FlextLdapGroupSpecification,
    FlextLdapPasswordService,
    FlextLdapPasswordSpecification,
    FlextLdapUserManagementService,
    FlextLdapUserSpecification,
    GroupEntityBuilder,
    UserEntityBuilder,
)

from flext_ldap.exceptions import (
    FlextLdapError,
    FlextLdapExceptionFactory,
    FlextLdapUserError,
    FlextLdapConfigurationError,
    FlextLdapConnectionError,
)

from flext_ldap.utils import (
    flext_ldap_validate_dn,
    flext_ldap_validate_attribute_name,
    flext_ldap_validate_attribute_value,
    flext_ldap_sanitize_attribute_name,
)
from flext_ldap.typings import LdapAttributeDict

from flext_ldap.config import FlextLdapAuthConfig as FlextLdapConfig
# CLI imports (testing if circular dependency is resolved)
from flext_ldap.cli import (
    FlextLdapCliCommandService,
    FlextLdapCliFormatterService,
    cli,
    get_command_service,
    get_formatter_service,
    main,
)

# Version info
try:
    __version__ = importlib.metadata.version("flext-ldap")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.9.0"

__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())

# Public API
__all__: list[str] = [
    # Core API
    "FlextLdapApi",
    "get_ldap_api",
    "create_ldap_api",
    # Configuration
    "FlextLdapConnectionConfig",
    "FlextLdapSettings",
    "FlextLdapAuthConfig",
    "FlextLdapConfig",
    # Domain Models
    "FlextLdapEntry",
    "FlextLdapUser",
    "FlextLdapGroup",
    "FlextLdapCreateUserRequest",
    "FlextLdapSearchRequest",
    "FlextLdapSearchResponse",
    "FlextLdapDistinguishedName",
    "FlextLdapScope",
    # Constants (selective export)
    "FlextLdapProtocolConstants",
    "FlextLdapConnectionConstants",
    "FlextLdapAttributeConstants",
    "FlextLdapObjectClassConstants",
    "FlextLdapConstants",
    "FlextLdapScopeEnum",
    "FlextLdapLoggingConfig",
    "FlextLdapSearchConfig",
    "create_development_config",
    "create_production_config",
    "create_test_config",
    "FlextLdapFilter",
    # Services
    "FlextLdapService",
    # Infrastructure
    "FlextLdapClient",
    # Container functions
    "get_ldap_container",
    "reset_ldap_container",
    # Exceptions
    "FlextLdapError",
    "FlextLdapExceptionFactory",
    "FlextLdapUserError",
    "FlextLdapConfigurationError",
    "FlextLdapConnectionError",
    # Missing exports that tests need
    "SCOPE_MAP",
    "EntityParameterBuilder",
    "FlextLdapActiveUserSpecification",
    "FlextLdapCompleteUserSpecification",
    "FlextLdapDistinguishedNameSpecification",
    "FlextLdapDomainFactory",
    "FlextLdapDomainSpecification",
    "FlextLdapEmailSpecification",
    "FlextLdapGroupManagementService",
    "FlextLdapGroupSpecification",
    "FlextLdapPasswordService",
    "FlextLdapPasswordSpecification",
    "FlextLdapUserManagementService",
    "FlextLdapUserSpecification",
    "GroupEntityBuilder",
    "UserEntityBuilder",
    # CLI exports (testing if circular dependency is resolved)
    "FlextLdapCliCommandService",
    "FlextLdapCliFormatterService",
    "cli",
    "get_command_service",
    "get_formatter_service",
    "main",
    # Utilities
    "flext_ldap_validate_dn",
    "flext_ldap_validate_attribute_name",
    "flext_ldap_validate_attribute_value",
    "flext_ldap_sanitize_attribute_name",
    "LdapAttributeDict",
    # Metadata
    "__version__",
    "__version_info__",
]

# Testing convenience exposed scope
FlextLdapScope = _ConstantsLdapScope
