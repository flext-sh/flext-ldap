"""Enterprise LDAP directory integration library."""


import importlib.metadata

from .api import FlextLdapApi, get_ldap_api, create_ldap_api
from .value_objects import FlextLdapScope
from .constants import (
    FlextLdapProtocolConstants,
    FlextLdapConnectionConstants,
    FlextLdapAttributeConstants,
    FlextLdapConstants,
    FlextLdapValidationMessages,
    FlextLdapOperationMessages,
    FlextLdapValidationConstants,
    FlextLdapObjectClassConstants,
    FlextLdapScopeConstants,
)
from .connection_config import FlextLdapConnectionConfig

# Import from new configuration modules
from .configuration import (
    FlextLdapAuthConfig,
    FlextLdapLoggingConfig,
    FlextLdapSearchConfig,
)
from .settings import (
    FlextLdapSettings,
    create_development_config,
    create_production_config,
    create_test_config,
)

# Import field definitions
from .fields import FlextLdapScopeEnum

# Import from reorganized modules
from .entities import (
    FlextLdapCreateUserRequest,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapUser,
    FlextLdapSearchRequest,
    FlextLdapSearchResponse,
)
from .value_objects import (
    FlextLdapDistinguishedName,
    FlextLdapFilter,
)

from .services import FlextLdapService

from .infrastructure import FlextLdapClient

from .container import get_ldap_container, reset_ldap_container

# Import missing exports that tests need
from .clients import SCOPE_MAP
from .domain import (
    FlextLdapEntityParameterBuilder,
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
    FlextLdapGroupEntityBuilder,
    FlextLdapUserEntityBuilder,
)

from .exceptions import (
    FlextLdapError,
    FlextLdapExceptionFactory,
    FlextLdapUserError,
    FlextLdapConfigurationError,
    FlextLdapConnectionError,
)

from .utils import (
    flext_ldap_validate_dn,
    flext_ldap_validate_attribute_name,
    flext_ldap_validate_attribute_value,
    flext_ldap_sanitize_attribute_name,
)
from .typings import LdapAttributeDict

from .config import FlextLdapAuthConfig as FlextLdapConfig

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
    "FlextLdapValidationMessages",
    "FlextLdapOperationMessages",
    "FlextLdapValidationConstants",
    "FlextLdapObjectClassConstants",
    "FlextLdapScopeConstants",
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
    "FlextLdapEntityParameterBuilder",
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
    "FlextLdapGroupEntityBuilder",
    "FlextLdapUserEntityBuilder",
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
# FlextLdapScope is imported directly from value_objects.py above
