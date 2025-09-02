"""Enterprise LDAP directory integration library."""

import importlib.metadata

from .api import FlextLDAPApi
from .value_objects import FlextLDAPScope
from .constants import (
    FlextLDAPProtocolConstants,
    FlextLDAPConnectionConstants,
    FlextLDAPAttributeConstants,
    FlextLDAPConstants,
    FlextLDAPValidationMessages,
    FlextLDAPOperationMessages,
    FlextLDAPValidationConstants,
    FlextLDAPObjectClassConstants,
    FlextLDAPScopeConstants,
)
from .connection_config import FlextLDAPConnectionConfig

# Import from new configuration modules
from .configuration import (
    FlextLDAPAuthConfig,
    FlextLDAPLoggingConfig,
    FlextLDAPSearchConfig,
)
from .settings import (
    FlextLDAPSettings,
)

# Import field definitions
from .fields import FlextLDAPScopeEnum

# Import from reorganized modules
from .entities import (
    FlextLDAPCreateUserRequest,
    FlextLDAPEntry,
    FlextLDAPGroup,
    FlextLDAPUser,
    FlextLDAPSearchRequest,
    FlextLDAPSearchResponse,
)
from .value_objects import (
    FlextLDAPDistinguishedName,
    FlextLDAPFilter,
)

from .services import FlextLDAPService

from .clients import FlextLDAPClient

from .container import FlextLDAPContainer

# Import missing exports that tests need
from .clients import SCOPE_MAP
from .domain import (
    FlextLDAPEntityParameterBuilder,
    FlextLDAPActiveUserSpecification,
    FlextLDAPCompleteUserSpecification,
    FlextLDAPDistinguishedNameSpecification,
    FlextLDAPDomainFactory,
    FlextLDAPDomainSpecification,
    FlextLDAPEmailSpecification,
    FlextLDAPGroupManagementService,
    FlextLDAPGroupSpecification,
    FlextLDAPPasswordService,
    FlextLDAPPasswordSpecification,
    FlextLDAPUserManagementService,
    FlextLDAPUserSpecification,
    FlextLDAPGroupEntityBuilder,
    FlextLDAPUserEntityBuilder,
)

from .exceptions import (
    FlextLDAPError,
    FlextLDAPExceptionFactory,
    FlextLDAPUserError,
    FlextLDAPConfigurationError,
    FlextLDAPConnectionError,
)

from .utilities import FlextLDAPUtilities
from .typings import LdapAttributeDict
from .type_guards import FlextLDAPTypeGuards

from .configuration import FlextLDAPAuthConfig as FlextLDAPConfig

# Version info
try:
    __version__ = importlib.metadata.version("flext-ldap")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.9.0"

__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())

# Public API
__all__: list[str] = [
    # Core API
    "FlextLDAPApi",
    # Configuration
    "FlextLDAPConnectionConfig",
    "FlextLDAPSettings",
    "FlextLDAPAuthConfig",
    "FlextLDAPConfig",
    # Domain Models
    "FlextLDAPEntry",
    "FlextLDAPUser",
    "FlextLDAPGroup",
    "FlextLDAPCreateUserRequest",
    "FlextLDAPSearchRequest",
    "FlextLDAPSearchResponse",
    "FlextLDAPDistinguishedName",
    "FlextLDAPScope",
    # Constants (selective export)
    "FlextLDAPProtocolConstants",
    "FlextLDAPConnectionConstants",
    "FlextLDAPAttributeConstants",
    "FlextLDAPObjectClassConstants",
    "FlextLDAPConstants",
    "FlextLDAPValidationMessages",
    "FlextLDAPOperationMessages",
    "FlextLDAPValidationConstants",
    "FlextLDAPObjectClassConstants",
    "FlextLDAPScopeConstants",
    "FlextLDAPScopeEnum",
    "FlextLDAPLoggingConfig",
    "FlextLDAPSearchConfig",
    "FlextLDAPFilter",
    # Services
    "FlextLDAPService",
    # Infrastructure
    "FlextLDAPClient",
    # Container
    "FlextLDAPContainer",
    # Exceptions
    "FlextLDAPError",
    "FlextLDAPExceptionFactory",
    "FlextLDAPUserError",
    "FlextLDAPConfigurationError",
    "FlextLDAPConnectionError",
    # Exports that tests need
    "SCOPE_MAP",
    "FlextLDAPEntityParameterBuilder",
    "FlextLDAPActiveUserSpecification",
    "FlextLDAPCompleteUserSpecification",
    "FlextLDAPDistinguishedNameSpecification",
    "FlextLDAPDomainFactory",
    "FlextLDAPDomainSpecification",
    "FlextLDAPEmailSpecification",
    "FlextLDAPGroupManagementService",
    "FlextLDAPGroupSpecification",
    "FlextLDAPPasswordService",
    "FlextLDAPPasswordSpecification",
    "FlextLDAPUserManagementService",
    "FlextLDAPUserSpecification",
    "FlextLDAPGroupEntityBuilder",
    "FlextLDAPUserEntityBuilder",
    # Utilities and Type Guards
    "FlextLDAPUtilities",
    "FlextLDAPTypeGuards",
    "LdapAttributeDict",
    # Metadata
    "__version__",
    "__version_info__",
]

# Testing convenience exposed scope
# FlextLDAPScope is imported directly from value_objects.py above
