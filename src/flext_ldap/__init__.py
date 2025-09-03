"""Enterprise LDAP directory integration library."""

import importlib.metadata

from flext_ldap.api import FlextLDAPApi
from flext_ldap.value_objects import FlextLDAPScope
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

# Import specific constants that tests need
from .constants import (
    FlextLDAPValidationConstants as _ValidationConstants,
)

MAX_PASSWORD_LENGTH = _ValidationConstants.MAX_PASSWORD_LENGTH
MIN_PASSWORD_LENGTH = _ValidationConstants.MIN_PASSWORD_LENGTH

# Import PASSWORD_PATTERN from appropriate location
import re

PASSWORD_PATTERN = re.compile(r"^(?=.*[a-zA-Z])(?=.*\d).{8,}$")
from flext_ldap.connection_config import FlextLDAPConnectionConfig

# Import from new configuration modules
from flext_ldap.configuration import (
    FlextLDAPAuthConfig,
    FlextLDAPLoggingConfig,
    FlextLDAPSearchConfig,
)
from flext_ldap.settings import (
    FlextLDAPSettings,
)

# Import field definitions
from flext_ldap.fields import FlextLDAPScopeEnum

# Import from reorganized modules
from flext_ldap.entities import (
    FlextLDAPCreateUserRequest,
    FlextLDAPEntry,
    FlextLDAPGroup,
    FlextLDAPUser,
    FlextLDAPSearchRequest,
    FlextLDAPSearchResponse,
)
from flext_ldap.value_objects import (
    FlextLDAPDistinguishedName,
    FlextLDAPFilter,
)

from flext_ldap.services import (
    FlextLDAPService,
    FlextLDAPServices,
    FlextLDAPUserService,
    FlextLDAPGroupService,
)

from flext_ldap.clients import FlextLDAPClient

from flext_ldap.container import FlextLDAPContainer

# Import missing exports that tests need
from flext_ldap.clients import SCOPE_MAP
from flext_ldap.domain import (
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

from flext_ldap.exceptions import (
    FlextLDAPError,
    FlextLDAPExceptionFactory,
    FlextLDAPUserError,
    FlextLDAPConfigurationError,
    FlextLDAPConnectionError,
    FlextLDAPAuthenticationError,
    FlextLDAPOperationError,
    FlextLDAPSearchError,
    FlextLDAPTypeError,
    FlextLDAPValidationError,
)

from flext_ldap.utilities import FlextLDAPUtilities
from flext_ldap.typings import LdapAttributeDict
from flext_ldap.type_guards import FlextLDAPTypeGuards

from flext_ldap.configuration import FlextLDAPAuthConfig as FlextLDAPConfig

# Import adapters
from flext_ldap.adapters import FlextLDAPAdapters

# Import operations
from flext_ldap.operations import (
    FlextLDAPOperations,
    FlextLDAPOperationsService,
    FlextLDAPConnectionOperations,
    FlextLDAPSearchOperations,
    FlextLDAPEntryOperations,
    FlextLDAPUserOperations,
    FlextLDAPGroupOperations,
)

# Import repositories
from flext_ldap.repositories import (
    FlextLDAPRepositories,
    FlextLDAPRepository,
    FlextLDAPUserRepository,
    FlextLDAPGroupRepository,
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
    "FlextLDAPServices",
    "FlextLDAPUserService",
    "FlextLDAPGroupService",
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
    "FlextLDAPAuthenticationError",
    "FlextLDAPOperationError",
    "FlextLDAPSearchError",
    "FlextLDAPTypeError",
    "FlextLDAPValidationError",
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
    # Adapters
    "FlextLDAPAdapters",
    # Operations
    "FlextLDAPOperations",
    "FlextLDAPOperationsService",
    "FlextLDAPConnectionOperations",
    "FlextLDAPSearchOperations",
    "FlextLDAPEntryOperations",
    "FlextLDAPUserOperations",
    "FlextLDAPGroupOperations",
    # Repositories
    "FlextLDAPRepositories",
    "FlextLDAPRepository",
    "FlextLDAPUserRepository",
    "FlextLDAPGroupRepository",
    # Constants for tests
    "MAX_PASSWORD_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "PASSWORD_PATTERN",
    # Metadata
    "__version__",
    "__version_info__",
]

# Testing convenience exposed scope
# FlextLDAPScope is imported directly from value_objects.py above
