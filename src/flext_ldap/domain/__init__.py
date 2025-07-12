"""LDAP Domain Layer - Business Logic and Entities.

Version 0.7.0 - Clean Architecture
NO LEGACY CODE - Only clean implementations.
"""

from flext_core import DomainEntity, DomainValueObject, InMemoryRepository

from flext_ldap.domain.entities import (LDAPConnection, LDAPGroup, LDAPOperation,
                                        LDAPUser)
from flext_ldap.domain.exceptions import (LDAPConnectionError, LDAPDomainError,
                                          LDAPDuplicateError, LDAPEntityError,
                                          LDAPGroupError, LDAPNotFoundError,
                                          LDAPOperationError, LDAPServiceError,
                                          LDAPUserError, LDAPValidationError)
from flext_ldap.domain.repositories import LDAPConnectionRepository, LDAPUserRepository
from flext_ldap.domain.value_objects import DistinguishedName, LDAPAttribute

__all__ = [
    "DistinguishedName",
    "DomainEntity",
    "DomainValueObject",
    "InMemoryRepository",
    "LDAPAttribute",
    "LDAPConnection",
    "LDAPConnectionError",
    "LDAPConnectionRepository",
    "LDAPDomainError",
    "LDAPDuplicateError",
    "LDAPEntityError",
    "LDAPGroup",
    "LDAPGroupError",
    "LDAPNotFoundError",
    "LDAPOperation",
    "LDAPOperationError",
    "LDAPServiceError",
    "LDAPUser",
    "LDAPUserError",
    "LDAPUserRepository",
    "LDAPValidationError",
]
