"""LDAP type definitions for flext-ldap domain.

This module contains all type aliases and type definitions used throughout
the flext-ldap domain. Following FLEXT standards, all types are organized
under a single FlextLdapTypes class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations


class FlextLdapTypes:
    """Unified LDAP types class containing all type definitions for the domain.

    This class consolidates all LDAP-related type aliases, type variables,
    and complex type definitions in a single location following FLEXT
    domain separation patterns.
    """

    class Entry:
        """LDAP entry-related type definitions."""

        # Basic LDAP attribute value types
        type AttributeValue = str | list[str] | bytes | list[bytes]

        # LDAP attributes dictionary
        type AttributeDict = dict[str, AttributeValue]

        # LDAP entry data structure
        type Data = dict[str, AttributeValue]

        # Distinguished Name type
        type DN = str

        # Object classes list
        type ObjectClasses = list[str]

    class Search:
        """LDAP search-related type definitions."""

        # Search result entry
        type ResultEntry = dict[str, object]

        # Search result collection
        type Result = list[ResultEntry]

        # Search filter string
        type Filter = str

        # Search scope values
        type Scope = str

        # Search base DN
        type BaseDN = str

        # Attributes to return
        type Attributes = list[str] | None

    class Connection:
        """LDAP connection-related type definitions."""

        # Server URI
        type ServerURI = str

        # Port number
        type Port = int

        # Bind DN for authentication
        type BindDN = str | None

        # Bind password
        type BindPassword = str | None

        # Connection timeout
        type Timeout = int

        # SSL/TLS configuration
        type UseSSL = bool
        type UseTLS = bool

    class Validation:
        """LDAP validation-related type definitions."""

        # Validation result type
        type ValidationResult = bool

        # Error message type
        type ErrorMessage = str

        # Field name for validation
        type FieldName = str

    class Operation:
        """LDAP operation-related type definitions."""

        # Operation type identifier
        type OperationType = str

        # Operation result code
        type ResultCode = int

        # Operation duration in milliseconds
        type Duration = float

        # Operation status
        type Status = bool


__all__ = [
    "FlextLdapTypes",
]
