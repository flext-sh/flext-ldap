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
        AttributeValue = str | list[str] | bytes | list[bytes]

        # LDAP attributes dictionary
        AttributeDict = dict[str, "FlextLdapTypes.Entry.AttributeValue"]

        # LDAP entry data structure
        Data = dict[str, "FlextLdapTypes.Entry.AttributeValue"]

        # Distinguished Name type
        DN = str

        # Object classes list
        ObjectClasses = list[str]

    class Search:
        """LDAP search-related type definitions."""

        # Search result entry
        ResultEntry = dict[str, object]

        # Search result collection
        Result = list["FlextLdapTypes.Search.ResultEntry"]

        # Search filter string
        Filter = str

        # Search scope values
        Scope = str

        # Search base DN
        BaseDN = str

        # Attributes to return
        Attributes = list[str] | None

    class Connection:
        """LDAP connection-related type definitions."""

        # Server URI
        ServerURI = str

        # Port number
        Port = int

        # Bind DN for authentication
        BindDN = str | None

        # Bind password
        BindPassword = str | None

        # Connection timeout
        Timeout = int

        # SSL/TLS configuration
        UseSSL = bool
        UseTLS = bool

    class Validation:
        """LDAP validation-related type definitions."""

        # Validation result type
        ValidationResult = bool

        # Error message type
        ErrorMessage = str

        # Field name for validation
        FieldName = str

    class Operation:
        """LDAP operation-related type definitions."""

        # Operation type identifier
        OperationType = str

        # Operation result code
        ResultCode = int

        # Operation duration in milliseconds
        Duration = float

        # Operation status
        Status = bool


__all__ = [
    "FlextLdapTypes",
]
