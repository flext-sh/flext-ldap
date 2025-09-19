"""FLEXT LDAP Types Module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Literal

from flext_core import FlextTypes


class FlextLdapTypes(FlextTypes):
    """Unified type definitions for FLEXT LDAP ecosystem.

    Provides comprehensive type system for domain operations, search parameters,
    client configurations, entry structures, and connection management. All types
    are organized into logical namespaces following Clean Architecture patterns with
    internal properties with full type safety.
    """

    class Domain:
        """Domain-level type definitions for LDAP entities."""

        DistinguishedName = str
        Dn = str
        ValidatedDn = str
        LdapDn = str
        BaseDn = str
        Rdn = str
        AttributeName = str
        AttributeValue = str | int | bool | bytes
        ObjectClass = str
        ConnectionId = str

    class Search:
        """Search operation type definitions."""

        Filter = str
        FilterString = str
        LdapFilter = str
        SearchScope = str
        ScopeType = Literal["BASE", "LEVEL", "SUBTREE"]
        SearchResult = dict[str, object]
        ResultEntry = dict[str, object]
        ResultList = list[dict[str, object]]
        SearchAttributes = list[str] | None
        SizeLimit = int
        TimeLimit = int

    class Client:
        """Client configuration and connection types."""

        LdapScope = Literal["BASE", "LEVEL", "SUBTREE"]
        ServerUri = str
        Port = int
        UseSSL = bool
        UseTLS = bool
        Username = str
        Password = str
        BindDn = str
        Timeout = int

    class Entry:
        """LDAP entry structure types."""

        EntryDict = dict[str, object]
        AttributeDict = dict[str, list[str]]
        AttributeValue = str | int | bool | bytes | object
        EntryData = dict[str, object]
        RawEntry = dict[str, object]
        NormalizedEntry = dict[str, object]

    class Connection:
        """Connection management types."""

        type ConnectionId = str
        ConnectionState = Literal["UNBOUND", "BOUND", "CLOSED"]
        ConnectionPool = dict[str, object]
        SessionId = str
        ConnectionConfig = dict[str, object]

    class Operation:
        """LDAP operation types."""

        OperationType = Literal["ADD", "DELETE", "MODIFY", "SEARCH", "BIND"]
        OperationResult = dict[str, object]
        ModifyType = Literal["ADD", "DELETE", "REPLACE"]
        ModifyOperation = dict[str, object]

    class Request:
        """Request parameter types."""

        SearchRequest = dict[str, object]
        ModifyRequest = dict[str, object]
        AddRequest = dict[str, object]
        DeleteRequest = dict[str, object]
        BindRequest = dict[str, object]


__all__ = [
    "FlextLdapTypes",
]
