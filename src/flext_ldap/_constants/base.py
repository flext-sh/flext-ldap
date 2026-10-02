"""Private constants base for flext-ldap.

Owns every LDAP constant value so the public ``constants.py`` facade module
declares no constant directly (ENFORCE-079); the facade re-exports them via
``c.Ldap.*`` through inheritance.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Final

from flext_ldif import FlextLdifConstants
from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException

from .enums import FlextLdapConstantsEnums

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flext_ldap import t


class FlextLdapConstantsBase(FlextLdapConstantsEnums):
    """Private constants owner for LDAP defaults, sets, and lookup tables."""

    NAME: ClassVar[str] = "FLEXT_LDAP"
    VENDOR_STRING_MAX_TOKENS: Final[int] = 2
    DEFAULT_MAX_RETRIES: Final[int] = 5
    DEFAULT_RETRY_DELAY: Final[float] = 1.0
    PORT: Final[int] = 389
    TIMEOUT: Final[int] = FlextLdifConstants.DEFAULT_TIMEOUT_SECONDS
    AUTO_BIND: Final[bool] = True
    AUTO_RANGE: Final[bool] = True
    DEFAULT_BIND_DN: Final[str] = ""
    DEFAULT_BIND_PASSWORD: Final[str] = ""
    DEFAULT_USE_SSL: Final[bool] = False
    DEFAULT_USE_TLS: Final[bool] = False
    ALL_ENTRIES_FILTER: Final[str] = "(objectClass=*)"
    UNKNOWN_CATEGORY: Final[str] = "unknown"
    EXAMPLE_BASE_DN: Final[str] = "dc=example,dc=com"
    MULTI_PHASE_PARAM_COUNT: Final[int] = 5
    SINGLE_PHASE_PARAM_COUNT: Final[int] = 4
    DN_TRUNCATION_LENGTH: Final[int] = 100
    BATCH_SIZE: Final[int] = 100

    VALID_STATUSES: Final[frozenset[FlextLdapConstantsEnums.Status]] = frozenset({
        FlextLdapConstantsEnums.Status.PENDING,
        FlextLdapConstantsEnums.Status.RUNNING,
        FlextLdapConstantsEnums.Status.COMPLETED,
        FlextLdapConstantsEnums.Status.FAILED,
    })

    PARTIAL_SUCCESS_CODES: Final[frozenset[FlextLdapConstantsEnums.ResultCode]] = (
        frozenset({
            FlextLdapConstantsEnums.ResultCode.SUCCESS,
            FlextLdapConstantsEnums.ResultCode.REFERRAL,
        })
    )

    ENTRY_ALREADY_EXISTS_RE: Final[t.RegexPattern] = re.compile(
        r"entry already exists|already exists|entryalreadyexists|ldap_already_exists",
        re.IGNORECASE,
    )

    NO_SUCH_OBJECT_RE: Final[t.RegexPattern] = re.compile(
        r"nosuchobject|no such object", re.IGNORECASE
    )

    OPERATION_SUCCESS_MESSAGES: ClassVar[
        Mapping[FlextLdapConstantsEnums.OperationType, str]
    ] = MappingProxyType({
        FlextLdapConstantsEnums.OperationType.ADD: "Entry added successfully",
        FlextLdapConstantsEnums.OperationType.MODIFY: "Entry modified successfully",
        FlextLdapConstantsEnums.OperationType.DELETE: "Entry deleted successfully",
        FlextLdapConstantsEnums.OperationType.SEARCH: "Search completed successfully",
    })
    "Per-operation success messages used by the ldap3 operation executor."

    OPERATION_FAILURE_PREFIXES: ClassVar[
        Mapping[FlextLdapConstantsEnums.OperationType, str]
    ] = MappingProxyType({
        FlextLdapConstantsEnums.OperationType.ADD: "Add failed",
        FlextLdapConstantsEnums.OperationType.MODIFY: "Modify failed",
        FlextLdapConstantsEnums.OperationType.DELETE: "Delete failed",
        FlextLdapConstantsEnums.OperationType.SEARCH: "Search failed",
    })
    "Per-operation error message prefixes used by the ldap3 operation executor."

    EXC_CONNECTION: Final[tuple[type[Exception], ...]] = (
        *FlextLdifConstants.EXC_BROAD_IO_TYPE,
        _Ldap3LDAPException,
    )
    "Boundary catch for ldap3 connect/bind: c.EXC_BROAD_IO_TYPE plus LDAPException."

    DEFAULT_SCOPE: Final[FlextLdapConstantsEnums.SearchScope] = (
        FlextLdapConstantsEnums.SearchScope.SUBTREE
    )

    LDAP3_SCOPE_BY_SEARCH_SCOPE: Final[
        t.MappingKV[
            FlextLdapConstantsEnums.SearchScope,
            FlextLdapConstantsEnums.SearchScopeValue,
        ]
    ] = MappingProxyType({
        FlextLdapConstantsEnums.SearchScope.BASE: FlextLdapConstantsEnums.SearchScopeValue.BASE,
        FlextLdapConstantsEnums.SearchScope.ONELEVEL: FlextLdapConstantsEnums.SearchScopeValue.LEVEL,
        FlextLdapConstantsEnums.SearchScope.SUBTREE: FlextLdapConstantsEnums.SearchScopeValue.SUBTREE,
    })

    DEFAULT_TYPE: Final[FlextLdifConstants.Ldif.ServerTypes] = (
        FlextLdifConstants.Ldif.ServerTypes.RFC
    )

    ROOT_DSE_DETECTION_ORDER: Final[t.StrSequence] = (
        FlextLdifConstants.Ldif.ServerTypes.OPENLDAP.value,
        FlextLdifConstants.Ldif.ServerTypes.OID.value,
        FlextLdifConstants.Ldif.ServerTypes.OUD.value,
        FlextLdifConstants.Ldif.ServerTypes.AD.value,
        FlextLdifConstants.Ldif.ServerTypes.DS389.value,
    )

    ROOT_DSE_EXTENSION_MARKERS: Final[t.MappingKV[str, frozenset[str]]] = (
        MappingProxyType({
            FlextLdifConstants.Ldif.ServerTypes.OPENLDAP.value: frozenset({"openldap"}),
            FlextLdifConstants.Ldif.ServerTypes.OID.value: frozenset({"oracle", "oid"}),
            FlextLdifConstants.Ldif.ServerTypes.OUD.value: frozenset({"oud"}),
            FlextLdifConstants.Ldif.ServerTypes.AD.value: frozenset({
                "microsoft",
                "windows",
            }),
            FlextLdifConstants.Ldif.ServerTypes.DS389.value: frozenset({
                "389",
                "dirsrv",
            }),
        })
    )

    ROOT_DSE_CONTEXT_MARKERS: Final[t.MappingKV[str, frozenset[str]]] = (
        MappingProxyType({
            FlextLdifConstants.Ldif.ServerTypes.OID.value: frozenset({"oracle"}),
            FlextLdifConstants.Ldif.ServerTypes.AD.value: frozenset({
                "microsoft",
                "windows",
            }),
        })
    )

    ROOT_DSE_VENDOR_REQUIRED_MARKERS: Final[t.MappingKV[str, frozenset[str]]] = (
        MappingProxyType({
            FlextLdifConstants.Ldif.ServerTypes.OUD.value: frozenset({
                "oracle",
                "unified directory",
            }),
            FlextLdifConstants.Ldif.ServerTypes.OID.value: frozenset({"oracle"}),
            FlextLdifConstants.Ldif.ServerTypes.OPENLDAP.value: frozenset(),
            FlextLdifConstants.Ldif.ServerTypes.AD.value: frozenset(),
            FlextLdifConstants.Ldif.ServerTypes.DS389.value: frozenset(),
        })
    )

    ROOT_DSE_VENDOR_ANY_MARKERS: Final[t.MappingKV[str, frozenset[str]]] = (
        MappingProxyType({
            FlextLdifConstants.Ldif.ServerTypes.OID.value: frozenset({
                "internet directory",
                "oid",
                "corporation",
            }),
            FlextLdifConstants.Ldif.ServerTypes.OPENLDAP.value: frozenset({"openldap"}),
            FlextLdifConstants.Ldif.ServerTypes.AD.value: frozenset({
                "microsoft",
                "active directory",
            }),
            FlextLdifConstants.Ldif.ServerTypes.DS389.value: frozenset({
                "389",
                "dirsrv",
            }),
        })
    )

    ROOT_DSE_VENDOR_EXCLUDED_MARKERS: Final[t.MappingKV[str, frozenset[str]]] = (
        MappingProxyType({
            FlextLdifConstants.Ldif.ServerTypes.OID.value: frozenset({
                "unified directory"
            })
        })
    )

    ROOT_DSE_VENDOR_MAX_TOKENS: Final[t.MappingKV[str, int]] = MappingProxyType({
        FlextLdifConstants.Ldif.ServerTypes.OID.value: VENDOR_STRING_MAX_TOKENS
    })


__all__: list[str] = ["FlextLdapConstantsBase"]
