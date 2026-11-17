# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Constants package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._constants.base import FlextLdapConstantsBase


__all__: tuple[str, ...] = ("FlextLdapConstantsBase",)

install_lazy_exports(
    __name__,
    globals(),
    {"FlextLdapConstantsBase": ".base"},
    public_exports=__all__,
    deferred_members={
        "FlextLdapConstantsBase": (
            "Status",
            "OperationName",
            "ResultCode",
            "ErrorMessage",
            "AttributeName",
            "OperationType",
            "UpsertOperation",
            "SearchScope",
            "SearchScopeValue",
            "ModifyOperation",
            "Ldap3SearchScope",
            "Ldap3GetInfo",
            "REAL_ATTRIBUTES_ONLY_CONTROL_OID",
            "TlsValidation",
            "RootDseAttribute",
            "NAME",
            "VENDOR_STRING_MAX_TOKENS",
            "DEFAULT_MAX_RETRIES",
            "DEFAULT_RETRY_DELAY",
            "PORT",
            "TIMEOUT",
            "AUTO_BIND",
            "AUTO_RANGE",
            "DEFAULT_BIND_DN",
            "DEFAULT_BIND_PASSWORD",
            "DEFAULT_USE_SSL",
            "DEFAULT_USE_TLS",
            "ALL_ENTRIES_FILTER",
            "UNKNOWN_CATEGORY",
            "EXAMPLE_BASE_DN",
            "MULTI_PHASE_PARAM_COUNT",
            "SINGLE_PHASE_PARAM_COUNT",
            "DN_TRUNCATION_LENGTH",
            "BATCH_SIZE",
            "MAX_OUTSTANDING_SEARCHES",
            "VALID_STATUSES",
            "PARTIAL_SUCCESS_CODES",
            "ENTRY_ALREADY_EXISTS_RE",
            "NO_SUCH_OBJECT_RE",
            "OPERATION_SUCCESS_MESSAGES",
            "OPERATION_FAILURE_PREFIXES",
            "EXC_CONNECTION",
            "DEFAULT_SCOPE",
            "DEFAULT_TLS_VALIDATION",
            "TLS_VERIFY_MODE_BY_VALIDATION",
            "LDAP3_SCOPE_BY_SEARCH_SCOPE",
            "DEFAULT_TYPE",
            "ROOT_DSE_DETECTION_ORDER",
            "ROOT_DSE_EXTENSION_MARKERS",
            "ROOT_DSE_CONTEXT_MARKERS",
            "ROOT_DSE_VENDOR_REQUIRED_MARKERS",
            "ROOT_DSE_VENDOR_ANY_MARKERS",
            "ROOT_DSE_VENDOR_EXCLUDED_MARKERS",
            "ROOT_DSE_VENDOR_MAX_TOKENS",
        ),
    },
)
