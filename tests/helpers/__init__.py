# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Helpers package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from tests.helpers.operation_helpers import (
        LDAP_MODIFY_ADD,
        LDAP_MODIFY_DELETE,
        LDAP_MODIFY_REPLACE,
        LdapClientType,
        LdapEntry,
        LdapOperationsType,
        OperationResultType,
        SearchResultType,
        SearchScopeType,
        T,
        TestsFlextLdapOperationHelpers,
        c,
        m,
    )

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "LDAP_MODIFY_ADD": ("tests.helpers.operation_helpers", "LDAP_MODIFY_ADD"),
    "LDAP_MODIFY_DELETE": ("tests.helpers.operation_helpers", "LDAP_MODIFY_DELETE"),
    "LDAP_MODIFY_REPLACE": ("tests.helpers.operation_helpers", "LDAP_MODIFY_REPLACE"),
    "LdapClientType": ("tests.helpers.operation_helpers", "LdapClientType"),
    "LdapEntry": ("tests.helpers.operation_helpers", "LdapEntry"),
    "LdapOperationsType": ("tests.helpers.operation_helpers", "LdapOperationsType"),
    "OperationResultType": ("tests.helpers.operation_helpers", "OperationResultType"),
    "SearchResultType": ("tests.helpers.operation_helpers", "SearchResultType"),
    "SearchScopeType": ("tests.helpers.operation_helpers", "SearchScopeType"),
    "T": ("tests.helpers.operation_helpers", "T"),
    "TestsFlextLdapOperationHelpers": ("tests.helpers.operation_helpers", "TestsFlextLdapOperationHelpers"),
    "c": ("tests.helpers.operation_helpers", "c"),
    "m": ("tests.helpers.operation_helpers", "m"),
}

__all__ = [
    "LDAP_MODIFY_ADD",
    "LDAP_MODIFY_DELETE",
    "LDAP_MODIFY_REPLACE",
    "LdapClientType",
    "LdapEntry",
    "LdapOperationsType",
    "OperationResultType",
    "SearchResultType",
    "SearchScopeType",
    "T",
    "TestsFlextLdapOperationHelpers",
    "c",
    "m",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
