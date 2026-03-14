# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Test infrastructure for flext-ldap tests.

Provides centralized test objects that extend production modules from src/flext_ldap/.
All test objects use real inheritance to expose the full hierarchy without duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

    from tests.base import TestsFlextLdapServiceBase, s
    from tests.conftest import (
        FLEXT_LDAP_ROOT,
        FLEXT_WORKSPACE_ROOT,
        LDAP_ADMIN_DN,
        LDAP_ADMIN_PASSWORD,
        LDAP_BASE_DN,
        LDAP_COMPOSE_FILE,
        LDAP_CONTAINER_NAME,
        LDAP_LEGACY_ADMIN_DN,
        LDAP_LEGACY_ADMIN_PASSWORD,
        LDAP_PORT,
        LDAP_SERVICE_NAME,
        SAMPLE_GROUP_ENTRY,
        SAMPLE_USER_ENTRY,
        DNSTracker,
        FileLock,
        TestFixtures,
        base_ldif_content,
        base_ldif_entries,
        connection_config,
        create_flext_ldap_instance,
        ldap3_connection,
        ldap_client,
        ldap_config,
        ldap_connection,
        ldap_container,
        ldap_operations,
        ldap_parser,
        ldap_test_data_loader,
        logger,
        make_group_dn,
        make_user_dn,
        pytest_runtest_makereport,
        pytest_sessionstart,
        sample_connection_config,
        search_options,
        session_id,
        test_dns_tracker,
        test_group_entry,
        test_groups_json,
        test_user_entry,
        test_users_json,
        unique_dn_suffix,
        worker_id,
    )
    from tests.constants import TestsFlextLdapConstants, c
    from tests.helpers.operation_helpers import (
        LdapClientType,
        LdapEntry,
        LdapOperationsType,
        OperationResultType,
        SearchResultType,
        SearchScopeType,
        TestsFlextLdapOperationHelpers,
    )
    from tests.models import TestsFlextLdapModels, m, tm
    from tests.protocols import TestsFlextLdapProtocols, p
    from tests.test_smoke import TestsFlextLdapSmoke, pytestmark
    from tests.typings import (
        GenericCallableParameterDict,
        GenericFieldsDict,
        GenericTestCaseDict,
        LdapConnectionConfigDict,
        LdapConnectionResultDict,
        LdapContainerDict,
        LdapEntryDataDict,
        LdapModifyOperationDict,
        LdapSchemaAttributeDict,
        LdapSchemaObjectClassDict,
        LdapSearchOptionsDict,
        LdapSearchResultDict,
        LdapTestScenarioDict,
        T,
        T_co,
        T_contra,
        TestsFlextLdapTypes,
        t,
        tt,
    )
    from tests.unit.test_api import TestsFlextLdapApi
    from tests.unit.test_base import TestsFlextLdapBase
    from tests.unit.test_config import TestsFlextLdapSettings
    from tests.unit.test_detection import TestsFlextLdapDetection
    from tests.unit.test_entry_adapter import TestsFlextLdapEntryAdapter
    from tests.unit.test_ldap3_adapter import TestsFlextLdap3Adapter
    from tests.unit.test_operations import TestsFlextLdapOperations
    from tests.unit.test_sync import TestsFlextLdapSync
    from tests.utilities import TestsFlextLdapUtilities, u

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "DNSTracker": ("tests.conftest", "DNSTracker"),
    "FLEXT_LDAP_ROOT": ("tests.conftest", "FLEXT_LDAP_ROOT"),
    "FLEXT_WORKSPACE_ROOT": ("tests.conftest", "FLEXT_WORKSPACE_ROOT"),
    "FileLock": ("tests.conftest", "FileLock"),
    "GenericCallableParameterDict": ("tests.typings", "GenericCallableParameterDict"),
    "GenericFieldsDict": ("tests.typings", "GenericFieldsDict"),
    "GenericTestCaseDict": ("tests.typings", "GenericTestCaseDict"),
    "LDAP_ADMIN_DN": ("tests.conftest", "LDAP_ADMIN_DN"),
    "LDAP_ADMIN_PASSWORD": ("tests.conftest", "LDAP_ADMIN_PASSWORD"),
    "LDAP_BASE_DN": ("tests.conftest", "LDAP_BASE_DN"),
    "LDAP_COMPOSE_FILE": ("tests.conftest", "LDAP_COMPOSE_FILE"),
    "LDAP_CONTAINER_NAME": ("tests.conftest", "LDAP_CONTAINER_NAME"),
    "LDAP_LEGACY_ADMIN_DN": ("tests.conftest", "LDAP_LEGACY_ADMIN_DN"),
    "LDAP_LEGACY_ADMIN_PASSWORD": ("tests.conftest", "LDAP_LEGACY_ADMIN_PASSWORD"),
    "LDAP_PORT": ("tests.conftest", "LDAP_PORT"),
    "LDAP_SERVICE_NAME": ("tests.conftest", "LDAP_SERVICE_NAME"),
    "LdapClientType": ("tests.helpers.operation_helpers", "LdapClientType"),
    "LdapConnectionConfigDict": ("tests.typings", "LdapConnectionConfigDict"),
    "LdapConnectionResultDict": ("tests.typings", "LdapConnectionResultDict"),
    "LdapContainerDict": ("tests.typings", "LdapContainerDict"),
    "LdapEntry": ("tests.helpers.operation_helpers", "LdapEntry"),
    "LdapEntryDataDict": ("tests.typings", "LdapEntryDataDict"),
    "LdapModifyOperationDict": ("tests.typings", "LdapModifyOperationDict"),
    "LdapOperationsType": ("tests.helpers.operation_helpers", "LdapOperationsType"),
    "LdapSchemaAttributeDict": ("tests.typings", "LdapSchemaAttributeDict"),
    "LdapSchemaObjectClassDict": ("tests.typings", "LdapSchemaObjectClassDict"),
    "LdapSearchOptionsDict": ("tests.typings", "LdapSearchOptionsDict"),
    "LdapSearchResultDict": ("tests.typings", "LdapSearchResultDict"),
    "LdapTestScenarioDict": ("tests.typings", "LdapTestScenarioDict"),
    "OperationResultType": ("tests.helpers.operation_helpers", "OperationResultType"),
    "SAMPLE_GROUP_ENTRY": ("tests.conftest", "SAMPLE_GROUP_ENTRY"),
    "SAMPLE_USER_ENTRY": ("tests.conftest", "SAMPLE_USER_ENTRY"),
    "SearchResultType": ("tests.helpers.operation_helpers", "SearchResultType"),
    "SearchScopeType": ("tests.helpers.operation_helpers", "SearchScopeType"),
    "T": ("tests.typings", "T"),
    "T_co": ("tests.typings", "T_co"),
    "T_contra": ("tests.typings", "T_contra"),
    "TestFixtures": ("tests.conftest", "TestFixtures"),
    "TestsFlextLdap3Adapter": (
        "tests.unit.test_ldap3_adapter",
        "TestsFlextLdap3Adapter",
    ),
    "TestsFlextLdapApi": ("tests.unit.test_api", "TestsFlextLdapApi"),
    "TestsFlextLdapBase": ("tests.unit.test_base", "TestsFlextLdapBase"),
    "TestsFlextLdapConstants": ("tests.constants", "TestsFlextLdapConstants"),
    "TestsFlextLdapDetection": ("tests.unit.test_detection", "TestsFlextLdapDetection"),
    "TestsFlextLdapEntryAdapter": (
        "tests.unit.test_entry_adapter",
        "TestsFlextLdapEntryAdapter",
    ),
    "TestsFlextLdapModels": ("tests.models", "TestsFlextLdapModels"),
    "TestsFlextLdapOperationHelpers": (
        "tests.helpers.operation_helpers",
        "TestsFlextLdapOperationHelpers",
    ),
    "TestsFlextLdapOperations": (
        "tests.unit.test_operations",
        "TestsFlextLdapOperations",
    ),
    "TestsFlextLdapProtocols": ("tests.protocols", "TestsFlextLdapProtocols"),
    "TestsFlextLdapServiceBase": ("tests.base", "TestsFlextLdapServiceBase"),
    "TestsFlextLdapSettings": ("tests.unit.test_config", "TestsFlextLdapSettings"),
    "TestsFlextLdapSmoke": ("tests.test_smoke", "TestsFlextLdapSmoke"),
    "TestsFlextLdapSync": ("tests.unit.test_sync", "TestsFlextLdapSync"),
    "TestsFlextLdapTypes": ("tests.typings", "TestsFlextLdapTypes"),
    "TestsFlextLdapUtilities": ("tests.utilities", "TestsFlextLdapUtilities"),
    "base_ldif_content": ("tests.conftest", "base_ldif_content"),
    "base_ldif_entries": ("tests.conftest", "base_ldif_entries"),
    "c": ("tests.constants", "c"),
    "connection_config": ("tests.conftest", "connection_config"),
    "create_flext_ldap_instance": ("tests.conftest", "create_flext_ldap_instance"),
    "ldap3_connection": ("tests.conftest", "ldap3_connection"),
    "ldap_client": ("tests.conftest", "ldap_client"),
    "ldap_config": ("tests.conftest", "ldap_config"),
    "ldap_connection": ("tests.conftest", "ldap_connection"),
    "ldap_container": ("tests.conftest", "ldap_container"),
    "ldap_operations": ("tests.conftest", "ldap_operations"),
    "ldap_parser": ("tests.conftest", "ldap_parser"),
    "ldap_test_data_loader": ("tests.conftest", "ldap_test_data_loader"),
    "logger": ("tests.conftest", "logger"),
    "m": ("tests.models", "m"),
    "make_group_dn": ("tests.conftest", "make_group_dn"),
    "make_user_dn": ("tests.conftest", "make_user_dn"),
    "p": ("tests.protocols", "p"),
    "pytest_runtest_makereport": ("tests.conftest", "pytest_runtest_makereport"),
    "pytest_sessionstart": ("tests.conftest", "pytest_sessionstart"),
    "pytestmark": ("tests.test_smoke", "pytestmark"),
    "s": ("tests.base", "s"),
    "sample_connection_config": ("tests.conftest", "sample_connection_config"),
    "search_options": ("tests.conftest", "search_options"),
    "session_id": ("tests.conftest", "session_id"),
    "t": ("tests.typings", "t"),
    "test_dns_tracker": ("tests.conftest", "test_dns_tracker"),
    "test_group_entry": ("tests.conftest", "test_group_entry"),
    "test_groups_json": ("tests.conftest", "test_groups_json"),
    "test_user_entry": ("tests.conftest", "test_user_entry"),
    "test_users_json": ("tests.conftest", "test_users_json"),
    "tm": ("tests.models", "tm"),
    "tt": ("tests.typings", "tt"),
    "u": ("tests.utilities", "u"),
    "unique_dn_suffix": ("tests.conftest", "unique_dn_suffix"),
    "worker_id": ("tests.conftest", "worker_id"),
}

__all__ = [
    "FLEXT_LDAP_ROOT",
    "FLEXT_WORKSPACE_ROOT",
    "LDAP_ADMIN_DN",
    "LDAP_ADMIN_PASSWORD",
    "LDAP_BASE_DN",
    "LDAP_COMPOSE_FILE",
    "LDAP_CONTAINER_NAME",
    "LDAP_LEGACY_ADMIN_DN",
    "LDAP_LEGACY_ADMIN_PASSWORD",
    "LDAP_PORT",
    "LDAP_SERVICE_NAME",
    "SAMPLE_GROUP_ENTRY",
    "SAMPLE_USER_ENTRY",
    "DNSTracker",
    "FileLock",
    "GenericCallableParameterDict",
    "GenericFieldsDict",
    "GenericTestCaseDict",
    "LdapClientType",
    "LdapConnectionConfigDict",
    "LdapConnectionResultDict",
    "LdapContainerDict",
    "LdapEntry",
    "LdapEntryDataDict",
    "LdapModifyOperationDict",
    "LdapOperationsType",
    "LdapSchemaAttributeDict",
    "LdapSchemaObjectClassDict",
    "LdapSearchOptionsDict",
    "LdapSearchResultDict",
    "LdapTestScenarioDict",
    "OperationResultType",
    "SearchResultType",
    "SearchScopeType",
    "T",
    "T_co",
    "T_contra",
    "TestFixtures",
    "TestsFlextLdap3Adapter",
    "TestsFlextLdapApi",
    "TestsFlextLdapBase",
    "TestsFlextLdapConstants",
    "TestsFlextLdapDetection",
    "TestsFlextLdapEntryAdapter",
    "TestsFlextLdapModels",
    "TestsFlextLdapOperationHelpers",
    "TestsFlextLdapOperations",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapServiceBase",
    "TestsFlextLdapSettings",
    "TestsFlextLdapSmoke",
    "TestsFlextLdapSync",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "base_ldif_content",
    "base_ldif_entries",
    "c",
    "connection_config",
    "create_flext_ldap_instance",
    "ldap3_connection",
    "ldap_client",
    "ldap_config",
    "ldap_connection",
    "ldap_container",
    "ldap_operations",
    "ldap_parser",
    "ldap_test_data_loader",
    "logger",
    "m",
    "make_group_dn",
    "make_user_dn",
    "p",
    "pytest_runtest_makereport",
    "pytest_sessionstart",
    "pytestmark",
    "s",
    "sample_connection_config",
    "search_options",
    "session_id",
    "t",
    "test_dns_tracker",
    "test_group_entry",
    "test_groups_json",
    "test_user_entry",
    "test_users_json",
    "tm",
    "tt",
    "u",
    "unique_dn_suffix",
    "worker_id",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
