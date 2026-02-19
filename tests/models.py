"""Test model definitions extending src models for centralized test objects.

This module provides test-specific model extensions that inherit from
src/flext_ldap/models.py classes. This centralizes test objects without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.models import FlextLdapModels
from flext_tests.models import FlextTestsModels


class TestsFlextLdapModels(FlextTestsModels, FlextLdapModels):
    """Test models - composição de FlextTestsModels + FlextLdapModels.

    Hierarquia:
    - FlextTestsModels: Utilitários de teste genéricos
    - FlextLdapModels: Models de domínio do projeto
    - TestsFlextLdapModels: Composição + namespace .Tests

    Access patterns:
    - tm.Tests.* - Test fixtures (ConnectionConfig, SearchOptions, etc.)
    - m.Ldap.* - Production domain models
    """

    class Tests:
        """Test fixture models namespace.

        Convenience aliases for test-only shortcuts.
        Production code should use m.Ldap.* pattern.
        """

        # Connection models for testing
        ConnectionConfig = FlextLdapModels.Ldap.ConnectionConfig
        SearchOptions = FlextLdapModels.Ldap.SearchOptions

        # Sync models for testing
        SyncOptions = FlextLdapModels.Ldap.SyncOptions
        SyncStats = FlextLdapModels.Ldap.SyncStats
        SyncPhaseConfig = FlextLdapModels.Ldap.SyncPhaseConfig
        LdapBatchStats = FlextLdapModels.Ldap.LdapBatchStats

        # Result models for testing
        UpsertResult = FlextLdapModels.Ldap.UpsertResult
        BatchUpsertResult = FlextLdapModels.Ldap.BatchUpsertResult
        OperationResult = FlextLdapModels.Ldap.OperationResult
        SearchResult = FlextLdapModels.Ldap.SearchResult
        LdapOperationResult = FlextLdapModels.Ldap.LdapOperationResult
        PhaseSyncResult = FlextLdapModels.Ldap.PhaseSyncResult
        MultiPhaseSyncResult = FlextLdapModels.Ldap.MultiPhaseSyncResult

        # Metadata models for testing
        ConversionMetadata = FlextLdapModels.Ldap.ConversionMetadata

        # Collection models for testing
        CollectionsConfig = FlextLdapModels.Collections.Config
        CollectionsOptions = FlextLdapModels.Collections.Options
        CollectionsResults = FlextLdapModels.Collections.Results
        CollectionsStatistics = FlextLdapModels.Collections.Statistics


# Short aliases for tests
tm = TestsFlextLdapModels
m = TestsFlextLdapModels

__all__ = [
    "TestsFlextLdapModels",
    "m",
    "tm",
]
