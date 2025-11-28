"""Unit tests for FlextLdapOperations.

**Modules Tested:**
- `flext_ldap.services.operations.FlextLdapOperations` - LDAP operations service

**Test Scope:**
- Operations service initialization
- Fast-fail pattern for disconnected operations (search, add, modify, delete, execute)
- Error handling and validation

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Module: TestFlextLdapOperations
Scope: Comprehensive operations testing with maximum code reuse
Pattern: Parametrized tests using factories and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

import pytest
from flext_core import FlextResult
from flext_ldif.services.parser import FlextLdifParser
from ldap3 import MODIFY_REPLACE

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations

from ..fixtures.constants import TestConstants
from ..helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.unit


class OperationType(StrEnum):
    """Enum for LDAP operation types using StrEnum pattern."""

    SEARCH = "search"
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"
    EXECUTE = "execute"


@dataclass(frozen=True, slots=True)
class OperationFactory:
    """Factory for creating operation callables using Python 3.13 dataclass.

    Eliminates lambda-based patterns in favor of explicit methods that are
    individually testable and maintain clear type signatures.
    """

    operations: FlextLdapOperations

    def create_search(
        self,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Create and execute search operation."""
        return self.operations.search(
            TestDeduplicationHelpers.create_search(
                base_dn=TestConstants.DEFAULT_BASE_DN,
            ),
        )

    def create_add(
        self,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Create and execute add operation."""
        return self.operations.add(
            TestDeduplicationHelpers.create_entry(
                TestConstants.TEST_USER_DN,
                {"cn": ["test"], "objectClass": ["top", "person"]},
            ),
        )

    def create_modify(
        self,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Create and execute modify operation."""
        return self.operations.modify(
            TestConstants.TEST_USER_DN,
            {"mail": [(MODIFY_REPLACE, ["test@example.com"])]},
        )

    def create_delete(
        self,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Create and execute delete operation."""
        return self.operations.delete(TestConstants.TEST_USER_DN)

    def create_execute(
        self,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Create and execute generic execute operation."""
        return self.operations.execute()

    def get_operation_result(
        self,
        operation_type: OperationType,
    ) -> (
        FlextResult[FlextLdapModels.SearchResult]
        | FlextResult[FlextLdapModels.OperationResult]
    ):
        """Get operation result by type."""
        if operation_type == OperationType.SEARCH:
            return self.create_search()
        if operation_type == OperationType.ADD:
            return self.create_add()
        if operation_type == OperationType.MODIFY:
            return self.create_modify()
        if operation_type == OperationType.DELETE:
            return self.create_delete()
        return self.create_execute()


class TestFlextLdapOperations:
    """Comprehensive tests for FlextLdapOperations using factories and DRY principles.

    Uses parametrized tests and constants for maximum code reuse.
    """

    OPERATION_TYPES: ClassVar[tuple[OperationType, ...]] = (
        OperationType.SEARCH,
        OperationType.ADD,
        OperationType.MODIFY,
        OperationType.DELETE,
        OperationType.EXECUTE,
    )

    @staticmethod
    def _create_operations_service(
        parser: FlextLdifParser | None,
    ) -> FlextLdapOperations:
        """Create operations service instance."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=parser)
        return FlextLdapOperations(connection=connection)

    def test_operations_initialization(
        self,
        ldap_parser: FlextLdifParser | None,
    ) -> None:
        """Test operations service initialization and connection validation."""
        operations = self._create_operations_service(ldap_parser)
        assert operations is not None
        assert operations._connection is not None
        assert not operations._connection.is_connected

    @pytest.mark.parametrize("operation_type", OPERATION_TYPES)
    def test_operation_when_not_connected_returns_failure(
        self,
        ldap_parser: FlextLdifParser | None,
        operation_type: OperationType,
    ) -> None:
        """Test operations fail fast when not connected (parametrized).

        Verifies that all operation types return FlextResult.failure() when
        the connection is not established, maintaining fast-fail pattern.
        """
        operations = self._create_operations_service(ldap_parser)
        factory = OperationFactory(operations=operations)
        result = factory.get_operation_result(operation_type)

        assert isinstance(result, FlextResult)
        assert result.is_failure, f"Expected failure, got: {result}"
        assert result.error is not None
        assert "connected" in result.error.lower()
        assert not operations._connection.is_connected
