"""Comprehensive unit tests for LDAP mixins.

This module provides comprehensive unit tests for all LDAP mixin classes,
testing validation mixins, factory mixins, and business rules mixins.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any

import pytest

from flext_core import FlextResult
from flext_ldap.mixins import FlextLdapMixins


class TestValidationMixin:
    """Test ValidationMixin functionality."""

    def test_validate_not_empty_with_valid_value(self) -> None:
        """Test validate_not_empty with non-empty value."""
        result = FlextLdapMixins.ValidationMixin.validate_not_empty(
            "username", "testuser"
        )

        assert result.is_success
        assert result.error is None

    def test_validate_not_empty_with_empty_string(self) -> None:
        """Test validate_not_empty with empty string."""
        result = FlextLdapMixins.ValidationMixin.validate_not_empty("username", "")

        assert result.is_failure
        assert result.error is not None
        assert "cannot be empty" in result.error

    def test_validate_not_empty_with_whitespace(self) -> None:
        """Test validate_not_empty with whitespace-only string."""
        result = FlextLdapMixins.ValidationMixin.validate_not_empty("username", "   ")

        assert result.is_failure
        assert result.error is not None
        assert "cannot be empty" in result.error

    def test_validate_not_empty_with_none(self) -> None:
        """Test validate_not_empty with None value."""
        result = FlextLdapMixins.ValidationMixin.validate_not_empty("username", None)

        assert result.is_failure
        assert result.error is not None
        assert "cannot be empty" in result.error

    def test_validate_status_with_valid_status(self) -> None:
        """Test validate_status with valid status value."""
        for status in ["pending", "running", "completed", "failed", "cancelled"]:
            result = FlextLdapMixins.ValidationMixin.validate_status(status)
            assert result.is_success, f"Status {status} should be valid"

    def test_validate_status_with_invalid_status(self) -> None:
        """Test validate_status with invalid status value."""
        result = FlextLdapMixins.ValidationMixin.validate_status("invalid")

        assert result.is_failure
        assert result.error is not None
        assert "Invalid status" in result.error
        assert "invalid" in result.error

    @pytest.mark.parametrize(
        ("value", "expected_success"),
        [
            (1.0, True),
            (100.0, True),
            (0.1, True),
            (0.0, False),
            (-1.0, False),
            (-100.0, False),
        ],
    )
    def test_validate_positive_number(
        self, value: float, expected_success: bool
    ) -> None:
        """Test validate_positive_number with various values."""
        result = FlextLdapMixins.ValidationMixin.validate_positive_number(
            "count", value
        )

        if expected_success:
            assert result.is_success
        else:
            assert result.is_failure
            assert result.error is not None
            assert "must be positive" in result.error

    @pytest.mark.parametrize(
        ("value", "expected_success"),
        [
            (0.0, True),
            (1.0, True),
            (100.0, True),
            (-1.0, False),
            (-100.0, False),
        ],
    )
    def test_validate_non_negative_number(
        self, value: float, expected_success: bool
    ) -> None:
        """Test validate_non_negative_number with various values."""
        result = FlextLdapMixins.ValidationMixin.validate_non_negative_number(
            "count", value
        )

        if expected_success:
            assert result.is_success
        else:
            assert result.is_failure
            assert result.error is not None
            assert "must be non-negative" in result.error

    def test_validate_enum_value_with_valid_value(self) -> None:
        """Test validate_enum_value with valid enum value."""
        valid_values = ["option1", "option2", "option3"]
        result = FlextLdapMixins.ValidationMixin.validate_enum_value(
            "choice", "option1", valid_values
        )

        assert result.is_success

    def test_validate_enum_value_with_invalid_value(self) -> None:
        """Test validate_enum_value with invalid enum value."""
        valid_values = ["option1", "option2", "option3"]
        result = FlextLdapMixins.ValidationMixin.validate_enum_value(
            "choice", "invalid", valid_values
        )

        assert result.is_failure
        assert result.error is not None
        assert "Invalid choice" in result.error
        assert "invalid" in result.error
        assert "option1" in result.error


class TestFactoryMixin:
    """Test FactoryMixin functionality."""

    def test_create_flext_result_ok(self) -> None:
        """Test create_flext_result_ok creates successful result."""
        value: dict[str, str] = {"test": "data"}
        result = FlextLdapMixins.FactoryMixin.create_flext_result_ok(value)

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.value == value

    def test_create_flext_result_ok_with_none(self) -> None:
        """Test create_flext_result_ok with None value."""
        result = FlextLdapMixins.FactoryMixin.create_flext_result_ok(None)

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.value is None

    def test_create_flext_result_ok_with_various_types(self) -> None:
        """Test create_flext_result_ok with various value types."""
        test_values = [
            "string",
            123,
            45.67,
            True,
            ["list", "of", "items"],
            {"dict": "value"},
        ]

        for value in test_values:
            result: FlextResult[Any] = (
                FlextLdapMixins.FactoryMixin.create_flext_result_ok(value)
            )
            assert result.is_success
            assert result.value == value

    def test_create_flext_result_fail(self) -> None:
        """Test create_flext_result_fail creates failed result."""
        error_message: str = "Operation failed"
        result: Any = FlextLdapMixins.FactoryMixin.create_flext_result_fail(
            error_message
        )

        assert isinstance(result, FlextResult)
        assert result.is_failure
        assert result.error == error_message

    def test_create_flext_result_fail_with_detailed_error(self) -> None:
        """Test create_flext_result_fail with detailed error message."""
        error_message: str = "Validation failed: email format invalid"
        result: Any = FlextLdapMixins.FactoryMixin.create_flext_result_fail(
            error_message
        )

        assert result.is_failure
        assert result.error == error_message
        assert result.error is not None
        assert "Validation failed" in result.error


class TestBusinessRulesMixin:
    """Test BusinessRulesMixin functionality."""

    def test_validate_command_execution_state_with_matching_status(self) -> None:
        """Test validate_command_execution_state with matching status."""
        result = FlextLdapMixins.BusinessRulesMixin.validate_command_execution_state(
            current_status="pending", expected_status="pending", operation="start"
        )

        assert result.is_success

    def test_validate_command_execution_state_with_mismatched_status(self) -> None:
        """Test validate_command_execution_state with mismatched status."""
        result = FlextLdapMixins.BusinessRulesMixin.validate_command_execution_state(
            current_status="running", expected_status="pending", operation="start"
        )

        assert result.is_failure
        assert result.error is not None
        assert "Cannot start" in result.error
        assert "pending" in result.error
        assert "running" in result.error

    @pytest.mark.parametrize(
        ("current", "expected", "operation"),
        [
            ("pending", "running", "execute"),
            ("running", "completed", "finish"),
            ("completed", "pending", "restart"),
        ],
    )
    def test_validate_command_execution_state_various_transitions(
        self, current: str, expected: str, operation: str
    ) -> None:
        """Test validate_command_execution_state with various state transitions."""
        result = FlextLdapMixins.BusinessRulesMixin.validate_command_execution_state(
            current_status=current, expected_status=expected, operation=operation
        )

        assert result.is_failure
        assert result.error is not None
        assert operation in result.error

    def test_validate_pipeline_step_with_valid_step(self) -> None:
        """Test validate_pipeline_step with valid step structure."""
        step: dict[str, object] = {
            "name": "test_step",
            "command": "execute_command",
            "optional_field": "value",
        }
        result = FlextLdapMixins.BusinessRulesMixin.validate_pipeline_step(step)

        assert result.is_success

    def test_validate_pipeline_step_missing_name(self) -> None:
        """Test validate_pipeline_step with missing name field."""
        step: dict[str, object] = {"command": "execute_command"}
        result = FlextLdapMixins.BusinessRulesMixin.validate_pipeline_step(step)

        assert result.is_failure
        assert result.error is not None
        assert "name" in result.error

    def test_validate_pipeline_step_missing_command(self) -> None:
        """Test validate_pipeline_step with missing command field."""
        step: dict[str, object] = {"name": "test_step"}
        result = FlextLdapMixins.BusinessRulesMixin.validate_pipeline_step(step)

        assert result.is_failure
        assert result.error is not None
        assert "command" in result.error

    def test_validate_pipeline_step_empty_dict(self) -> None:
        """Test validate_pipeline_step with empty dictionary."""
        step: dict[str, object] = {}
        result = FlextLdapMixins.BusinessRulesMixin.validate_pipeline_step(step)

        assert result.is_failure
        assert result.error is not None
        assert "name" in result.error


class TestMixinsIntegration:
    """Test mixins integration and combined usage."""

    def test_validation_mixin_chain(self) -> None:
        """Test chaining multiple validation mixin calls."""
        # Validate username
        username_result = FlextLdapMixins.ValidationMixin.validate_not_empty(
            "username", "testuser"
        )
        assert username_result.is_success

        # Validate status
        status_result = FlextLdapMixins.ValidationMixin.validate_status("pending")
        assert status_result.is_success

        # Validate count
        count_result = FlextLdapMixins.ValidationMixin.validate_positive_number(
            "count", 10.0
        )
        assert count_result.is_success

    def test_factory_and_validation_integration(self) -> None:
        """Test integration of factory and validation mixins."""
        # Create successful result
        success_result: Any = FlextLdapMixins.FactoryMixin.create_flext_result_ok(
            "data"
        )
        assert success_result.is_success

        # Validate the data using validation mixin
        validation_result = FlextLdapMixins.ValidationMixin.validate_not_empty(
            "data", success_result.value
        )
        assert validation_result.is_success

    def test_business_rules_and_validation_integration(self) -> None:
        """Test integration of business rules and validation mixins."""
        # Validate command state
        state_result = (
            FlextLdapMixins.BusinessRulesMixin.validate_command_execution_state(
                current_status="pending", expected_status="pending", operation="execute"
            )
        )
        assert state_result.is_success

        # Validate status value
        status_result = FlextLdapMixins.ValidationMixin.validate_status("pending")
        assert status_result.is_success


class TestMixinErrorMessages:
    """Test mixin error message quality and consistency."""

    def test_validation_error_messages_include_field_name(self) -> None:
        """Test validation error messages include field name."""
        result = FlextLdapMixins.ValidationMixin.validate_not_empty("email", "")

        assert result.is_failure
        assert result.error is not None
        assert "email" in result.error.lower()

    def test_positive_number_error_includes_requirement(self) -> None:
        """Test positive number error includes requirement."""
        result = FlextLdapMixins.ValidationMixin.validate_positive_number("age", -5.0)

        assert result.is_failure
        assert result.error is not None
        assert "positive" in result.error.lower()

    def test_enum_error_includes_valid_values(self) -> None:
        """Test enum validation error includes valid values list."""
        valid_values = ["red", "green", "blue"]
        result = FlextLdapMixins.ValidationMixin.validate_enum_value(
            "color", "yellow", valid_values
        )

        assert result.is_failure
        assert result.error is not None
        for value in valid_values:
            assert value in result.error

    def test_pipeline_step_error_specificity(self) -> None:
        """Test pipeline step validation provides specific error."""
        step: dict[str, object] = {"name": "test"}  # Missing command
        result = FlextLdapMixins.BusinessRulesMixin.validate_pipeline_step(step)

        assert result.is_failure
        assert result.error is not None
        assert "command" in result.error.lower()
        assert "name" not in result.error.lower()  # Only missing field mentioned
