"""LDAP-specific mixins for flext-ldap library.

This module provides LDAP-specific mixin functionality extending flext-core
patterns with LDAP domain-specific behaviors.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextMixins, FlextResult


class FlextLdapMixins(FlextMixins):
    """LDAP-specific mixins extending FlextMixins.

    Provides LDAP domain-specific mixin functionality while inheriting
    all standard flext-core mixin capabilities.

    Architecture:
    - Inherits all core mixin functionality from FlextMixins
    - Adds LDAP-specific validation and processing mixins
    - Maintains single class per module pattern
    """

    class ValidationMixin:
        """LDAP validation mixin for business rule validation."""

        @staticmethod
        def validate_not_empty(field_name: str, value: str | None) -> FlextResult[None]:
            """Validate that a field is not empty.

            Args:
                field_name: Name of the field being validated
                value: Value to validate

            Returns:
                FlextResult indicating validation success or failure

            """
            if not value or not str(value).strip():
                return FlextResult[None].fail(f"{field_name} cannot be empty")
            return FlextResult[None].ok(None)

        @staticmethod
        def validate_status(status: str) -> FlextResult[None]:
            """Validate status field value.

            Args:
                status: Status value to validate

            Returns:
                FlextResult indicating validation success or failure

            """
            valid_statuses = ["pending", "running", "completed", "failed", "cancelled"]
            if status not in valid_statuses:
                return FlextResult[None].fail(
                    f"Invalid status: {status}. Must be one of {valid_statuses}"
                )
            return FlextResult[None].ok(None)

        @staticmethod
        def validate_positive_number(
            field_name: str, value: float
        ) -> FlextResult[None]:
            """Validate that a number is positive.

            Args:
                field_name: Name of the field being validated
                value: Number to validate

            Returns:
                FlextResult indicating validation success or failure

            """
            if value <= 0:
                return FlextResult[None].fail(f"{field_name} must be positive")
            return FlextResult[None].ok(None)

        @staticmethod
        def validate_non_negative_number(
            field_name: str, value: float
        ) -> FlextResult[None]:
            """Validate that a number is non-negative.

            Args:
                field_name: Name of the field being validated
                value: Number to validate

            Returns:
                FlextResult indicating validation success or failure

            """
            if value < 0:
                return FlextResult[None].fail(f"{field_name} must be non-negative")
            return FlextResult[None].ok(None)

        @staticmethod
        def validate_enum_value(
            field_name: str, value: str, valid_values: list[str]
        ) -> FlextResult[None]:
            """Validate that a value is in a list of valid enum values.

            Args:
                field_name: Name of the field being validated
                value: Value to validate
                valid_values: List of valid enum values

            Returns:
                FlextResult indicating validation success or failure

            """
            if value not in valid_values:
                return FlextResult[None].fail(
                    f"Invalid {field_name}: {value}. Must be one of {valid_values}"
                )
            return FlextResult[None].ok(None)

    class FactoryMixin:
        """Factory mixin for creating LDAP domain objects."""

        @staticmethod
        def create_flext_result_ok(value: object) -> FlextResult[object]:
            """Create a successful FlextResult.

            Args:
                value: Value to wrap in successful result

            Returns:
                FlextResult with success status

            """
            return FlextResult[object].ok(value)

        @staticmethod
        def create_flext_result_fail(error: str) -> FlextResult[object]:
            """Create a failed FlextResult.

            Args:
                error: Error message

            Returns:
                FlextResult with failure status

            """
            return FlextResult[object].fail(error)

    class BusinessRulesMixin:
        """Business rules mixin for LDAP domain logic."""

        @staticmethod
        def validate_command_execution_state(
            current_status: str,
            expected_status: str,
            operation: str,
        ) -> FlextResult[None]:
            """Validate command execution state transition.

            Args:
                current_status: Current status of the command
                expected_status: Expected status for the operation
                operation: Name of the operation being performed

            Returns:
                FlextResult indicating validation success or failure

            """
            if current_status != expected_status:
                return FlextResult[None].fail(
                    f"Cannot {operation}: expected status '{expected_status}' but got '{current_status}'"
                )
            return FlextResult[None].ok(None)

        @staticmethod
        def validate_pipeline_step(step: dict[str, object]) -> FlextResult[None]:
            """Validate pipeline step structure.

            Args:
                step: Pipeline step dictionary to validate

            Returns:
                FlextResult indicating validation success or failure

            """
            if "name" not in step:
                return FlextResult[None].fail("Step must have a 'name' field")

            if "command" not in step:
                return FlextResult[None].fail("Step must have a 'command' field")

            return FlextResult[None].ok(None)


__all__ = [
    "FlextLdapMixins",
]
