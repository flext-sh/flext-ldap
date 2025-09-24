"""LDAP-specific mixins for flext-ldap library.

This module provides LDAP-specific mixin functionality extending flext-core
patterns with LDAP domain-specific behaviors.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextHandlers, FlextMixins, FlextResult


class FlextLdapMixins(FlextMixins):
    """LDAP-specific mixins extending FlextMixins.

    Provides LDAP domain-specific mixin functionality while inheriting
    all standard flext-core mixin capabilities.

    Architecture:
    - Inherits all core mixin functionality from FlextMixins
    - Adds LDAP-specific validation and processing mixins
    - Maintains single class per module pattern
    """

    class ValidationMixin(FlextHandlers[object, FlextResult[object]]):
        """LDAP validation mixin for business rule validation."""

        @staticmethod
        def validate_not_empty(field_name: str, value: object) -> FlextResult[object]:
            """Validate that a field is not empty."""
            if value is None or (isinstance(value, str) and not value.strip()):
                return FlextResult[object].fail(f"{field_name} cannot be empty")
            return FlextResult[object].ok(value)

        @staticmethod
        def validate_status(status: str) -> FlextResult[object]:
            """Validate status value."""
            valid_statuses = ["pending", "running", "completed", "failed", "cancelled"]
            if status not in valid_statuses:
                return FlextResult[object].fail(
                    f"Invalid status: {status}. Must be one of {valid_statuses}"
                )
            return FlextResult[object].ok(status)

        @staticmethod
        def validate_positive_number(
            field_name: str, value: float
        ) -> FlextResult[object]:
            """Validate that a number is positive."""
            if value <= 0:
                return FlextResult[object].fail(f"{field_name} must be positive")
            return FlextResult[object].ok(value)

        @staticmethod
        def validate_non_negative_number(
            field_name: str, value: float
        ) -> FlextResult[object]:
            """Validate that a number is non-negative."""
            if value < 0:
                return FlextResult[object].fail(f"{field_name} must be non-negative")
            return FlextResult[object].ok(value)

        @staticmethod
        def validate_enum_value(
            field_name: str, value: str, valid_values: list[str]
        ) -> FlextResult[object]:
            """Validate that a value is in the list of valid values."""
            if value not in valid_values:
                return FlextResult[object].fail(
                    f"Invalid {field_name}: {value}. Must be one of {valid_values}"
                )
            return FlextResult[object].ok(value)

    class FactoryMixin(FlextHandlers[object, FlextResult[object]]):
        """LDAP factory mixin for object creation."""

        @staticmethod
        def create_flext_result_ok(value: object) -> FlextResult[object]:
            """Create a successful FlextResult."""
            return FlextResult[object].ok(value)

        @staticmethod
        def create_flext_result_fail(error_message: str) -> FlextResult[object]:
            """Create a failed FlextResult."""
            return FlextResult[object].fail(error_message)

    class BusinessRulesMixin(FlextHandlers[object, FlextResult[object]]):
        """LDAP business rules mixin for domain validation."""

        @staticmethod
        def validate_command_execution_state(
            current_status: str, expected_status: str, operation: str
        ) -> FlextResult[object]:
            """Validate command execution state transition."""
            if current_status != expected_status:
                return FlextResult[object].fail(
                    f"Cannot {operation} command in {current_status} state. Expected {expected_status}"
                )
            return FlextResult[object].ok(current_status)

        @staticmethod
        def validate_pipeline_step(step: dict[str, object]) -> FlextResult[object]:
            """Validate pipeline step structure."""
            if "name" not in step:
                return FlextResult[object].fail(
                    "Pipeline step missing required field: name"
                )

            if "command" not in step:
                return FlextResult[object].fail(
                    "Pipeline step missing required field: command"
                )

            return FlextResult[object].ok(step)


__all__ = [
    "FlextLdapMixins",
]
