"""🔄 Migration-related LDAP Exceptions.

Exception classes for LDAP migration and data transfer errors.
"""

from __future__ import annotations

from typing import Any, cast

# Type for error context data passed to exception constructors
ErrorContext = str, int, float, bool, list[str, dict[str, Any], None]

from ldap_core_shared.exceptions.base import LDAPError


class MigrationError(LDAPError):
    """🔄 Exception for LDAP migration failures.

    Base class for all migration-related errors during data transfer operations.
    """

    def __init__(
        self,
        message: str,
        *,
        migration_phase: str | None = None,
        source_dn: str | None = None,
        target_dn: str | None = None,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
    ) -> None:
        """Initialize migration error.

        Args:
            message: Error description
            migration_phase: Phase of migration where error occurred
            source_dn: Source DN being migrated
            target_dn: Target DN in destination
            error_code: Optional LDAP error code
            context: Additional context information
            original_error: Original exception that caused this error

        """
        final_context = context or {}
        if migration_phase:
            final_context["migration_phase"] = migration_phase
        if source_dn:
            final_context["source_dn"] = source_dn
        if target_dn:
            final_context["target_dn"] = target_dn

        super().__init__(
            message,
            error_code=error_code,
            context=final_context,
            original_error=original_error,
        )


class SchemaValidationError(MigrationError):
    """🔍 Exception for schema validation failures during migration."""

    def __init__(
        self,
        message: str,
        *,
        schema_element: str | None = None,
        validation_type: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize schema validation error.

        Args:
            message: Error description
            schema_element: Schema element that failed validation
            validation_type: Type of validation that failed
            **kwargs: Additional arguments for MigrationError

        """
        context: dict[str, Any] = cast("dict[str, Any]", kwargs.get("context", {}))
        if schema_element:
            context["schema_element"] = schema_element
        if validation_type:
            context["validation_type"] = validation_type

        super().__init__(
            message,
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )


class DataIntegrityError(MigrationError):
    """💾 Exception for data integrity issues during migration."""

    def __init__(
        self,
        message: str,
        *,
        integrity_check: str | None = None,
        expected_value: str | int | float | bool | None = None,
        actual_value: str | int | float | bool | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize data integrity error.

        Args:
            message: Error description
            integrity_check: Type of integrity check that failed
            expected_value: Expected value
            actual_value: Actual value found
            **kwargs: Additional arguments for MigrationError

        """
        context: dict[str, Any] = cast("dict[str, Any]", kwargs.get("context", {}))
        if integrity_check:
            context["integrity_check"] = integrity_check
        if expected_value is not None:
            context["expected_value"] = str(expected_value)
        if actual_value is not None:
            context["actual_value"] = str(actual_value)

        super().__init__(
            message,
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )


class PerformanceThresholdError(MigrationError):
    """⚡ Exception for performance threshold violations during migration."""

    def __init__(
        self,
        message: str,
        *,
        metric_name: str | None = None,
        threshold_value: float | None = None,
        actual_value: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize performance threshold error.

        Args:
            message: Error description
            metric_name: Name of the performance metric
            threshold_value: Performance threshold that was exceeded
            actual_value: Actual performance value
            **kwargs: Additional arguments for MigrationError

        """
        context: dict[str, Any] = cast("dict[str, Any]", kwargs.get("context", {}))
        if metric_name:
            context["metric_name"] = metric_name
        if threshold_value is not None:
            context["threshold_value"] = threshold_value
        if actual_value is not None:
            context["actual_value"] = actual_value

        super().__init__(
            message,
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )


class MigrationValidationError(MigrationError):
    """✅ Exception for migration data validation failures."""

    def __init__(
        self,
        message: str,
        *,
        validation_rule: str | None = None,
        entry_count: int | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize migration validation error.

        Args:
            message: Error description
            validation_rule: Validation rule that failed
            entry_count: Number of entries processed when error occurred
            **kwargs: Additional arguments for MigrationError

        """
        context: dict[str, Any] = cast("dict[str, Any]", kwargs.get("context", {}))
        if validation_rule:
            context["validation_rule"] = validation_rule
        if entry_count is not None:
            context["entry_count"] = entry_count

        super().__init__(
            message,
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )


class MigrationPerformanceError(MigrationError):
    """📊 Exception for migration performance issues."""

    def __init__(
        self,
        message: str,
        *,
        performance_metric: str | None = None,
        expected_value: float | None = None,
        actual_value: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize migration performance error.

        Args:
            message: Error description
            performance_metric: Metric that failed (entries/sec, memory usage, etc.)
            expected_value: Expected performance value
            actual_value: Actual performance value
            **kwargs: Additional arguments for MigrationError

        """
        context: dict[str, Any] = cast("dict[str, Any]", kwargs.get("context", {}))
        if performance_metric:
            context["performance_metric"] = performance_metric
        if expected_value is not None:
            context["expected_value"] = expected_value
        if actual_value is not None:
            context["actual_value"] = actual_value

        super().__init__(
            message,
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )


class MigrationDataError(MigrationError):
    """💾 Exception for migration data integrity issues."""

    def __init__(
        self,
        message: str,
        *,
        data_issue: str | None = None,
        affected_attributes: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize migration data error.

        Args:
            message: Error description
            data_issue: Type of data issue (encoding, format, corruption, etc.)
            affected_attributes: Attributes affected by the data issue
            **kwargs: Additional arguments for MigrationError

        """
        context: dict[str, Any] = cast("dict[str, Any]", kwargs.get("context", {}))
        if data_issue:
            context["data_issue"] = data_issue
        if affected_attributes:
            context["affected_attributes"] = affected_attributes

        super().__init__(
            message,
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )


class MigrationConfigurationError(MigrationError):
    """⚙️ Exception for migration configuration issues."""

    def __init__(
        self,
        message: str,
        *,
        config_parameter: str | None = None,
        config_value: str | int | float | bool | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize migration configuration error.

        Args:
            message: Error description
            config_parameter: Configuration parameter that is invalid
            config_value: Invalid configuration value
            **kwargs: Additional arguments for MigrationError

        """
        context: dict[str, Any] = cast("dict[str, Any]", kwargs.get("context", {}))
        if config_parameter:
            context["config_parameter"] = config_parameter
        if config_value is not None:
            context["config_value"] = str(config_value)  # Convert to string for safety

        super().__init__(
            message,
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )
