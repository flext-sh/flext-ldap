"""🔄 Migration-related LDAP Exceptions.

Exception classes for LDAP migration and data transfer errors.
"""

from __future__ import annotations

from typing import Any, Optional

from ldap_core_shared.exceptions.base import LDAPError


class MigrationError(LDAPError):
    """🔄 Exception for LDAP migration failures.

    Base class for all migration-related errors during data transfer operations.
    """

    def __init__(
        self,
        message: str,
        *,
        migration_phase: Optional[str] = None,
        source_dn: Optional[str] = None,
        target_dn: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize migration error.

        Args:
            message: Error description
            migration_phase: Phase of migration where error occurred
            source_dn: Source DN being migrated
            target_dn: Target DN in destination
            **kwargs: Additional arguments for LDAPError
        """
        context = kwargs.get("context", {})
        if migration_phase:
            context["migration_phase"] = migration_phase
        if source_dn:
            context["source_dn"] = source_dn
        if target_dn:
            context["target_dn"] = target_dn

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class MigrationValidationError(MigrationError):
    """✅ Exception for migration data validation failures."""

    def __init__(
        self,
        message: str,
        *,
        validation_rule: Optional[str] = None,
        entry_count: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize migration validation error.

        Args:
            message: Error description
            validation_rule: Validation rule that failed
            entry_count: Number of entries processed when error occurred
            **kwargs: Additional arguments for MigrationError
        """
        context = kwargs.get("context", {})
        if validation_rule:
            context["validation_rule"] = validation_rule
        if entry_count is not None:
            context["entry_count"] = entry_count

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class MigrationPerformanceError(MigrationError):
    """📊 Exception for migration performance issues."""

    def __init__(
        self,
        message: str,
        *,
        performance_metric: Optional[str] = None,
        expected_value: Optional[float] = None,
        actual_value: Optional[float] = None,
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
        context = kwargs.get("context", {})
        if performance_metric:
            context["performance_metric"] = performance_metric
        if expected_value is not None:
            context["expected_value"] = expected_value
        if actual_value is not None:
            context["actual_value"] = actual_value

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class MigrationDataError(MigrationError):
    """💾 Exception for migration data integrity issues."""

    def __init__(
        self,
        message: str,
        *,
        data_issue: Optional[str] = None,
        affected_attributes: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize migration data error.

        Args:
            message: Error description
            data_issue: Type of data issue (encoding, format, corruption, etc.)
            affected_attributes: Attributes affected by the data issue
            **kwargs: Additional arguments for MigrationError
        """
        context = kwargs.get("context", {})
        if data_issue:
            context["data_issue"] = data_issue
        if affected_attributes:
            context["affected_attributes"] = affected_attributes

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class MigrationConfigurationError(MigrationError):
    """⚙️ Exception for migration configuration issues."""

    def __init__(
        self,
        message: str,
        *,
        config_parameter: Optional[str] = None,
        config_value: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize migration configuration error.

        Args:
            message: Error description
            config_parameter: Configuration parameter that is invalid
            config_value: Invalid configuration value
            **kwargs: Additional arguments for MigrationError
        """
        context = kwargs.get("context", {})
        if config_parameter:
            context["config_parameter"] = config_parameter
        if config_value is not None:
            context["config_value"] = str(config_value)  # Convert to string for safety

        kwargs["context"] = context
        super().__init__(message, **kwargs)
