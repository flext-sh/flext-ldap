"""Configuration management for flext-ldap.

This module provides LDAP configuration management with environment
variable support, validation, and singleton patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import ClassVar, Self, cast, final

from pydantic import (
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import SettingsConfigDict

from flext_core import (
    FlextConfig,
    FlextConstants,
    FlextLogger,
    FlextModels,
    FlextResult,
)
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapLoggingConstants:
    """LDAP-specific logging constants for FLEXT LDAP module.

    Provides domain-specific logging defaults, levels, and configuration
    options tailored for LDAP operations, directory access, and LDAP
    performance monitoring.
    """

    # LDAP-specific log levels
    DEFAULT_LEVEL = FlextConstants.Config.LogLevel.WARNING
    CONNECTION_LEVEL = FlextConstants.Config.LogLevel.INFO
    QUERY_LEVEL = FlextConstants.Config.LogLevel.DEBUG
    AUTHENTICATION_LEVEL = FlextConstants.Config.LogLevel.INFO
    MODIFICATION_LEVEL = FlextConstants.Config.LogLevel.INFO
    ERROR_LEVEL = FlextConstants.Config.LogLevel.ERROR

    # Connection logging
    LOG_CONNECTION_ATTEMPTS = True
    LOG_CONNECTION_SUCCESS = True
    LOG_CONNECTION_FAILURES = True
    LOG_CONNECTION_CLOSURES = True
    LOG_CONNECTION_POOL_EVENTS = True
    LOG_CONNECTION_TIMEOUTS = True

    # Query and search logging
    LOG_SEARCH_OPERATIONS = True
    LOG_SEARCH_FILTERS = False  # Don't log search filters by default (privacy)
    LOG_SEARCH_RESULTS_COUNT = True
    LOG_SEARCH_DURATION = True
    LOG_LARGE_RESULT_SETS = True
    LARGE_RESULT_SET_THRESHOLD = 1000

    # Authentication logging
    LOG_AUTHENTICATION_ATTEMPTS = True
    LOG_AUTHENTICATION_SUCCESS = True
    LOG_AUTHENTICATION_FAILURES = True
    LOG_AUTHENTICATION_ERRORS = True
    MASK_PASSWORDS = True
    MASK_BIND_DN = False  # Log bind DN for debugging

    # Modification logging
    LOG_ADD_OPERATIONS = True
    LOG_MODIFY_OPERATIONS = True
    LOG_DELETE_OPERATIONS = True
    LOG_MODIFY_ATTRIBUTES = False  # Don't log modified attributes by default (privacy)
    LOG_MODIFY_VALUES = False  # Don't log modified values by default (privacy)

    # Performance tracking
    TRACK_LDAP_PERFORMANCE = True
    LDAP_PERFORMANCE_THRESHOLD_WARNING = 1000.0  # 1 second
    LDAP_PERFORMANCE_THRESHOLD_CRITICAL = 5000.0  # 5 seconds
    TRACK_CONNECTION_POOL_USAGE = True
    TRACK_QUERY_COMPLEXITY = True

    # Error logging specifics
    LOG_LDAP_ERRORS = True
    LOG_VALIDATION_ERRORS = True
    LOG_TIMEOUT_ERRORS = True
    LOG_CONNECTION_ERRORS = True
    LOG_QUERY_ERRORS = True

    # Context information to include
    INCLUDE_VALUES_IN_LOGS = False
    INCLUDE_FILTERS_IN_LOGS = False
    INCLUDE_CONTROLS_IN_LOGS = False
    INCLUDE_TIMING_IN_LOGS = True
    INCLUDE_CONNECTION_INFO_IN_LOGS = True
    INCLUDE_USER_INFO_IN_LOGS = True
    INCLUDE_SERVER_INFO_IN_LOGS = True
    MASK_SENSITIVE_DATA = True
    MASK_ATTRIBUTES = False
    MASK_VALUES = True
    USE_STANDARD_TEMPLATES = True
    CUSTOM_LOG_FORMAT = ""
    ENABLE_AUDIT_LOGGING = True
    AUDIT_LOG_LEVEL = FlextConstants.Config.LogLevel.INFO
    INCLUDE_CONNECTION_ID = True
    INCLUDE_OPERATION_ID = True
    INCLUDE_USER_DN = True
    INCLUDE_BASE_DN = True
    INCLUDE_SCOPE = True
    INCLUDE_ATTRIBUTES = False  # Don't include attributes by default (privacy)

    # Security logging
    LOG_ACCESS_CONTROL_VIOLATIONS = True
    LOG_PERMISSION_DENIED = True
    LOG_SUSPICIOUS_QUERIES = True
    LOG_BULK_OPERATIONS = True
    BULK_OPERATION_THRESHOLD = 100

    # Additional logging constants referenced in config
    LOG_LDAP_QUERIES = True
    LOG_LDAP_RESPONSES = True
    STRUCTURED_LOGGING = True
    LOG_CONNECTION_EVENTS = True
    LOG_BIND_ATTEMPTS = True
    LOG_SEARCH_RESULTS = True
    LOG_COMPARE_OPERATIONS = True
    LOG_LDAP_WARNINGS = True
    LOG_LDAP_EXCEPTIONS = True
    LOG_LDAP_TIMEOUTS = True
    LOG_LDAP_RETRIES = True
    LOG_LDAP_PERFORMANCE = True
    LOG_LDAP_CONNECTIONS = True
    LOG_LDAP_DISCONNECTIONS = True
    LOG_LDAP_POOL_EVENTS = True
    LOG_LDAP_CACHE_EVENTS = True
    LOG_LDAP_SSL_EVENTS = True
    LOG_LDAP_AUTHENTICATION = True
    LOG_LDAP_AUTHORIZATION = True
    LOG_LDAP_AUDIT = True
    LOG_LDAP_SECURITY = True
    LOG_LDAP_COMPLIANCE = True
    ENVIRONMENT_SPECIFIC_LOGGING = True
    AUDIT_LOG_FILE = "/var/log/flext-ldap/audit.log"
    INCLUDE_DN_IN_LOGS = True
    INCLUDE_ATTRIBUTES_IN_LOGS = False

    # Message templates for LDAP operations
    class Messages:
        """LDAP-specific log message templates."""

        # Connection messages
        CONNECTION_ATTEMPT = "LDAP connection attempt to {server}:{port}"
        CONNECTION_SUCCESS = "LDAP connection established to {server}:{port}"
        CONNECTION_FAILED = "LDAP connection failed to {server}:{port}: {error}"
        CONNECTION_CLOSED = "LDAP connection closed to {server}:{port}"
        CONNECTION_TIMEOUT = "LDAP connection timeout to {server}:{port}"

        # Authentication messages
        AUTH_ATTEMPT = "LDAP authentication attempt for user: {user_dn}"
        AUTH_SUCCESS = "LDAP authentication successful for user: {user_dn}"
        AUTH_FAILED = "LDAP authentication failed for user: {user_dn}: {error}"
        AUTH_ERROR = "LDAP authentication error for user: {user_dn}: {error}"

        # Search messages
        SEARCH_STARTED = (
            "LDAP search started: base={base_dn} scope={scope} filter={filter}"
        )
        SEARCH_COMPLETED = (
            "LDAP search completed: {result_count} results in {duration}ms"
        )
        SEARCH_FAILED = "LDAP search failed: {error}"
        LARGE_RESULT_SET = (
            "LDAP search returned large result set: {result_count} results"
        )

        # Modification messages
        ADD_OPERATION = "LDAP add operation: dn={dn}"
        ADD_SUCCESS = "LDAP add successful: dn={dn}"
        ADD_FAILED = "LDAP add failed: dn={dn} error: {error}"

        MODIFY_OPERATION = "LDAP modify operation: dn={dn}"
        MODIFY_SUCCESS = "LDAP modify successful: dn={dn}"
        MODIFY_FAILED = "LDAP modify failed: dn={dn} error: {error}"

        DELETE_OPERATION = "LDAP delete operation: dn={dn}"
        DELETE_SUCCESS = "LDAP delete successful: dn={dn}"
        DELETE_FAILED = "LDAP delete failed: dn={dn} error: {error}"

        # Performance messages
        SLOW_OPERATION = "Slow LDAP operation: {operation} took {duration}ms"
        SLOW_SEARCH = "Slow LDAP search: {filter} took {duration}ms"
        HIGH_CONNECTION_USAGE = "High LDAP connection pool usage: {used}/{total}"

        # Error messages
        LDAP_ERROR = "LDAP error: {error_code} {error_message}"
        VALIDATION_ERROR = "LDAP validation error: {field} {error}"
        TIMEOUT_ERROR = "LDAP timeout error: {operation} exceeded {timeout}ms"
        CONNECTION_ERROR = "LDAP connection error: {error}"

        # Security messages
        ACCESS_DENIED = "LDAP access denied: {user_dn} {operation} {dn}"
        PERMISSION_DENIED = "LDAP permission denied: {user_dn} {operation}"
        SUSPICIOUS_QUERY = "Suspicious LDAP query: {user_dn} {filter}"
        BULK_OPERATION = "LDAP bulk operation detected: {operation} {count} entries"

    # Environment-specific overrides for LDAP logging
    class Environment:
        """Environment-specific LDAP logging configuration."""

        DEVELOPMENT: ClassVar[dict[str, object]] = {
            "log_search_filters": True,  # Log search filters in dev
            "log_modify_attributes": True,  # Log modified attributes in dev
            "log_modify_values": True,  # Log modified values in dev
            "include_attributes": True,  # Include attributes in dev
            "audit_log_level": FlextConstants.Config.LogLevel.DEBUG,
        }

        STAGING: ClassVar[dict[str, object]] = {
            "log_search_filters": False,
            "log_modify_attributes": False,
            "log_modify_values": False,
            "include_attributes": False,
            "audit_log_level": FlextConstants.Config.LogLevel.INFO,
        }

        PRODUCTION: ClassVar[dict[str, object]] = {
            "log_search_filters": False,
            "log_modify_attributes": False,
            "log_modify_values": False,
            "include_attributes": False,
            "audit_log_level": FlextConstants.Config.LogLevel.WARNING,
        }

        TESTING: ClassVar[dict[str, object]] = {
            "log_search_filters": True,
            "log_modify_attributes": True,
            "log_modify_values": True,
            "include_attributes": True,
            "audit_log_level": FlextConstants.Config.LogLevel.DEBUG,
        }


@final
class FlextLdapConfigs(FlextConfig):
    """FLEXT-LDAP Configuration singleton extending FlextConfig with LDAP-specific fields.

    This class provides a singleton configuration instance for LDAP operations,
    extending the base FlextConfig with LDAP-specific fields and validation rules.
    It serves as the single source of truth for LDAP configuration across the
    entire flext-ldap library.

    Features:
    - SINGLETON GLOBAL INSTANCE - One source of truth for LDAP configuration
    - LDAP-specific fields with proper validation
    - Environment variable integration with FLEXT_LDAP_ prefix
    - Parameter override support for runtime behavior changes
    - Clean Architecture integration with flext-core patterns
    - Unified type definitions within the class
    """

    # Pydantic model configuration
    model_config = SettingsConfigDict(
        env_prefix="FLEXT_LDAP_",
        env_file_encoding="utf-8",
        extra="ignore",  # Allow extra environment variables from other projects
        case_sensitive=False,
        arbitrary_types_allowed=True,
        populate_by_name=True,
        validate_assignment=True,
        use_enum_values=True,
    )

    # SINGLETON pattern implementation - use global instance
    _global_instance: ClassVar[FlextConfig | None] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    # === TYPE DEFINITIONS (CONSOLIDATED) ===
    # These replace the loose type aliases from module level
    class Types:
        """Unified type definitions for LDAP configuration."""

        ConfigDict = dict[str, object]
        ConnectionName = str
        ConfigPath = str | Path

    # LDAP configuration fields using FlextLdapModels.ConnectionConfig directly

    # === LDAP CONNECTION CONFIGURATION ===
    # Connection to LDAP servers (can be a single or multiple connections)
    ldap_default_connection: FlextLdapModels.ConnectionConfig | None = Field(
        default=None,
        description="Default LDAP connection configuration",
        alias="ldap_connection",
    )

    # Bind DN and password for authentication (if not provided in connection config)
    ldap_bind_dn: str | None = Field(
        default=None,
        description="LDAP bind distinguished name for authentication",
        alias="bind_dn",
    )
    ldap_bind_password: SecretStr | None = Field(
        default=None,
        description="LDAP bind password for authentication",
        alias="bind_password",
    )

    # SSL/TLS configuration
    ldap_use_ssl: bool = Field(
        default=True,
        description="Use SSL/TLS for LDAP connections",
        alias="use_ssl",
    )
    ldap_verify_certificates: bool = Field(
        default=True,
        description="Verify SSL/TLS certificates",
        alias="verify_certificates",
    )

    # === LDAP BEHAVIOR CONFIGURATION ===
    # Debug and logging
    ldap_enable_debug: bool = Field(
        default=False,
        description="Enable debug mode for LDAP operations",
        alias="debug",
    )
    # Debug and logging - using FlextLdapLoggingConstants as SOURCE OF TRUTH
    ldap_log_queries: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_QUERIES,
        description="Log LDAP queries",
        alias="log_queries",
    )
    ldap_log_responses: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_RESPONSES,
        description="Log LDAP responses",
        alias="log_responses",
    )
    ldap_structured_logging: bool = Field(
        default=FlextLdapLoggingConstants.STRUCTURED_LOGGING,
        description="Use structured logging for LDAP operations",
        alias="structured_logging",
    )

    # Additional LDAP-specific logging fields using FlextLdapLoggingConstants
    log_connection_events: bool = Field(
        default=FlextLdapLoggingConstants.LOG_CONNECTION_EVENTS,
        description="Log LDAP connection events",
    )

    log_bind_attempts: bool = Field(
        default=FlextLdapLoggingConstants.LOG_BIND_ATTEMPTS,
        description="Log LDAP bind attempts",
    )

    log_search_operations: bool = Field(
        default=FlextLdapLoggingConstants.LOG_SEARCH_OPERATIONS,
        description="Log LDAP search operations",
    )

    log_search_filters: bool = Field(
        default=FlextLdapLoggingConstants.LOG_SEARCH_FILTERS,
        description="Log LDAP search filters",
    )

    log_search_results: bool = Field(
        default=FlextLdapLoggingConstants.LOG_SEARCH_RESULTS,
        description="Log LDAP search results",
    )

    log_modify_operations: bool = Field(
        default=FlextLdapLoggingConstants.LOG_MODIFY_OPERATIONS,
        description="Log LDAP modify operations",
    )

    log_modify_attributes: bool = Field(
        default=FlextLdapLoggingConstants.LOG_MODIFY_ATTRIBUTES,
        description="Log modified attributes",
    )

    log_modify_values: bool = Field(
        default=FlextLdapLoggingConstants.LOG_MODIFY_VALUES,
        description="Log modified values",
    )

    log_add_operations: bool = Field(
        default=FlextLdapLoggingConstants.LOG_ADD_OPERATIONS,
        description="Log LDAP add operations",
    )

    log_delete_operations: bool = Field(
        default=FlextLdapLoggingConstants.LOG_DELETE_OPERATIONS,
        description="Log LDAP delete operations",
    )

    log_compare_operations: bool = Field(
        default=FlextLdapLoggingConstants.LOG_COMPARE_OPERATIONS,
        description="Log LDAP compare operations",
    )

    log_ldap_errors: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_ERRORS,
        description="Log LDAP errors",
    )

    log_ldap_warnings: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_WARNINGS,
        description="Log LDAP warnings",
    )

    log_ldap_exceptions: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_EXCEPTIONS,
        description="Log LDAP exceptions",
    )

    log_ldap_timeouts: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_TIMEOUTS,
        description="Log LDAP timeouts",
    )

    log_ldap_retries: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_RETRIES,
        description="Log LDAP retry attempts",
    )

    log_ldap_performance: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_PERFORMANCE,
        description="Log LDAP performance metrics",
    )

    log_ldap_connections: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_CONNECTIONS,
        description="Log LDAP connection details",
    )

    log_ldap_disconnections: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_DISCONNECTIONS,
        description="Log LDAP disconnection events",
    )

    log_ldap_pool_events: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_POOL_EVENTS,
        description="Log LDAP connection pool events",
    )

    log_ldap_cache_events: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_CACHE_EVENTS,
        description="Log LDAP cache events",
    )

    log_ldap_ssl_events: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_SSL_EVENTS,
        description="Log LDAP SSL/TLS events",
    )

    log_ldap_authentication: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_AUTHENTICATION,
        description="Log LDAP authentication events",
    )

    log_ldap_authorization: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_AUTHORIZATION,
        description="Log LDAP authorization events",
    )

    log_ldap_audit: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_AUDIT,
        description="Log LDAP audit events",
    )

    log_ldap_security: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_SECURITY,
        description="Log LDAP security events",
    )

    log_ldap_compliance: bool = Field(
        default=FlextLdapLoggingConstants.LOG_LDAP_COMPLIANCE,
        description="Log LDAP compliance events",
    )

    # Performance tracking for LDAP operations
    track_ldap_performance: bool = Field(
        default=FlextLdapLoggingConstants.TRACK_LDAP_PERFORMANCE,
        description="Track LDAP performance metrics",
    )

    ldap_performance_threshold_warning: float = Field(
        default=FlextLdapLoggingConstants.LDAP_PERFORMANCE_THRESHOLD_WARNING,
        description="LDAP performance warning threshold in milliseconds",
    )

    ldap_performance_threshold_critical: float = Field(
        default=FlextLdapLoggingConstants.LDAP_PERFORMANCE_THRESHOLD_CRITICAL,
        description="LDAP performance critical threshold in milliseconds",
    )

    # Context information to include in logs
    include_dn_in_logs: bool = Field(
        default=FlextLdapLoggingConstants.INCLUDE_DN_IN_LOGS,
        description="Include DN in log messages",
    )

    include_attributes_in_logs: bool = Field(
        default=FlextLdapLoggingConstants.INCLUDE_ATTRIBUTES_IN_LOGS,
        description="Include attributes in log messages",
    )

    include_values_in_logs: bool = Field(
        default=FlextLdapLoggingConstants.INCLUDE_VALUES_IN_LOGS,
        description="Include values in log messages",
    )

    include_filters_in_logs: bool = Field(
        default=FlextLdapLoggingConstants.INCLUDE_FILTERS_IN_LOGS,
        description="Include filters in log messages",
    )

    include_controls_in_logs: bool = Field(
        default=FlextLdapLoggingConstants.INCLUDE_CONTROLS_IN_LOGS,
        description="Include controls in log messages",
    )

    include_timing_in_logs: bool = Field(
        default=FlextLdapLoggingConstants.INCLUDE_TIMING_IN_LOGS,
        description="Include timing information in log messages",
    )

    include_connection_info_in_logs: bool = Field(
        default=FlextLdapLoggingConstants.INCLUDE_CONNECTION_INFO_IN_LOGS,
        description="Include connection information in log messages",
    )

    include_user_info_in_logs: bool = Field(
        default=FlextLdapLoggingConstants.INCLUDE_USER_INFO_IN_LOGS,
        description="Include user information in log messages",
    )

    include_server_info_in_logs: bool = Field(
        default=FlextLdapLoggingConstants.INCLUDE_SERVER_INFO_IN_LOGS,
        description="Include server information in log messages",
    )

    # Security and privacy settings
    mask_sensitive_data: bool = Field(
        default=FlextLdapLoggingConstants.MASK_SENSITIVE_DATA,
        description="Mask sensitive data in logs",
    )

    mask_passwords: bool = Field(
        default=FlextLdapLoggingConstants.MASK_PASSWORDS,
        description="Mask passwords in logs",
    )

    mask_attributes: bool = Field(
        default=FlextLdapLoggingConstants.MASK_ATTRIBUTES,
        description="Mask sensitive attributes in logs",
    )

    mask_values: bool = Field(
        default=FlextLdapLoggingConstants.MASK_VALUES,
        description="Mask sensitive values in logs",
    )

    # Log message templates
    use_standard_templates: bool = Field(
        default=FlextLdapLoggingConstants.USE_STANDARD_TEMPLATES,
        description="Use standard log message templates",
    )

    custom_log_format: str | None = Field(
        default=FlextLdapLoggingConstants.CUSTOM_LOG_FORMAT,
        description="Custom log message format",
    )

    # Audit logging
    enable_audit_logging: bool = Field(
        default=FlextLdapLoggingConstants.ENABLE_AUDIT_LOGGING,
        description="Enable audit logging",
    )

    audit_log_level: str = Field(
        default=FlextLdapLoggingConstants.AUDIT_LOG_LEVEL,
        description="Audit log level",
    )

    audit_log_file: str = Field(
        default=FlextLdapLoggingConstants.AUDIT_LOG_FILE,
        description="Audit log file path",
    )

    # Environment-specific logging
    environment_specific_logging: bool = Field(
        default=FlextLdapLoggingConstants.ENVIRONMENT_SPECIFIC_LOGGING,
        description="Enable environment-specific logging",
    )

    # Caching - using FlextConstants as SOURCE OF TRUTH
    ldap_enable_caching: bool = Field(
        default=False,  # Keep as False for LDAP safety
        description="Enable caching for LDAP operations",
        alias="enable_caching",
    )
    ldap_cache_ttl: int = Field(
        default=FlextConstants.Defaults.TIMEOUT * 10,  # 300 seconds
        description="Cache time-to-live in seconds",
        alias="cache_ttl",
        ge=0,
    )

    # === LDAP OPERATION LIMITS ===
    # Search limits - using FlextConstants as SOURCE OF TRUTH
    ldap_size_limit: int = Field(
        default=FlextConstants.Defaults.PAGE_SIZE * 10,  # 1000
        description="Maximum number of entries to return in search",
        alias="size_limit",
        ge=0,
    )
    ldap_time_limit: int = Field(
        default=FlextConstants.Network.DEFAULT_TIMEOUT,
        description="Maximum time in seconds for search operations",
        alias="time_limit",
        ge=0,
    )
    ldap_page_size: int = Field(
        default=FlextConstants.Defaults.PAGE_SIZE,
        description="Page size for paged searches",
        alias="page_size",
        ge=1,
        le=1000,
    )

    # Connection pool settings - using FlextConstants as SOURCE OF TRUTH
    ldap_pool_size: int = Field(
        default=FlextConstants.Container.DEFAULT_WORKERS * 5,  # 10
        description="Maximum number of connections in pool",
        alias="pool_size",
        ge=1,
        le=100,
    )
    ldap_pool_timeout: int = Field(
        default=FlextConstants.Network.DEFAULT_TIMEOUT,
        description="Timeout for getting connection from pool (seconds)",
        alias="pool_timeout",
        ge=1,
    )

    # Retry configuration - using FlextConstants as SOURCE OF TRUTH
    ldap_retry_attempts: int = Field(
        default=FlextConstants.Reliability.MAX_RETRY_ATTEMPTS,
        description="Number of retry attempts for failed operations",
        alias="retry_attempts",
        ge=0,
        le=10,
    )
    ldap_retry_delay: int = Field(
        default=1,  # Keep as 1 second for LDAP responsiveness
        description="Delay between retry attempts (seconds)",
        alias="retry_delay",
        ge=0,
        le=60,
    )
    ldap_enable_test_mode: bool = Field(
        default=False,
        description="Enable test mode for LDAP operations",
        alias="enable_test_mode",
    )

    # === VALIDATION METHODS ===
    @field_validator("ldap_bind_dn")
    @classmethod
    def validate_bind_dn(cls, value: str | None) -> str | None:
        """Validate bind DN format if provided.

        Returns:
            str | None: The validated bind DN or None if not provided.

        Raises:
            ValueError: If the bind DN format is invalid.

        """
        if value is None:
            return value

        # Basic DN validation using value objects
        dn_result = FlextLdapModels.ValueObjects.DistinguishedName.create(value)
        if dn_result.is_failure:
            msg = f"Invalid LDAP bind DN format: {value}"
            raise ValueError(msg)

        return value

    @model_validator(mode="after")
    def validate_configuration_consistency(self) -> Self:
        """Validate configuration consistency and business rules.

        Returns:
            Self: The validated configuration instance.

        Raises:
            ValueError: If configuration validation fails.

        """
        # Validation 1: Connection configuration consistency
        if self.ldap_default_connection is None:
            # Create default connection if not provided
            default_server = FlextLdapConstants.Protocol.DEFAULT_SERVER_URI
            try:
                self.ldap_default_connection = FlextLdapModels.ConnectionConfig(
                    server=default_server,
                )
            except Exception as e:
                msg = f"Failed to create default LDAP connection: {e}"
                raise ValueError(msg) from e

        # Validation 2: Caching configuration
        if self.ldap_enable_caching and self.ldap_cache_ttl <= 0:
            msg = "Cache TTL must be positive when caching is enabled"
            raise ValueError(msg)

        # Validation 3: Pool configuration
        if self.ldap_pool_size <= 0:
            msg = "Pool size must be positive"
            raise ValueError(msg)

        # Validation 4: Retry configuration
        if self.ldap_retry_attempts > 0 and self.ldap_retry_delay < 0:
            msg = "Retry delay must be non-negative when retries are enabled"
            raise ValueError(msg)

        return self

    # === SINGLETON PATTERN IMPLEMENTATION ===
    @classmethod
    def get_global_instance(cls) -> FlextLdapConfigs:
        """Get or create the global singleton instance.

        Returns:
            The global FlextLdapConfigs instance

        """
        if cls._global_instance is None:
            with cls._lock:
                if cls._global_instance is None:
                    cls._global_instance = cls()
        # Type cast is safe since we ensure it's FlextLdapConfigs
        return cast("FlextLdapConfigs", cls._global_instance)

    @classmethod
    def set_global_instance(cls, config: FlextConfig) -> None:
        """Set the global singleton instance.

        Args:
            config: New FlextConfig instance to set as global

        Raises:
            TypeError: If config is not a FlextLdapConfigs instance.

        """
        if not isinstance(config, FlextLdapConfigs):
            msg = f"Expected FlextLdapConfigs, got {type(config)}"
            raise TypeError(msg)
        with cls._lock:
            cls._global_instance = config

    @classmethod
    def reset_global_instance(cls) -> None:
        """Reset the global singleton instance (mainly for testing)."""
        with cls._lock:
            cls._global_instance = None

    # === BUSINESS LOGIC VALIDATION ===
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDAP configuration business rules.

        Returns:
            FlextResult indicating validation success or failure

        """
        try:
            # Rule 1: Connection configuration must be valid
            if self.ldap_default_connection is None:
                return FlextResult[None].fail("Default LDAP connection is required")

            # Rule 2: If authentication is configured, both DN and password are needed
            if self.ldap_bind_dn is not None and self.ldap_bind_password is None:
                return FlextResult[None].fail(
                    "Bind password is required when bind DN is specified",
                )

            # Rule 3: Cache TTL must be reasonable
            max_cache_ttl = 3600  # 1 hour
            if self.ldap_enable_caching and self.ldap_cache_ttl > max_cache_ttl:
                return FlextResult[None].fail(
                    f"Cache TTL cannot exceed {max_cache_ttl} seconds",
                )

            # Rule 4: Pool size must be reasonable for environment
            max_pool_size = 50
            if self.ldap_pool_size > max_pool_size:
                return FlextResult[None].fail(
                    f"Pool size cannot exceed {max_pool_size}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Configuration validation failed: {e}")

    # === UTILITY METHODS ===
    def get_effective_server_uri(self) -> str:
        """Get the effective server URI for LDAP connections.

        Returns:
            The effective server URI

        """
        if self.ldap_default_connection and self.ldap_default_connection.server:
            return self.ldap_default_connection.server
        return FlextLdapConstants.Protocol.DEFAULT_SERVER_URI

    def get_effective_bind_dn(self) -> str | None:
        """Get the effective bind DN for authentication.

        Returns:
            The effective bind DN or None

        """
        return self.ldap_bind_dn

    def get_effective_bind_password(self) -> str | None:
        """Get the effective bind password for authentication.

        Returns:
            The effective bind password or None

        """
        return (
            self.ldap_bind_password.get_secret_value()
            if self.ldap_bind_password
            else None
        )

    def is_ssl_enabled(self) -> bool:
        """Check if SSL/TLS is enabled.

        Returns:
            True if SSL/TLS is enabled

        """
        return self.ldap_use_ssl

    def is_debug_enabled(self) -> bool:
        """Check if debug mode is enabled.

        Returns:
            True if debug mode is enabled

        """
        return self.ldap_enable_debug

    @classmethod
    def create_development_ldap_config(
        cls,
        **overrides: str | float | bool | None,
    ) -> FlextResult[FlextLdapConfigs]:
        """Create development LDAP configuration with appropriate defaults.

        Args:
            **overrides: Additional configuration overrides

        Returns:
            FlextResult containing development configuration

        """
        try:
            # Create config data with typed values
            config_data: dict[str, object] = {
                "environment": "development",
                "debug": True,
                "ldap_enable_debug": True,
                "ldap_log_queries": True,
                "ldap_log_responses": True,
                "ldap_enable_caching": False,
                "ldap_verify_certificates": False,
                "ldap_size_limit": 1000,
                "ldap_time_limit": 60,
            }

            # Apply overrides if any
            if overrides:
                config_data.update(overrides)

            # Use model_validate for proper type handling
            config = cls.model_validate(config_data)
            return FlextResult[FlextLdapConfigs].ok(config)
        except Exception as e:
            return FlextResult["FlextLdapConfigs"].fail(
                f"Failed to create development config: {e}",
            )

    @classmethod
    def create_test_ldap_config(
        cls,
        **overrides: str | float | bool | None,
    ) -> FlextResult[FlextLdapConfigs]:
        """Create test LDAP configuration with appropriate defaults.

        Args:
            **overrides: Additional configuration overrides

        Returns:
            FlextResult containing test configuration

        """
        try:
            # Create config data with typed values
            config_data: dict[str, object] = {
                "environment": "test",
                "debug": False,
                "ldap_enable_debug": False,
                "ldap_log_queries": False,
                "ldap_log_responses": False,
                "ldap_enable_caching": False,
                "ldap_verify_certificates": False,
                "ldap_size_limit": 500,
                "ldap_time_limit": 30,
                "ldap_enable_test_mode": True,
            }

            # Apply overrides if any
            if overrides:
                config_data.update(overrides)

            # Use model_validate for proper type handling
            config = cls.model_validate(config_data)
            return FlextResult[FlextLdapConfigs].ok(config)
        except Exception as e:
            return FlextResult["FlextLdapConfigs"].fail(
                f"Failed to create test config: {e}",
            )

    @classmethod
    def create_production_ldap_config(
        cls,
        **overrides: dict[str, object],
    ) -> FlextResult[FlextLdapConfigs]:
        """Create production LDAP configuration with appropriate defaults.

        Args:
            **overrides: Additional configuration overrides

        Returns:
            FlextResult containing production configuration

        """
        try:
            production_defaults: dict[str, object] = {
                "environment": "production",
                "debug": False,
                "ldap_enable_debug": False,
                "ldap_log_queries": False,
                "ldap_log_responses": False,
                "ldap_enable_caching": True,  # Enable caching in production
                "ldap_cache_ttl": 3600,  # 1 hour cache
                "ldap_verify_certificates": True,  # Strict SSL in production
                "ldap_size_limit": 5000,  # Higher limits for production
                "ldap_time_limit": 120,
                "ldap_pool_size": 10,  # Connection pooling
            }
            production_defaults.update(overrides)
            config = cls.model_validate(production_defaults)
            return FlextResult["FlextLdapConfigs"].ok(config)
        except Exception as e:
            return FlextResult["FlextLdapConfigs"].fail(
                f"Failed to create production config: {e}",
            )

    def apply_ldap_overrides(self, overrides: dict[str, object]) -> FlextResult[None]:
        """Apply LDAP configuration overrides to current instance.

        Args:
            overrides: Dictionary of configuration overrides

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # Map override keys to actual field names
            field_mapping = {
                "size_limit": "ldap_size_limit",
                "time_limit": "ldap_time_limit",
                "enable_caching": "ldap_enable_caching",
                "cache_ttl": "ldap_cache_ttl",
                "log_queries": "ldap_log_queries",
                "log_responses": "ldap_log_responses",
                "structured_logging": "ldap_structured_logging",
                "enable_debug": "ldap_enable_debug",
                "verify_certificates": "ldap_verify_certificates",
                "use_ssl": "ldap_use_ssl",
                "pool_size": "ldap_pool_size",
                "page_size": "ldap_page_size",
                "retry_attempts": "ldap_retry_attempts",
                "retry_delay": "ldap_retry_delay",
            }

            # Apply overrides using setattr
            for key, value in overrides.items():
                field_name = field_mapping.get(key, key)
                if hasattr(self, field_name):
                    setattr(self, field_name, value)
                # Try direct field name for non-mapped fields
                elif hasattr(self, key):
                    setattr(self, key, value)
                else:
                    return FlextResult[None].fail(f"Unknown configuration field: {key}")

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Failed to apply overrides: {e}")

    def get_ldap_search_config(self) -> dict[str, object]:
        """Get LDAP search-related configuration.

        Returns:
            Dictionary containing search configuration

        """
        return {
            "size_limit": self.ldap_size_limit,
            "time_limit": self.ldap_time_limit,
            "page_size": self.ldap_page_size,
        }

    def get_ldap_performance_config(self) -> dict[str, object]:
        """Get LDAP performance-related configuration.

        Returns:
            Dictionary containing performance configuration

        """
        return {
            "enable_caching": self.ldap_enable_caching,
            "cache_ttl": self.ldap_cache_ttl,
            "pool_size": self.ldap_pool_size,
            "pool_timeout": self.ldap_pool_timeout,
            "retry_attempts": self.ldap_retry_attempts,
            "retry_delay": self.ldap_retry_delay,
        }

    def get_ldap_logging_config(self) -> dict[str, object]:
        """Get LDAP logging-related configuration.

        Returns:
            Dictionary containing logging configuration

        """
        return {
            "log_queries": self.ldap_log_queries,
            "log_responses": self.ldap_log_responses,
            "structured_logging": self.ldap_structured_logging,
            "enable_debug": self.ldap_enable_debug,
            "log_connection_events": self.log_connection_events,
            "log_bind_attempts": self.log_bind_attempts,
            "log_search_operations": self.log_search_operations,
            "log_search_filters": self.log_search_filters,
            "log_search_results": self.log_search_results,
            "log_modify_operations": self.log_modify_operations,
            "log_modify_attributes": self.log_modify_attributes,
            "log_modify_values": self.log_modify_values,
            "log_add_operations": self.log_add_operations,
            "log_delete_operations": self.log_delete_operations,
            "log_compare_operations": self.log_compare_operations,
            "log_ldap_errors": self.log_ldap_errors,
            "log_ldap_warnings": self.log_ldap_warnings,
            "log_ldap_exceptions": self.log_ldap_exceptions,
            "log_ldap_timeouts": self.log_ldap_timeouts,
            "log_ldap_retries": self.log_ldap_retries,
            "log_ldap_performance": self.log_ldap_performance,
            "log_ldap_connections": self.log_ldap_connections,
            "log_ldap_disconnections": self.log_ldap_disconnections,
            "log_ldap_pool_events": self.log_ldap_pool_events,
            "log_ldap_cache_events": self.log_ldap_cache_events,
            "log_ldap_ssl_events": self.log_ldap_ssl_events,
            "log_ldap_authentication": self.log_ldap_authentication,
            "log_ldap_authorization": self.log_ldap_authorization,
            "log_ldap_audit": self.log_ldap_audit,
            "log_ldap_security": self.log_ldap_security,
            "log_ldap_compliance": self.log_ldap_compliance,
            "track_ldap_performance": self.track_ldap_performance,
            "ldap_performance_threshold_warning": self.ldap_performance_threshold_warning,
            "ldap_performance_threshold_critical": self.ldap_performance_threshold_critical,
            "include_dn_in_logs": self.include_dn_in_logs,
            "include_attributes_in_logs": self.include_attributes_in_logs,
            "include_values_in_logs": self.include_values_in_logs,
            "include_filters_in_logs": self.include_filters_in_logs,
            "include_controls_in_logs": self.include_controls_in_logs,
            "include_timing_in_logs": self.include_timing_in_logs,
            "include_connection_info_in_logs": self.include_connection_info_in_logs,
            "include_user_info_in_logs": self.include_user_info_in_logs,
            "include_server_info_in_logs": self.include_server_info_in_logs,
            "mask_sensitive_data": self.mask_sensitive_data,
            "mask_passwords": self.mask_passwords,
            "mask_attributes": self.mask_attributes,
            "mask_values": self.mask_values,
            "use_standard_templates": self.use_standard_templates,
            "custom_log_format": self.custom_log_format,
            "enable_audit_logging": self.enable_audit_logging,
            "audit_log_level": self.audit_log_level,
            "audit_log_file": self.audit_log_file,
            "environment_specific_logging": self.environment_specific_logging,
        }

    def get_effective_connection(self) -> Types.ConfigDict | None:
        """Get effective connection configuration.

        Returns:
            Dictionary containing connection details or None

        """
        if not self.ldap_default_connection:
            return None

        return {
            "server": self.ldap_default_connection.server,
            "port": self.ldap_default_connection.port,
            "use_ssl": self.ldap_use_ssl,
            "verify_certificates": self.ldap_verify_certificates,
        }

    def get_effective_auth_config(self) -> dict[str, object]:
        """Get effective authentication configuration.

        Returns:
            Dictionary containing authentication details

        """
        return {
            "bind_dn": self.get_effective_bind_dn(),
            "use_ssl": self.ldap_use_ssl,
            "verify_certificates": self.ldap_verify_certificates,
        }

    class LdapConnection(FlextConfig):
        """LDAP connection configuration with validation."""

        model_config = SettingsConfigDict(
            extra="ignore",  # Allow client-a and other project-specific environment variables
            validate_assignment=True,
            str_strip_whitespace=True,
        )

        def model_post_init(
            self,
            __context: dict[str, object] | None = None,
            /,
        ) -> None:
            """Post-initialization setup for LDAP configuration."""
            super().model_post_init(__context)
            self._logger = FlextLogger(__name__)

        # Basic Connection Settings
        server: str = Field(
            default=FlextLdapConstants.Protocol.DEFAULT_SERVER_URI,
            description=f"LDAP server URI (e.g., '{FlextLdapConstants.Protocol.PROTOCOL_PREFIX_LDAP}host' or '{FlextLdapConstants.Protocol.PROTOCOL_PREFIX_LDAPS}host:{FlextLdapConstants.Protocol.DEFAULT_SSL_PORT}')",
            min_length=1,
        )

        port: int = Field(
            default=FlextLdapConstants.Protocol.DEFAULT_PORT,
            description=f"LDAP server port ({FlextLdapConstants.Protocol.DEFAULT_PORT} for LDAP, {FlextLdapConstants.Protocol.DEFAULT_SSL_PORT} for LDAPS)",
            ge=1,
            le=65535,
        )

        use_ssl: bool = Field(
            default=False,
            description="Use SSL/TLS encryption (LDAPS)",
        )

        # Authentication Settings
        bind_dn: str = Field(
            default="",
            description="Bind Distinguished Name for authentication",
        )

        bind_password: str = Field(
            default="",
            description="Password for bind DN",
            repr=False,  # Hide password in repr
        )

        # Connection Pool Settings
        timeout: int = Field(
            default=FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS,
            description="Connection timeout in seconds",
            ge=1,
            le=300,
        )

        pool_size: int = Field(
            default=FlextLdapConstants.Protocol.DEFAULT_POOL_SIZE,
            description="Maximum number of connections in pool",
            ge=1,
            le=50,
        )

        # TLS/SSL Settings
        ca_cert_file: Path | None = Field(
            default=None,
            description="Path to CA certificate file for SSL verification",
        )

        client_cert_file: Path | None = Field(
            default=None,
            description="Path to client certificate file",
        )

        client_key_file: Path | None = Field(
            default=None,
            description="Path to client private key file",
        )

        verify_ssl: bool = Field(
            default=True,
            description="Verify SSL certificates",
        )

        @field_validator("server")
        @classmethod
        def validate_server_uri(cls, v: str) -> str:
            """Validate LDAP server URI format using FlextModels.Url validation.

            Returns:
                str: The validated server URI.

            Raises:
                ValueError: If the server URI format is invalid.

            """
            if not v or not v.strip():
                msg = "Server URI cannot be empty"
                raise ValueError(msg)

            v = v.strip()

            # Convert LDAP schemes to HTTP for FlextModels.Url validation
            temp_url = v
            if v.startswith("ldap://"):
                temp_url = v.replace("ldap://", "http://", 1)
            elif v.startswith("ldaps://"):
                temp_url = v.replace("ldaps://", "https://", 1)
            else:
                msg = "LDAP URI must start with 'ldap://' or 'ldaps://'"
                raise ValueError(msg)

            # Use FlextModels.create_validated_url for comprehensive validation
            url_result = FlextModels.create_validated_url(temp_url)
            if url_result.is_failure:
                msg = f"Invalid LDAP URI format: {url_result.error}"
                raise ValueError(msg)

            return v

        @field_validator("ca_cert_file", "client_cert_file", "client_key_file")
        @classmethod
        def validate_cert_files(cls, v: Path | None) -> Path | None:
            """Validate certificate files using direct validation.

            Returns:
                Path | None: The validated certificate file path or None.

            Raises:
                ValueError: If the certificate file path is invalid.

            """
            if v is None:
                return v

            # Use direct validation for file path validation
            path_str = str(v)
            if not path_str or not path_str.strip():
                msg = "Certificate file path invalid"
                raise ValueError(msg)

            # File existence validation
            if not v.exists():
                msg = f"Certificate file does not exist: {v}"
                raise ValueError(msg)

            return v

        def get_server_uri(self) -> str:
            """Get complete server URI including port if non-standard.

            Returns:
                str: The complete server URI with port.

            """
            if ":" in self.server and not self.server.endswith(f":{self.port}"):
                # Server already includes port
                return self.server

            # Add port if non-standard - use constants
            standard_port = (
                FlextLdapConstants.Protocol.DEFAULT_SSL_PORT
                if self.use_ssl
                else FlextLdapConstants.Protocol.DEFAULT_PORT
            )
            if self.port != standard_port:
                base_uri = self.server.rstrip("/")
                return f"{base_uri}:{self.port}"

            return self.server

        def validate_configuration(self) -> FlextResult[None]:
            """Validate the complete configuration.

            Returns:
                str:: Description of return value.

            """
            try:
                # Additional validation logic here
                if self.use_ssl and self.verify_ssl and not self.ca_cert_file:
                    self._logger.warning(
                        "SSL verification enabled but no CA certificate file specified",
                    )

                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Configuration validation failed: {e}")


# Removed backward compatibility alias - use FlextLdapConfigs directly
__all__ = [
    "FlextLdapConfigs",
]
