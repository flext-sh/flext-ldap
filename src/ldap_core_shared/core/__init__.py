"""Core Infrastructure for LDAP Core Shared.

This module provides the foundational infrastructure for the entire LDAP Core Shared
library, including standardized exception handling, enterprise configuration management,
structured logging, and initialization utilities.

Features:
    - Centralized exception hierarchy with context and security classification
    - Enterprise-grade configuration management with validation
    - Structured logging with performance monitoring and security events
    - Unified initialization and teardown procedures
    - Integration with external monitoring and observability systems

Architecture:
    - Exception handling with error classification and context preservation
    - Configuration management with hierarchical loading and validation
    - Logging framework with structured output and filtering
    - Core initialization with dependency management

Usage Example:
    >>> from ldap_core_shared.core import initialize_core, get_logger, LDAPCoreError
    >>>
    >>> # Initialize core infrastructure
    >>> config = initialize_core("production")
    >>>
    >>> # Get structured logger
    >>> logger = get_logger("my.component")
    >>>
    >>> # Use structured logging
    >>> with logger.context(operation="user_auth", user_id="john"):
    ...     logger.info("Starting authentication")
    ...     # ... operation code ...
    ...     logger.info("Authentication completed")

Standards:
    - Enterprise exception handling with structured context
    - Configuration management following 12-factor principles
    - Structured logging with correlation IDs and security classification
    - Initialization patterns with dependency injection
    - Graceful shutdown and resource cleanup
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import sys
from typing import TYPE_CHECKING, Any, Optional, Union

# Core infrastructure imports
from ldap_core_shared.core.config import (
    ApplicationConfig,
    ConfigManager,
    Environment,
)
from ldap_core_shared.core.config import (
    LogLevel as ConfigLogLevel,
)
from ldap_core_shared.core.exceptions import (
    ConfigurationValidationError,
    ErrorCategory,
    ErrorSeverity,
    LDAPCoreError,
    OperationTimeoutError,
    SchemaValidationError,
    ValidationError,
)
from ldap_core_shared.core.logging import (
    EventType,
    LoggerManager,
    PerformanceMonitor,
    SecurityEventType,
    StructuredLogger,
    get_logger,
    get_performance_monitor,
)

if TYPE_CHECKING:
    from pathlib import Path

# Global state management
_core_initialized: bool = False
_application_config: ApplicationConfig | None = None
_shutdown_handlers: list[callable] = []


class CoreInitializationError(LDAPCoreError):
    """Error during core infrastructure initialization."""

    def __init__(self, message: str, cause: Exception | None = None) -> None:
        """Initialize core initialization error.

        Args:
            message: Error message
            cause: Underlying cause
        """
        super().__init__(
            message=message,
            error_code="CORE_INIT_FAILED",
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.SYSTEM,
            cause=cause,
            user_message="Failed to initialize core infrastructure",
        )


def initialize_core(
    environment: str | Environment | None = None,
    config_file: str | Path | None = None,
    override_values: dict[str, Any] | None = None,
    force_reinit: bool = False,
) -> ApplicationConfig:
    """Initialize core infrastructure for LDAP Core Shared.

    This function sets up the complete infrastructure including configuration
    management, logging, exception handling, and performance monitoring.

    Args:
        environment: Target environment (development, testing, staging, production)
        config_file: Path to configuration file
        override_values: Configuration values to override
        force_reinit: Force reinitialization if already initialized

    Returns:
        Loaded and validated application configuration

    Raises:
        CoreInitializationError: If initialization fails

    Example:
        >>> # Basic initialization
        >>> config = initialize_core("production")
        >>>
        >>> # With custom config file
        >>> config = initialize_core(
        ...     environment="staging",
        ...     config_file="/etc/ldap-core/config.yaml"
        ... )
        >>>
        >>> # With overrides
        >>> config = initialize_core(
        ...     environment="development",
        ...     override_values={"debug": True, "logging": {"level": "DEBUG"}}
        ... )
    """
    global _core_initialized, _application_config

    # Check if already initialized
    if _core_initialized and not force_reinit:
        if _application_config is None:
            msg = "Core marked as initialized but no config available"
            raise CoreInitializationError(msg)
        return _application_config

    try:
        # Step 1: Load and validate configuration
        config = ConfigManager.load_config(
            environment=environment,
            config_file=config_file,
            override_values=override_values,
        )

        # Step 2: Initialize logging system
        LoggerManager.initialize(config.logging)

        # Step 3: Get core logger for initialization logging
        logger = get_logger("core.initialization")

        # Step 4: Log initialization start
        logger.info(
            "Starting LDAP Core Shared initialization",
            event_type=EventType.SYSTEM,
            environment=config.environment.value,
            version=config.version,
            debug_mode=config.debug,
        )

        # Step 5: Validate core dependencies
        _validate_core_dependencies(config, logger)

        # Step 6: Setup shutdown handlers
        _setup_shutdown_handlers(logger)

        # Step 7: Initialize performance monitoring if enabled
        if config.monitoring.enabled:
            performance_monitor = get_performance_monitor()
            if performance_monitor:
                logger.info(
                    "Performance monitoring initialized",
                    event_type=EventType.SYSTEM,
                    slow_threshold=config.logging.slow_query_threshold,
                )

        # Step 8: Mark as initialized
        _core_initialized = True
        _application_config = config

        # Step 9: Log successful initialization
        logger.info(
            "LDAP Core Shared initialization completed successfully",
            event_type=EventType.SYSTEM,
            environment=config.environment.value,
            components_initialized=[
                "configuration",
                "logging",
                "exception_handling",
                "performance_monitoring" if config.monitoring.enabled else None,
            ],
        )

        return config

    except Exception as e:
        # Log initialization failure
        try:
            # Try to get a basic logger for error reporting
            error_logger = logging.getLogger("core.initialization.error")
            error_logger.critical("Core initialization failed: %s", e)
        except Exception:
            # If logging setup failed, use stderr
            pass

        # Wrap in core initialization error
        if isinstance(e, ConfigurationValidationError | LDAPCoreError):
            msg = f"Configuration or infrastructure error: {e}"
            raise CoreInitializationError(
                msg,
                cause=e,
            ) from e
        msg = f"Unexpected error during initialization: {e}"
        raise CoreInitializationError(
            msg,
            cause=e,
        ) from e


def _validate_core_dependencies(
    config: ApplicationConfig, logger: StructuredLogger,
) -> None:
    """Validate core dependencies and environment requirements.

    Args:
        config: Application configuration
        logger: Logger for dependency validation

    Raises:
        CoreInitializationError: If dependencies are not satisfied
    """
    logger.debug("Validating core dependencies")

    # Check Python version
    min_python_version = (3, 8)
    current_version = sys.version_info[:2]
    if current_version < min_python_version:
        msg = (
            f"Python {min_python_version[0]}.{min_python_version[1]}+ required, "
            f"got {current_version[0]}.{current_version[1]}"
        )
        raise CoreInitializationError(
            msg,
        )

    # Validate critical paths exist (for production)
    if config.environment == Environment.PRODUCTION:
        critical_paths = [
            config.schema.base_path,
            config.schema.backup_path.parent,  # Parent must exist, we'll create backup_path
        ]

        for path in critical_paths:
            if not path.exists():
                logger.warning(
                    "Critical path does not exist: %s",
                    path,
                    extra={
                        "event_type": EventType.SYSTEM,
                        "path": str(path),
                        "environment": config.environment.value,
                    },
                )

    # Check required environment variables for production
    if config.environment == Environment.PRODUCTION:
        required_env_vars = ["LDAP_CORE_ENV"]
        missing_vars = [var for var in required_env_vars if not os.getenv(var)]
        if missing_vars:
            logger.warning(
                "Missing recommended environment variables: %s",
                missing_vars,
                extra={
                    "event_type": EventType.SYSTEM,
                    "missing_variables": missing_vars,
                },
            )

    logger.debug("Core dependency validation completed")


def _setup_shutdown_handlers(logger: StructuredLogger) -> None:
    """Setup graceful shutdown handlers.

    Args:
        logger: Logger for shutdown setup
    """
    logger.debug("Setting up shutdown handlers")

    def shutdown_handler() -> None:
        """Handle graceful shutdown."""
        try:
            shutdown_core()
        except Exception as e:
            logger.exception("Error during shutdown: %s", e, exception=e)

    # Register shutdown handler
    atexit.register(shutdown_handler)
    _shutdown_handlers.append(shutdown_handler)

    logger.debug("Shutdown handlers configured")


def shutdown_core() -> None:
    """Gracefully shutdown core infrastructure.

    Performs cleanup of all core infrastructure components including
    closing connections, flushing logs, and releasing resources.

    Example:
        >>> # Explicit shutdown
        >>> shutdown_core()
        >>>
        >>> # Or let atexit handler do it automatically
    """
    global _core_initialized, _application_config

    if not _core_initialized:
        return

    try:
        # Get logger for shutdown logging
        logger = get_logger("core.shutdown")

        logger.info(
            "Starting LDAP Core Shared shutdown",
            event_type=EventType.SYSTEM,
        )

        # Shutdown logging system (this will flush all logs)
        LoggerManager.shutdown()

        # Clear global state
        _core_initialized = False
        _application_config = None

        # Note: We can't log after LoggerManager.shutdown(), so print to stderr

    except Exception:
        pass


def is_initialized() -> bool:
    """Check if core infrastructure is initialized.

    Returns:
        True if core is initialized

    Example:
        >>> if not is_initialized():
        ...     initialize_core()
    """
    return _core_initialized


def get_config() -> ApplicationConfig:
    """Get current application configuration.

    Returns:
        Current application configuration

    Raises:
        CoreInitializationError: If core not initialized

    Example:
        >>> config = get_config()
        >>> ldap_servers = config.connection.servers
    """
    global _application_config

    if not _core_initialized or _application_config is None:
        msg = "Core infrastructure not initialized. Call initialize_core() first."
        raise CoreInitializationError(
            msg,
        )

    return _application_config


def reconfigure(
    config_file: str | Path | None = None,
    override_values: dict[str, Any] | None = None,
) -> ApplicationConfig:
    """Reconfigure the application with new settings.

    Args:
        config_file: New configuration file path
        override_values: Configuration values to override

    Returns:
        Updated application configuration

    Raises:
        CoreInitializationError: If reconfiguration fails

    Example:
        >>> # Reconfigure with new settings
        >>> config = reconfigure(override_values={"debug": True})
        >>>
        >>> # Reconfigure with new config file
        >>> config = reconfigure(config_file="/etc/ldap-core/new-config.yaml")
    """
    if not _core_initialized:
        msg = "Cannot reconfigure: core not initialized"
        raise CoreInitializationError(msg)

    current_config = get_config()

    # Reconfigure by reinitializing with current environment
    return initialize_core(
        environment=current_config.environment,
        config_file=config_file,
        override_values=override_values,
        force_reinit=True,
    )


# Convenience re-exports for easy access
__all__ = [
    # Configuration classes
    "ApplicationConfig",
    "ConfigManager",
    "ConfigurationValidationError",
    "CoreInitializationError",
    "Environment",
    "ErrorCategory",
    "ErrorSeverity",
    "EventType",
    # Exception classes
    "LDAPCoreError",
    "LoggerManager",
    "OperationTimeoutError",
    "PerformanceMonitor",
    "SchemaValidationError",
    "SecurityEventType",
    # Logging classes and functions
    "StructuredLogger",
    "ValidationError",
    "get_config",
    "get_logger",
    "get_performance_monitor",
    # Initialization functions
    "initialize_core",
    "is_initialized",
    "reconfigure",
    "shutdown_core",
]


# Auto-initialize in development mode if LDAP_CORE_AUTO_INIT is set
if os.getenv("LDAP_CORE_AUTO_INIT", "").lower() in {"true", "1", "yes"}:
    with contextlib.suppress(Exception):
        initialize_core()
