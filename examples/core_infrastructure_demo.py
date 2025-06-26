#!/usr/bin/env python3
"""Demo of LDAP Core Shared Infrastructure.

This script demonstrates the complete enterprise-grade infrastructure
including configuration management, structured logging, exception handling,
and performance monitoring.
"""

import sys
import time
from pathlib import Path

# Add the src directory to Python path for the demo
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ldap_core_shared.core import (
    ErrorCategory,
    ErrorSeverity,
    LDAPCoreError,
    SecurityEventType,
    get_config,
    get_logger,
    get_performance_monitor,
    initialize_core,
    is_initialized,
    shutdown_core,
)


def demo_configuration_management() -> None:
    """Demonstrate configuration management."""
    # Initialize with custom configuration
    initialize_core(
        environment="development",
        override_values={
            "debug": True,
            "logging": {
                "level": "DEBUG",
                "structured_logging": True,
                "performance_logging": True,
            },
            "monitoring": {
                "enabled": True,
                "metrics_enabled": True,
            },
        },
    )


def demo_structured_logging() -> None:
    """Demonstrate structured logging capabilities."""
    # Get logger for this component
    logger = get_logger("demo.component")

    # Basic logging
    logger.info("Starting logging demonstration")
    logger.debug("Debug information for troubleshooting")

    # Logging with context
    with logger.context(
        operation="schema_validation",
        schema_name="custom.schema",
        user_id="demo_user",
    ):
        logger.info("Schema validation started")
        logger.warning("Schema contains deprecated attributes")
        logger.info("Schema validation completed successfully")

    # Performance logging
    logger.performance(
        "Schema validation performance",
        metrics={
            "duration": 1.23,
            "attribute_count": 45,
            "object_class_count": 12,
            "validation_errors": 0,
        },
    )

    # Security logging
    logger.security(
        "User authenticated successfully",
        SecurityEventType.AUTHENTICATION_SUCCESS,
        user_id="demo_user",
        ip_address="192.168.1.100",
        method="LDAP_BIND",
    )

    # Audit logging
    logger.audit(
        "Schema deployment completed",
        operation_id="schema_deploy_001",
        target_environment="production",
        schema_count=3,
        deployment_status="success",
    )


def demo_performance_monitoring() -> None:
    """Demonstrate performance monitoring."""
    logger = get_logger("demo.performance")
    perf_monitor = get_performance_monitor()

    if not perf_monitor:
        return

    # Monitor operation performance
    with perf_monitor.time_operation("schema_parsing", logger):
        logger.info("Parsing large schema file...")
        time.sleep(0.1)  # Simulate work
        logger.info("Schema parsing completed")

    # Monitor another operation
    with perf_monitor.time_operation("ldap_connection", logger):
        logger.info("Establishing LDAP connection...")
        time.sleep(0.05)  # Simulate work
        logger.info("LDAP connection established")

    # Simulate slow operation
    with perf_monitor.time_operation("slow_validation", logger):
        logger.info("Starting slow validation...")
        time.sleep(1.2)  # Simulate slow work (exceeds 1.0s threshold)
        logger.info("Slow validation completed")


def demo_exception_handling() -> None:
    """Demonstrate enterprise exception handling."""
    logger = get_logger("demo.exceptions")

    # Example 1: Basic exception with context
    try:
        raise LDAPCoreError(
            message="Schema validation failed",
            error_code="SCHEMA_VALIDATION_001",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.VALIDATION,
            context={
                "schema_file": "custom.schema",
                "line_number": 42,
                "validation_rule": "RFC_4512_COMPLIANCE",
            },
            user_message="The schema file contains syntax errors",
        )
    except LDAPCoreError as e:
        logger.exception(
            f"Caught LDAP error: {e.message}",
            exception=e,
            error_code=e.error_code,
            severity=e.severity.value,
        )

    # Example 2: Nested exception with cause
    try:
        try:
            msg = "Invalid schema format"
            raise ValueError(msg)
        except ValueError as original_error:
            raise LDAPCoreError(
                message="Schema processing failed due to format error",
                error_code="SCHEMA_FORMAT_ERROR",
                severity=ErrorSeverity.MEDIUM,
                category=ErrorCategory.VALIDATION,
                cause=original_error,
                context={"processing_step": "initial_parse"},
            )
    except LDAPCoreError as e:
        logger.exception(
            f"Schema processing error: {e.message}",
            exception=e,
            original_cause=str(e.cause) if e.cause else None,
        )


def demo_system_integration() -> None:
    """Demonstrate system integration features."""
    logger = get_logger("demo.integration")

    # Configuration access
    config = get_config()
    logger.info(
        "Application configuration accessed",
        application_name=config.name,
        version=config.version,
        environment=config.environment.value,
    )

    # System status
    logger.info(
        "System status check",
        core_initialized=is_initialized(),
        performance_monitoring=get_performance_monitor() is not None,
        python_version=sys.version.split()[0],
        platform=sys.platform,
    )

    # Simulated integration points
    with logger.context(integration="external_ldap", server="ldap.example.com"):
        logger.info("Connecting to external LDAP server")
        logger.debug("Using connection pool strategy: SAFE_SYNC")
        logger.info("External LDAP connection established")

    with logger.context(integration="schema_repository", repository="git"):
        logger.info("Fetching latest schema definitions")
        logger.info("Schema repository sync completed")


def main() -> None:
    """Run the complete infrastructure demonstration."""
    try:
        # Run all demonstration modules
        demo_configuration_management()
        demo_structured_logging()
        demo_performance_monitoring()
        demo_exception_handling()
        demo_system_integration()

    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)

    finally:
        # Graceful shutdown
        shutdown_core()


if __name__ == "__main__":
    main()
