#!/usr/bin/env python3
"""Independent Demo of Core Infrastructure.

This demonstrates only the new core infrastructure without dependencies.
"""

import contextlib
import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def main() -> int | None:
    """Demonstrate the core infrastructure."""
    try:
        # Test 1: Direct imports of core modules

        # Import configuration
        from ldap_core_shared.core.config import (
            ApplicationConfig,
            ConfigManager,
        )

        # Import exceptions
        from ldap_core_shared.core.exceptions import (
            ErrorCategory,
            ErrorSeverity,
            LDAPCoreError,
        )

        # Import logging
        from ldap_core_shared.core.logging import (
            EventType,
            LoggerManager,
        )

        # Test 2: Configuration system
        ApplicationConfig()

        # Test 3: Exception system
        LDAPCoreError(
            message="Test exception for infrastructure demo",
            error_code="DEMO_TEST_001",
            severity=ErrorSeverity.LOW,
            category=ErrorCategory.SYSTEM,
            context={"demo": True, "test_id": "infrastructure_001"},
        )

        # Test 4: Logging system
        LoggerManager.initialize()
        logger = LoggerManager.get_logger("demo.test")

        # Test logging capabilities
        logger.info("Infrastructure demo logging test")
        logger.debug("Debug message for testing")

        # Test 5: Integration points

        # Configuration loading
        loaded_config = ConfigManager.load_config(
            environment="development",
            override_values={"debug": True, "version": "1.0.0-demo"},
        )

        # Logging with configuration
        LoggerManager.initialize(loaded_config.logging)
        demo_logger = LoggerManager.get_logger("demo.integration")
        demo_logger.info(
            "Integration test completed successfully",
            event_type=EventType.SYSTEM,
            test_name="infrastructure_demo",
            status="success",
        )

        # Summary

        return 0

    except Exception:
        import traceback

        traceback.print_exc()
        return 1

    finally:
        # Cleanup
        with contextlib.suppress(Exception):
            LoggerManager.shutdown()


if __name__ == "__main__":
    sys.exit(main())
