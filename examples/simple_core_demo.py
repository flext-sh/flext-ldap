#!/usr/bin/env python3
"""Simple Demo of LDAP Core Infrastructure.

This demonstrates the core infrastructure we just created.
"""

import sys
from pathlib import Path

# Add the src directory to Python path for the demo
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Import only our new core modules
from ldap_core_shared.core.config import ConfigManager
from ldap_core_shared.core.exceptions import ErrorCategory, ErrorSeverity, LDAPCoreError
from ldap_core_shared.core.logging import LoggerManager, get_logger


def main() -> int:
    """Demonstrate the core infrastructure."""
    try:
        # 1. Configuration Management
        config = ConfigManager.load_config(
            environment="development",
            override_values={"debug": True},
        )

        # 2. Logging System
        LoggerManager.initialize(config.logging)
        logger = get_logger("demo")
        logger.info("Logging system initialized")
        logger.debug("This is a debug message")

        # 3. Exception Handling
        try:
            raise LDAPCoreError(
                message="Demo error for testing",
                error_code="DEMO_001",
                severity=ErrorSeverity.LOW,
                category=ErrorCategory.SYSTEM,
            )
        except LDAPCoreError:
            pass

        # 4. System Integration

    except Exception:
        import traceback
        traceback.print_exc()
        return 1

    finally:
        # Cleanup
        LoggerManager.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
