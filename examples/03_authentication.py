#!/usr/bin/env python3
"""Authentication Operations Example - flext-ldap API.

This example demonstrates LDAP authentication functionality:
- User authentication (authenticate_user)
- Credential validation (validate_credentials)
- Authentication workflows
- Error handling for authentication failures
- Bind DN vs. User DN authentication

Uses ONLY api.py (FlextLdap) as the primary interface.

Environment Variables:
    LDAP_SERVER_URI: LDAP server URI (default: ldap://localhost:389)
    LDAP_BIND_DN: Bind DN (default: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: REDACTED_LDAP_BIND_PASSWORD)
    LDAP_BASE_DN: Base DN (default: dc=example,dc=com)

Example:
    python examples/03_authentication.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import sys
from typing import Final

from flext_core import FlextLogger, FlextResult

from flext_ldap.api import FlextLdap
from flext_ldap.config import FlextLdapConfig

logger = FlextLogger(__name__)

# Configuration from environment
LDAP_URI: Final[str] = os.getenv("LDAP_SERVER_URI", "ldap://localhost:389")
BIND_DN: Final[str] = os.getenv("LDAP_BIND_DN", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
BIND_PASSWORD: Final[str] = os.getenv("LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD")
BASE_DN: Final[str] = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")


def setup_api() -> FlextLdap | None:
    """Setup and connect FlextLdap API.

    Returns:
        Connected FlextLdap instance or None if connection failed.

    """
    config = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=BIND_PASSWORD,
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap(config=config)

    connect_result = api.connect()
    if connect_result.is_failure:
        logger.error(f"Connection failed: {connect_result.error}")
        return None

    return api


def demonstrate_user_authentication(api: FlextLdap) -> None:
    """Demonstrate user authentication with username and password.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("=== User Authentication ===")

    # Test authentication scenarios
    test_cases = [
        ("REDACTED_LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD", True, "Admin user with correct password"),
        ("REDACTED_LDAP_BIND_PASSWORD", "wrong_password", False, "Admin user with wrong password"),
        ("nonexistent", "password", False, "Non-existent user"),
        ("", "password", False, "Empty username"),
        ("REDACTED_LDAP_BIND_PASSWORD", "", False, "Empty password"),
    ]

    for username, password, should_succeed, description in test_cases:
        logger.info(f"\nTest: {description}")
        logger.info(f"   Username: {username!r}")

        result: FlextResult[bool] = api.authenticate_user(username, password)

        if result.is_success:
            authenticated = result.unwrap()
            if authenticated:
                status = "✅" if should_succeed else "❌ Unexpected"
                logger.info(f"   {status} Authentication SUCCEEDED")
            else:
                status = "❌" if should_succeed else "✅ Expected"
                logger.info(f"   {status} Authentication FAILED")
        else:
            status = "❌" if should_succeed else "✅ Expected"
            logger.info(f"   {status} Authentication error: {result.error}")


def demonstrate_credential_validation(api: FlextLdap) -> None:
    """Demonstrate credential validation with DN and password.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Credential Validation ===")

    # Test credential validation with full DN
    test_cases = [
        (
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "REDACTED_LDAP_BIND_PASSWORD",
            True,
            "Admin DN with correct password",
        ),
        (
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "wrong_password",
            False,
            "Admin DN with wrong password",
        ),
        (
            "cn=nonexistent,dc=example,dc=com",
            "password",
            False,
            "Non-existent DN",
        ),
        ("invalid-dn", "password", False, "Invalid DN format"),
        ("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "", False, "Empty password"),
    ]

    for dn, password, should_succeed, description in test_cases:
        logger.info(f"\nTest: {description}")
        logger.info(f"   DN: {dn}")

        result: FlextResult[bool] = api.validate_credentials(dn, password)

        if result.is_success:
            valid = result.unwrap()
            if valid:
                status = "✅" if should_succeed else "❌ Unexpected"
                logger.info(f"   {status} Credentials VALID")
            else:
                status = "❌" if should_succeed else "✅ Expected"
                logger.info(f"   {status} Credentials INVALID")
        else:
            status = "❌" if should_succeed else "✅ Expected"
            logger.info(f"   {status} Validation error: {result.error}")


def demonstrate_authentication_workflow(api: FlextLdap) -> None:
    """Demonstrate complete authentication workflow.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Complete Authentication Workflow ===")

    # Simulate a login workflow
    username = "REDACTED_LDAP_BIND_PASSWORD"
    password = "REDACTED_LDAP_BIND_PASSWORD"

    logger.info(f"Login attempt for user: {username}")

    # Step 1: Authenticate user
    logger.info("Step 1: Authenticating user...")
    auth_result: FlextResult[bool] = api.authenticate_user(username, password)

    if auth_result.is_failure:
        logger.error(f"   ❌ Authentication failed: {auth_result.error}")
        logger.info("   Workflow aborted: Authentication error")
        return

    if not auth_result.unwrap():
        logger.warning("   ❌ Authentication failed: Invalid credentials")
        logger.info("   Workflow aborted: Invalid username or password")
        return

    logger.info("   ✅ User authenticated successfully")

    # Step 2: Search for user details (after successful authentication)
    logger.info("Step 2: Retrieving user details...")
    search_result = api.search_one(
        search_base=BASE_DN,
        search_filter=f"(cn={username})",
        attributes=["cn", "objectClass", "description"],
    )

    if search_result.is_failure:
        logger.error(f"   ❌ User search failed: {search_result.error}")
        return

    user_entry = search_result.unwrap()
    if user_entry:
        logger.info("   ✅ User details retrieved:")
        logger.info(f"      DN: {user_entry.dn}")
        logger.info(f"      Attributes: {list(user_entry.attributes.keys())}")

        # Step 3: Validate credentials with full DN (optional verification)
        logger.info("Step 3: Validating credentials with DN...")
        validate_result: FlextResult[bool] = api.validate_credentials(
            user_entry.dn, password
        )

        if validate_result.is_success and validate_result.unwrap():
            logger.info("   ✅ Credentials validated successfully")
            logger.info("\n✅ Complete authentication workflow SUCCEEDED")
        else:
            error_msg = validate_result.error
            logger.warning(f"   ❌ Credential validation failed: {error_msg}")
    else:
        logger.warning("   ⚠️  User entry not found")


def demonstrate_authentication_error_handling(api: FlextLdap) -> None:
    """Demonstrate proper error handling for authentication.

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== Authentication Error Handling ===")

    # Demonstrate different error scenarios
    error_scenarios = [
        {
            "name": "Invalid Username Format",
            "username": "user@invalid",
            "password": "password",
            "expected": "Authentication should fail gracefully",
        },
        {
            "name": "SQL Injection Attempt",
            "username": "REDACTED_LDAP_BIND_PASSWORD' OR '1'='1",
            "password": "password",
            "expected": "Should be rejected safely",
        },
        {
            "name": "LDAP Injection Attempt",
            "username": "REDACTED_LDAP_BIND_PASSWORD)(objectClass=*",
            "password": "password",
            "expected": "Should be rejected safely",
        },
        {
            "name": "Very Long Username",
            "username": "a" * 1000,
            "password": "password",
            "expected": "Should handle gracefully",
        },
    ]

    for scenario in error_scenarios:
        logger.info(f"\nScenario: {scenario['name']}")
        logger.info(f"   Expected: {scenario['expected']}")

        result: FlextResult[bool] = api.authenticate_user(
            scenario["username"], scenario["password"]
        )

        if result.is_success:
            authenticated = result.unwrap()
            if authenticated:
                logger.warning("   ⚠️  Authentication succeeded (unexpected)")
            else:
                logger.info("   ✅ Authentication rejected (as expected)")
        else:
            logger.info(f"   ✅ Authentication error handled: {result.error}")


def demonstrate_bind_authentication() -> None:
    """Demonstrate authentication via bind DN (connection-level)."""
    logger.info("\n=== Bind DN Authentication ===")

    # Test authentication by binding with different credentials
    test_credentials = [
        ("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "REDACTED_LDAP_BIND_PASSWORD", True, "Admin bind"),
        ("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "wrong", False, "Invalid password"),
        ("cn=invalid,dc=example,dc=com", "password", False, "Invalid DN"),
    ]

    for bind_dn, bind_password, should_succeed, description in test_credentials:
        logger.info(f"\nTest: {description}")
        logger.info(f"   Bind DN: {bind_dn}")

        # Create new API instance with test credentials
        config = FlextLdapConfig(
            ldap_server_uri=LDAP_URI,
            ldap_bind_dn=bind_dn,
            ldap_bind_password=bind_password,
            ldap_base_dn=BASE_DN,
        )
        test_api = FlextLdap(config=config)

        # Try to connect (which includes bind)
        connect_result = test_api.connect()

        if connect_result.is_success:
            status = "✅" if should_succeed else "❌ Unexpected"
            logger.info(f"   {status} Bind SUCCEEDED")
            test_api.unbind()
        else:
            status = "❌" if should_succeed else "✅ Expected"
            logger.info(f"   {status} Bind failed: {connect_result.error}")


def main() -> int:
    """Run authentication operations demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 60)
    logger.info("FLEXT-LDAP Authentication Operations Example")
    logger.info("=" * 60)
    logger.info(f"Server: {LDAP_URI}")
    logger.info(f"Base DN: {BASE_DN}")
    logger.info("=" * 60)

    try:
        # Bind-level authentication (no existing connection needed)
        demonstrate_bind_authentication()

        # Connect to LDAP server for user authentication
        api = setup_api()
        if not api:
            logger.error("Cannot proceed without connection")
            return 1

        try:
            # Authentication demonstrations
            demonstrate_user_authentication(api)
            demonstrate_credential_validation(api)
            demonstrate_authentication_workflow(api)
            demonstrate_authentication_error_handling(api)

            logger.info("\n" + "=" * 60)
            logger.info("✅ All authentication operations completed successfully!")
            logger.info("=" * 60)

        finally:
            # Always disconnect
            if api.is_connected():
                api.unbind()
                logger.info("Disconnected from LDAP server")

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        return 1
    except Exception:
        logger.exception("Operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
