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
    LDAP_BIND_DN: Bind DN (default: cn=admin,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: admin)
    LDAP_BASE_DN: Base DN (default: dc=example,dc=com)

Example:
    python examples/03_authentication.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import sys
from copy import deepcopy
from typing import ClassVar, Final

from flext_core import FlextLogger, FlextResult, FlextTypes
from pydantic import SecretStr

from flext_ldap import FlextLdap, FlextLdapConfig, FlextLdapModels

logger: FlextLogger = FlextLogger(__name__)

LDAP_URI: Final[str] = os.getenv("LDAP_SERVER_URI", "ldap://localhost:3390")
BIND_DN: Final[str] = os.getenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
BIND_PASSWORD: Final[str] = os.getenv("LDAP_BIND_PASSWORD", "admin")
BASE_DN: Final[str] = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")


class DemoAuthScenarios:
    """Inline scenario data for authentication demonstrations."""

    _USERS: ClassVar[dict[str, FlextTypes.Dict]] = {
        "admin": {
            "password": "admin",
            "dn": "cn=admin,dc=example,dc=com",
            "attributes": {
                "cn": ["admin"],
                "description": ["Demo administrator"],
                "objectClass": ["inetOrgPerson", "top"],
            },
        },
        "jane": {
            "password": "hunter2",
            "dn": "cn=jane.doe,dc=example,dc=com",
            "attributes": {
                "cn": ["jane.doe"],
                "description": ["Demo user"],
                "objectClass": ["inetOrgPerson", "top"],
            },
        },
    }

    @classmethod
    def authenticate(cls, username: str, password: str) -> tuple[bool, str | None]:
        """Authenticate user with username and password.

        Args:
            username: Username to authenticate
            password: Password for authentication

        Returns:
            Tuple of (success: bool, error_message: str | None)

        """
        if not username:
            return False, "Username cannot be empty"
        if not password:
            return False, "Password cannot be empty"
        user = cls._USERS.get(username)
        if user is None:
            return False, f"User '{username}' not found"
        if user["password"] != password:
            return False, "Invalid credentials"
        return True, None

    @classmethod
    def validate(cls, dn: str, password: str) -> tuple[bool, str | None]:
        """Validate credentials with DN and password.

        Args:
            dn: Distinguished name for validation
            password: Password for validation

        Returns:
            Tuple of (success: bool, error_message: str | None)

        """
        if not dn:
            return False, "Distinguished name cannot be empty"
        if not password:
            return False, "Password cannot be empty"
        for user in cls._USERS.values():
            if user["dn"] == dn:
                if user["password"] == password:
                    return True, None
                return False, "Invalid credentials"
        return False, f"DN '{dn}' not found"

    @classmethod
    def get_attributes(cls, username: str) -> dict[str, FlextTypes.StringList] | None:
        """Get user attributes by username.

        Args:
            username: Username to look up

        Returns:
            User attributes dictionary or None if user not found

        """
        user = cls._USERS.get(username)
        if user is None:
            return None
        attributes = user["attributes"]
        if isinstance(attributes, dict):
            return deepcopy(attributes)
        return None


class DemoLdapApi:
    """Fallback API used when real LDAP connectivity is unavailable."""

    def __init__(self) -> None:
        """Initialize fallback API with demo configuration."""
        self.config = FlextLdapConfig(
            ldap_server_uri="ldap://demo-ldap",
            ldap_bind_dn=BIND_DN,
            ldap_bind_password=SecretStr(BIND_PASSWORD),
            ldap_base_dn=BASE_DN,
        )
        self._connected = False

    def connect(self) -> FlextResult[bool]:
        """Connect to the demo LDAP API.

        Returns:
            Success result

        """
        self._connected = True
        logger.info("🔁 Using in-memory demo LDAP API (no external server)")
        return FlextResult[bool].ok(True)

    def disconnect(self) -> FlextResult[bool]:
        """Disconnect from the demo LDAP API.

        Returns:
            Success result

        """
        self._connected = False
        return FlextResult[bool].ok(True)

    def unbind(self) -> FlextResult[bool]:
        """Unbind from the demo LDAP API.

        Returns:
            Success result

        """
        return self.unbind()

    def is_connected(self) -> bool:
        """Check if connected to the demo LDAP API.

        Returns:
            True if connected

        """
        return self._connected

    def authenticate_user(self, username: str, password: str) -> FlextResult[bool]:
        """Authenticate user with username and password.

        Args:
            username: Username to authenticate
            password: Password for authentication

        Returns:
            Success result or error result

        """
        success, error = DemoAuthScenarios.authenticate(username, password)
        if success:
            return FlextResult[bool].ok(True)
        return FlextResult[bool].fail(error or "Authentication failed")

    def validate_credentials(self, dn: str, password: str) -> FlextResult[bool]:
        """Validate credentials with DN and password.

        Args:
            dn: Distinguished name for validation
            password: Password for validation

        Returns:
            Success result or error result

        """
        success, error = DemoAuthScenarios.validate(dn, password)
        if success:
            return FlextResult[bool].ok(True)
        return FlextResult[bool].fail(error or "Credential validation failed")

    def search_one(
        self,
        request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Search for a single entry in the demo LDAP.

        Args:
            request: Search request parameters

        Returns:
            Single entry result or None

        """
        filter_str = request.filter_str
        username = ""
        if filter_str.startswith("(") and filter_str.endswith(")"):
            inner = filter_str[1:-1]
            if "=" in inner:
                username = inner.split("=", maxsplit=1)[1]
        attributes = DemoAuthScenarios.get_attributes(username)
        if attributes is None:
            return FlextResult[FlextLdapModels.Entry | None].ok(None)
        entry = FlextLdapModels.Entry(
            dn=f"cn={username},{BASE_DN}",
            attributes=attributes,
            object_classes=["inetOrgPerson", "top"],
        )
        return FlextResult[FlextLdapModels.Entry | None].ok(entry)


def setup_api() -> FlextLdap | DemoLdapApi:
    """Setup LDAP API, falling back to an in-memory demo implementation if needed."""
    FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap()

    # Use context manager for automatic connection/disconnection
    try:
        with api:
            return api
    except Exception as e:
        logger.warning(
            "Connection failed (%s). Switching to demo LDAP API.",
            e,
        )
        demo_api = DemoLdapApi()
        demo_api.connect()
        return demo_api


def demonstrate_user_authentication(api: FlextLdap | DemoLdapApi) -> None:
    """Demonstrate user authentication with username and password.

    Args:
        api: Connected LDAP API (real or demo)

    """
    logger.info("=== User Authentication ===")

    # Test authentication scenarios
    test_cases = [
        ("admin", "admin", True, "Admin user with correct password"),
        ("admin", "wrong_password", False, "Admin user with wrong password"),
        ("nonexistent", "password", False, "Non-existent user"),
        ("", "password", False, "Empty username"),
        ("admin", "", False, "Empty password"),
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


def demonstrate_credential_validation(api: FlextLdap | DemoLdapApi) -> None:
    """Demonstrate credential validation with DN and password.

    Args:
        api: Connected LDAP API (real or demo)

    """
    logger.info("\n=== Credential Validation ===")

    # Test credential validation with full DN
    test_cases = [
        (
            "cn=admin,dc=example,dc=com",
            "admin",
            True,
            "Admin DN with correct password",
        ),
        (
            "cn=admin,dc=example,dc=com",
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
        ("cn=admin,dc=example,dc=com", "", False, "Empty password"),
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


def demonstrate_authentication_workflow(api: FlextLdap | DemoLdapApi) -> None:
    """Demonstrate complete authentication workflow.

    Args:
        api: Connected LDAP API (real or demo)

    """
    logger.info("\n=== Complete Authentication Workflow ===")

    # Simulate a login workflow
    username = "admin"
    password = "admin"

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
    search_result: FlextResult[FlextLdapModels.Entry | None] = api.search_one(
        FlextLdapModels.SearchRequest(
            base_dn=BASE_DN,
            filter_str=f"(cn={username})",
            attributes=["cn", "objectClass", "description"],
        )
    )

    if search_result.is_failure:
        logger.error(f"   ❌ User search failed: {search_result.error}")
        return

    user_entry = search_result.unwrap()
    if user_entry:
        attributes_obj = getattr(user_entry, "attributes", {})
        if hasattr(attributes_obj, "data"):
            attribute_keys = list(getattr(attributes_obj, "data").keys())
        elif isinstance(attributes_obj, dict):
            attribute_keys = list(attributes_obj.keys())
        else:
            attribute_keys = []
        logger.info("   ✅ User details retrieved:")
        logger.info(f"      DN: {user_entry.dn}")
        logger.info(f"      Attributes: {attribute_keys}")

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


def demonstrate_authentication_error_handling(api: FlextLdap | DemoLdapApi) -> None:
    """Demonstrate proper error handling for authentication.

    Args:
        api: Connected LDAP API (real or demo)

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
            "username": "admin' OR '1'='1",
            "password": "password",
            "expected": "Should be rejected safely",
        },
        {
            "name": "LDAP Injection Attempt",
            "username": "admin)(objectClass=*",
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
        ("cn=admin,dc=example,dc=com", "admin", True, "Admin bind"),
        ("cn=admin,dc=example,dc=com", "wrong", False, "Invalid password"),
        ("cn=invalid,dc=example,dc=com", "password", False, "Invalid DN"),
    ]

    for bind_dn, bind_password, should_succeed, description in test_credentials:
        logger.info(f"\nTest: {description}")
        logger.info(f"   Bind DN: {bind_dn}")

        # Create new API instance with test credentials
        FlextLdapConfig(
            ldap_server_uri=LDAP_URI,
            ldap_bind_dn=bind_dn,
            ldap_bind_password=SecretStr(bind_password),
            ldap_base_dn=BASE_DN,
        )
        test_api = FlextLdap()

        # Try to connect (which includes bind)
        try:
            with test_api:
                status = "✅" if should_succeed else "❌ Unexpected"
                logger.info(f"   {status} Bind SUCCEEDED")
        except Exception as e:
            logger.warning(
                "   ⚠️  Real bind failed (%s). Using demo validation.",
                e,
            )
            success, error = DemoAuthScenarios.validate(bind_dn, bind_password)
            if success:
                status = "✅" if should_succeed else "❌ Unexpected"
                logger.info(f"   {status} Demo bind accepted")
            else:
                status = "❌" if should_succeed else "✅ Expected"
                logger.info(f"   {status} Demo bind rejected: {error}")


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

        try:
            # Authentication demonstrations
            demonstrate_user_authentication(api)
            demonstrate_credential_validation(api)
            demonstrate_authentication_workflow(api)
            demonstrate_authentication_error_handling(api)

            logger.info("\n%s", "=" * 60)
            logger.info("✅ All authentication operations completed successfully!")
            logger.info("=" * 60)

        finally:
            # Always disconnect
            if api.is_connected():
                if hasattr(api, "unbind"):
                    api.unbind()
                else:
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
