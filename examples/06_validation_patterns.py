#!/usr/bin/env python3
"""Validation Patterns Example - flext-ldap Domain Validation.

This example demonstrates comprehensive domain validation using FlextLdapValidations:
- DN (Distinguished Name) validation
- LDAP filter validation
- Configuration validation
- Entry validation for servers
- Business rule validation patterns
- Input sanitization patterns

Uses FlextLdapValidations class for all validation operations.
NO connection required for most validation operations.

Example:
    python examples/06_validation_patterns.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import sys

from flext_core import FlextLogger, FlextResult

from flext_ldap import FlextLdapModels, FlextLdapValidations

logger: FlextLogger = FlextLogger(__name__)


def demonstrate_dn_validation() -> None:
    """Demonstrate DN validation patterns."""
    logger.info("=== DN Validation Patterns ===")

    # Test various DN formats
    test_cases = [
        # Valid DNs
        ("cn=admin,dc=example,dc=com", True, "Standard admin DN"),
        ("uid=john.doe,ou=users,dc=example,dc=com", True, "User DN with UID"),
        ("ou=users,dc=example,dc=com", True, "Organizational Unit DN"),
        (
            "cn=John Doe,ou=People,dc=example,dc=com",
            True,
            "DN with space in value",
        ),
        ("dc=example,dc=com", True, "Base DN"),
        (
            "cn=config",
            True,
            "OpenLDAP config DN",
        ),
        # Invalid DNs
        ("", False, "Empty DN"),
        ("invalid-dn", False, "No RDN components"),
        ("cn=", False, "Empty value"),
        ("=value", False, "Missing attribute type"),
        ("cn=value,", False, "Trailing comma"),
        (",cn=value", False, "Leading comma"),
        ("cn=value,,dc=example", False, "Double comma"),
    ]

    logger.info("\nTesting DN validation:")
    for dn, expected_valid, description in test_cases:
        result: FlextResult[bool] = FlextLdapValidations.validate_dn(dn)

        is_valid = result.is_success
        status = "✅" if is_valid == expected_valid else "❌"

        logger.info(f"\n{status} {description}")
        logger.info(f"   DN: {dn!r}")
        logger.info(f"   Expected: {'Valid' if expected_valid else 'Invalid'}")
        logger.info(f"   Result: {'Valid' if is_valid else 'Invalid'}")

        if not is_valid and result.error:
            logger.info(f"   Error: {result.error}")


def demonstrate_filter_validation() -> None:
    """Demonstrate LDAP filter validation patterns."""
    logger.info("\n=== Filter Validation Patterns ===")

    # Test various filter formats
    test_cases = [
        # Valid filters
        ("(objectClass=person)", True, "Simple equality filter"),
        ("(cn=admin)", True, "Attribute equality"),
        ("(uid=*)", True, "Wildcard filter"),
        ("(mail=*@example.com)", True, "Wildcard in value"),
        ("(&(objectClass=person)(mail=*))", True, "AND filter"),
        ("(|(cn=admin)(cn=user))", True, "OR filter"),
        ("(!(objectClass=person))", True, "NOT filter"),
        (
            "(&(objectClass=inetOrgPerson)(|(mail=*@example.com)(mail=*@test.com)))",
            True,
            "Complex nested filter",
        ),
        ("(cn>=Smith)", True, "Greater-than-or-equal filter"),
        ("(cn<=Doe)", True, "Less-than-or-equal filter"),
        ("(cn~=John)", True, "Approximate match filter"),
        # Invalid filters
        ("", False, "Empty filter"),
        ("objectClass=person", False, "Missing parentheses"),
        ("(objectClass=", False, "Incomplete filter"),
        ("(objectClass=person", False, "Missing closing paren"),
        ("objectClass=person)", False, "Missing opening paren"),
        ("((objectClass=person))", False, "Extra parentheses"),
        ("(&(objectClass=person))", False, "AND with single condition"),
        ("(|)", False, "OR without conditions"),
        ("(&)", False, "AND without conditions"),
    ]

    logger.info("\nTesting filter validation:")
    for filter_str, expected_valid, description in test_cases:
        result: FlextResult[bool] = FlextLdapValidations.validate_filter(filter_str)

        is_valid = result.is_success
        status = "✅" if is_valid == expected_valid else "❌"

        logger.info(f"\n{status} {description}")
        logger.info(f"   Filter: {filter_str!r}")
        logger.info(f"   Expected: {'Valid' if expected_valid else 'Invalid'}")
        logger.info(f"   Result: {'Valid' if is_valid else 'Invalid'}")

        if not is_valid and result.error:
            logger.info(f"   Error: {result.error}")


def demonstrate_attribute_name_validation() -> None:
    """Demonstrate attribute name validation patterns."""
    logger.info("\n=== Attribute Name Validation ===")

    # Test various attribute names
    test_cases = [
        ("cn", True, "Common Name"),
        ("sn", True, "Surname"),
        ("mail", True, "Email"),
        ("objectClass", True, "Object Class"),
        ("uid", True, "User ID"),
        ("givenName", True, "Given Name"),
        ("telephoneNumber", True, "Phone Number"),
        ("userPassword", True, "Password"),
        ("", False, "Empty attribute"),
        ("invalid-attr-name", True, "Hyphenated (may be valid)"),
        ("123invalid", False, "Starting with number"),
        ("attr with space", False, "Space in name"),
    ]

    logger.info("\nTesting attribute name patterns:")
    for attr_name, expected_valid, description in test_cases:
        # Simple validation: non-empty and no spaces
        is_valid = bool(attr_name and " " not in attr_name)
        status = "✅" if is_valid == expected_valid else "❌"
        validity = "Valid" if is_valid else "Invalid"

        logger.info(f"{status} {description}: {attr_name!r} - {validity}")


def demonstrate_search_request_validation() -> None:
    """Demonstrate SearchRequest model validation."""
    logger.info("\n=== SearchRequest Validation ===")

    # Test various SearchRequest configurations
    test_cases: list[dict[str, str | dict[str, str | int | list[str]]]] = [  # type: ignore[reportUnknownVariableType]
        {
            "name": "Valid basic search",
            "params": {
                "base_dn": "dc=example,dc=com",
                "filter_str": "(objectClass=person)",
                "scope": "subtree",
                "attributes": ["cn", "mail"],
                "size_limit": 100,
                "time_limit": 30,
                "page_size": None,
                "paged_cookie": None,
            },
            "should_succeed": True,
        },
        {
            "name": "Valid with paging",
            "params": {
                "base_dn": "ou=users,dc=example,dc=com",
                "filter_str": "(uid=*)",
                "scope": "one",
                "attributes": [],
                "size_limit": 0,
                "time_limit": 0,
                "page_size": 100,
                "paged_cookie": b"",
            },
            "should_succeed": True,
        },
        {
            "name": "Empty base DN",
            "params": {
                "base_dn": "",
                "filter_str": "(objectClass=*)",
                "scope": "base",
                "attributes": [],
                "size_limit": 0,
                "time_limit": 0,
                "page_size": None,
                "paged_cookie": None,
            },
            "should_succeed": False,
        },
        {
            "name": "Invalid scope",
            "params": {
                "base_dn": "dc=example,dc=com",
                "filter_str": "(objectClass=*)",
                "scope": "invalid_scope",
                "attributes": [],
                "size_limit": 0,
                "time_limit": 0,
                "page_size": None,
                "paged_cookie": None,
            },
            "should_succeed": False,
        },
    ]

    logger.info("\nTesting SearchRequest validation:")
    for test_case in test_cases:  # type: ignore[reportUnknownVariableType]
        logger.info(f"\nTest: {test_case['name']}")

        try:
            search_request = FlextLdapModels.SearchRequest(**test_case["params"])  # type: ignore[reportUnknownArgumentType]
            logger.info("   ✅ SearchRequest created successfully")
            logger.info(f"      Base DN: {search_request.base_dn}")
            logger.info(f"      Filter: {search_request.filter_str}")
            logger.info(f"      Scope: {search_request.scope}")

            success = True
        except Exception as e:
            logger.info(f"   ❌ Validation failed: {e}")
            success = False

        expected: bool = test_case["should_succeed"]  # type: ignore[reportUnknownVariableType]
        result_str = "Success" if success else "Failure"
        if success == expected:
            logger.info(f"   Result: As expected ({result_str})")
        else:
            logger.warning(f"   Result: Unexpected ({result_str})")


def demonstrate_input_sanitization() -> None:
    """Demonstrate input sanitization patterns."""
    logger.info("\n=== Input Sanitization Patterns ===")

    # Dangerous inputs that should be sanitized or rejected
    dangerous_inputs = [
        {
            "type": "SQL Injection",
            "input": "admin' OR '1'='1",
            "context": "Username field",
        },
        {
            "type": "LDAP Injection",
            "input": "admin)(objectClass=*",
            "context": "Username for filter",
        },
        {
            "type": "Filter Injection",
            "input": "*)(uid=*",
            "context": "Search filter component",
        },
        {
            "type": "Command Injection",
            "input": "user; rm -rf /",
            "context": "Username field",
        },
        {
            "type": "Path Traversal",
            "input": "../../../etc/passwd",
            "context": "File path input",
        },
    ]

    logger.info("\nDangerous inputs to sanitize:")
    for dangerous in dangerous_inputs:
        logger.info(f"\n{dangerous['type']}:")
        logger.info(f"   Input: {dangerous['input']!r}")
        logger.info(f"   Context: {dangerous['context']}")

        # Demonstrate sanitization
        sanitized = (
            dangerous["input"]
            .replace(")", "\\29")
            .replace("(", "\\28")
            .replace("*", "\\2a")
        )
        logger.info(f"   Sanitized: {sanitized!r}")
        logger.info("   Action: Should be validated and escaped before use")


def demonstrate_business_rule_validation() -> None:
    """Demonstrate business rule validation patterns."""
    logger.info("\n=== Business Rule Validation ===")

    # Example business rules for user creation
    logger.info("\nValidating user creation business rules:")

    # Test case: Valid user
    user_data = {
        "uid": "john.doe",
        "cn": "John Doe",
        "sn": "Doe",
        "mail": "john.doe@example.com",
        "userPassword": "SecureP@ssw0rd123",
    }

    logger.info("\nTest: Valid user data")
    logger.info(f"   UID: {user_data['uid']}")
    logger.info(f"   Email: {user_data['mail']}")

    # Business rule 1: UID must be lowercase alphanumeric with dots
    uid_clean = user_data["uid"].replace(".", "")
    uid_valid = uid_clean.isalnum() and user_data["uid"].islower()
    logger.info(f"   ✅ UID format: {'Valid' if uid_valid else 'Invalid'}")

    # Business rule 2: Email must contain @
    email_valid = "@" in user_data["mail"]
    logger.info(f"   ✅ Email format: {'Valid' if email_valid else 'Invalid'}")

    # Business rule 3: Password must meet complexity requirements
    password = user_data["userPassword"]
    password_valid = (
        len(password) >= 8
        and any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c.isdigit() for c in password)
    )
    pwd_validity = "Valid" if password_valid else "Invalid"
    logger.info(f"   ✅ Password complexity: {pwd_validity}")

    # Test case: Invalid user
    invalid_user = {
        "uid": "Invalid User!",
        "mail": "invalid-email",
        "userPassword": "weak",
    }

    logger.info("\nTest: Invalid user data")
    logger.info(f"   UID: {invalid_user['uid']}")

    uid_clean_inv = invalid_user["uid"].replace(".", "")
    uid_valid = uid_clean_inv.isalnum() and invalid_user["uid"].islower()
    email_valid = "@" in invalid_user["mail"]
    password_valid = len(invalid_user["userPassword"]) >= 8

    logger.info(f"   ❌ UID format: {'Valid' if uid_valid else 'Invalid'}")
    logger.info(f"   ❌ Email format: {'Valid' if email_valid else 'Invalid'}")
    pwd_inv = "Valid" if password_valid else "Invalid"
    logger.info(f"   ❌ Password complexity: {pwd_inv}")


def main() -> int:
    """Run validation patterns demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 60)
    logger.info("FLEXT-LDAP Validation Patterns Example")
    logger.info("=" * 60)
    logger.info("Demonstrating domain validation with FlextLdapValidations")
    logger.info("=" * 60)

    try:
        # Domain validation demonstrations (no connection needed)
        demonstrate_dn_validation()
        demonstrate_filter_validation()
        demonstrate_attribute_name_validation()
        demonstrate_search_request_validation()
        demonstrate_input_sanitization()
        demonstrate_business_rule_validation()

        logger.info(f"\n{'=' * 60}")
        logger.info("✅ All validation patterns demonstrated successfully!")
        logger.info(f"{'=' * 60}")
        logger.info("Key Takeaways:")
        logger.info("- Always validate DNs before LDAP operations")
        logger.info("- Validate and sanitize filters to prevent injection")
        logger.info("- Use Pydantic models for structured validation")
        logger.info("- Implement business rules for domain-specific validation")
        logger.info("- Sanitize user inputs to prevent security issues")
        logger.info("=" * 60)

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        return 1
    except Exception:
        logger.exception("Operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
