#!/usr/bin/env python3
"""Domain Services Example - flext-ldap API.

This example demonstrates Domain-Driven Design patterns:
- FlextLdapDomain.UserSpecification for user business rules
- FlextLdapDomain.GroupSpecification for group business rules
- FlextLdapDomain.SearchSpecification for search validation
- FlextLdapDomain.DomainServices for domain logic
- Specification Pattern for complex business rules
- Domain-driven validation and business logic

Uses domain.py (FlextLdapDomain) and models.py (FlextLdapModels).

NO connection needed - Domain layer is pure business logic.

Example:
    python examples/12_domain_services.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import sys

from flext_core import FlextLogger

from flext_ldap import FlextLdapDomain, FlextLdapModels

logger: FlextLogger = FlextLogger(__name__)


def demonstrate_domain_driven_design_concepts() -> None:
    """Demonstrate Domain-Driven Design concepts (educational)."""
    logger.info("=== Domain-Driven Design Concepts ===")

    logger.info("\n1. Domain Layer:")
    logger.info("   • Pure business logic - NO infrastructure dependencies")
    logger.info("   • Entities - Objects with identity (User, Group)")
    logger.info("   • Value Objects - Objects without identity (Scope, Filter)")
    logger.info("   • Specifications - Business rule patterns")
    logger.info("   • Domain Services - Business logic that doesn't fit entities")

    logger.info("\n2. FlextLdapDomain Structure:")
    logger.info("   • UserSpecification - User-related business rules")
    logger.info("   • GroupSpecification - Group-related business rules")
    logger.info("   • SearchSpecification - Search validation rules")
    logger.info("   • DomainServices - Domain-level business logic")

    logger.info("\n3. Clean Architecture Benefits:")
    logger.info("   • Domain layer independent of infrastructure")
    logger.info("   • Business rules centralized and testable")
    logger.info("   • NO database/LDAP coupling in domain logic")
    logger.info("   • Portable across different infrastructures")


def demonstrate_user_specification() -> None:
    """Demonstrate UserSpecification business rules."""
    logger.info("\n=== UserSpecification - User Business Rules ===")

    logger.info("\n1. Username Validation:")

    # Test valid usernames
    valid_usernames = ["john_doe", "admin123", "user-name", "test_user_123"]

    for username in valid_usernames:
        is_valid = FlextLdapDomain.UserSpecification.is_valid_username(username)
        status = "✅" if is_valid else "❌"
        logger.info(f"   {status} '{username}': {'Valid' if is_valid else 'Invalid'}")

    # Test invalid usernames
    logger.info("\n2. Invalid Usernames:")
    invalid_usernames = ["ab", "", "user@name", "user name", "user.name!"]

    for username in invalid_usernames:
        is_valid = FlextLdapDomain.UserSpecification.is_valid_username(username)
        status = "✅" if not is_valid else "❌"
        logger.info(
            f"   {status} '{username}': Correctly rejected"
            if not is_valid
            else f"   {status} '{username}': Should be rejected"
        )

    logger.info("\n3. Email Validation:")

    # Test valid emails
    valid_emails = [
        "user@example.com",
        "john.doe@company.org",
        "test+tag@domain.co.uk",
    ]

    for email in valid_emails:
        is_valid = FlextLdapDomain.UserSpecification.is_valid_email(email)
        status = "✅" if is_valid else "❌"
        logger.info(f"   {status} '{email}': {'Valid' if is_valid else 'Invalid'}")

    # Test invalid emails
    logger.info("\n4. Invalid Emails:")
    invalid_emails = [
        "notanemail",
        "missing@domain",
        "@nodomain.com",
        "spaces in@email.com",
    ]

    for email in invalid_emails:
        is_valid = FlextLdapDomain.UserSpecification.is_valid_email(email)
        status = "✅" if not is_valid else "❌"
        logger.info(
            f"   {status} '{email}': Correctly rejected"
            if not is_valid
            else f"   {status} '{email}': Should be rejected"
        )

    logger.info("\n5. Password Policy Validation:")

    # Test valid passwords
    valid_passwords = ["Passw0rd123", "SecureP@ss1", "MyP@ssw0rd"]

    for password in valid_passwords:
        result = FlextLdapDomain.UserSpecification.meets_password_policy(password)
        if result.is_success:
            logger.info(f"   ✅ '{password}': Meets policy")
        else:
            logger.info(f"   ❌ '{password}': {result.error}")

    # Test invalid passwords
    logger.info("\n6. Invalid Passwords:")
    invalid_passwords = [
        ("short", "Too short (< 8 characters)"),
        ("lowercase123", "No uppercase letters"),
        ("UPPERCASE123", "No lowercase letters"),
        ("NoDigitsHere", "No numeric characters"),
    ]

    for password, reason in invalid_passwords:
        result = FlextLdapDomain.UserSpecification.meets_password_policy(password)
        if result.is_failure:
            logger.info(f"   ✅ '{password}': Correctly rejected")
            logger.info(f"      Reason: {result.error}")
        else:
            logger.info(f"   ❌ '{password}': Should be rejected ({reason})")


def demonstrate_group_specification() -> None:
    """Demonstrate GroupSpecification business rules."""
    logger.info("\n=== GroupSpecification - Group Business Rules ===")

    logger.info("\n1. Group Name Validation:")

    # Test valid group names
    valid_names = ["admin_group", "users-team", "group123", "test_group"]

    for name in valid_names:
        is_valid = FlextLdapDomain.GroupSpecification.is_valid_group_name(name)
        status = "✅" if is_valid else "❌"
        logger.info(f"   {status} '{name}': {'Valid' if is_valid else 'Invalid'}")

    # Test invalid group names
    logger.info("\n2. Invalid Group Names:")
    invalid_names = ["a", "", "group name", "group@special"]

    for name in invalid_names:
        is_valid = FlextLdapDomain.GroupSpecification.is_valid_group_name(name)
        status = "✅" if not is_valid else "❌"
        logger.info(
            f"   {status} '{name}': Correctly rejected"
            if not is_valid
            else f"   {status} '{name}': Should be rejected"
        )

    logger.info("\n3. Member Addition Business Rules:")

    # Create a sample group
    group = FlextLdapModels.Group(
        dn="cn=testgroup,ou=groups,dc=example,dc=com",
        cn="testgroup",
        description="Test group for demonstration",
        member_dns=["cn=user1,ou=users,dc=example,dc=com"],
        unique_member_dns=[],
    )

    logger.info(f"   Group: {group.cn}")
    logger.info(f"   Current members: {len(group.member_dns)}")

    # Test adding new member
    new_member = "cn=user2,ou=users,dc=example,dc=com"
    result = FlextLdapDomain.GroupSpecification.can_add_member_to_group(
        group, new_member, max_members=10
    )

    if result.is_success:
        logger.info(f"   ✅ Can add member: {new_member}")
    else:
        logger.info(f"   ❌ Cannot add member: {result.error}")

    # Test adding duplicate member
    duplicate_member = "cn=user1,ou=users,dc=example,dc=com"
    result = FlextLdapDomain.GroupSpecification.can_add_member_to_group(
        group, duplicate_member
    )

    if result.is_failure:
        logger.info(f"   ✅ Correctly rejected duplicate: {result.error}")
    else:
        logger.info("   ❌ Should reject duplicate member")

    # Test empty member DN
    result = FlextLdapDomain.GroupSpecification.can_add_member_to_group(group, "")

    if result.is_failure:
        logger.info(f"   ✅ Correctly rejected empty DN: {result.error}")
    else:
        logger.info("   ❌ Should reject empty DN")


def demonstrate_search_specification() -> None:
    """Demonstrate SearchSpecification business rules."""
    logger.info("\n=== SearchSpecification - Search Validation ===")

    logger.info("\n1. Safe Search Filter Validation:")

    # Test safe filters
    safe_filters = [
        "(objectClass=person)",
        "(uid=john)",
        "(&(cn=*)(mail=*@example.com))",
        "(|(givenName=John)(sn=Doe))",
    ]

    for filter_str in safe_filters:
        result = FlextLdapDomain.SearchSpecification.is_safe_search_filter(filter_str)
        if result.is_success:
            logger.info(f"   ✅ Safe filter: {filter_str}")
        else:
            logger.info(f"   ❌ Rejected: {filter_str} - {result.error}")

    logger.info("\n2. Unsafe Filter Detection:")

    # Test unsafe filters (LDAP injection attempts)
    unsafe_filters = ["", "(**)", "(()())"]

    for filter_str in unsafe_filters:
        result = FlextLdapDomain.SearchSpecification.is_safe_search_filter(filter_str)
        if result.is_failure:
            logger.info(f"   ✅ Correctly blocked: '{filter_str}'")
            logger.info(f"      Reason: {result.error}")
        else:
            logger.info(f"   ⚠️  Should block: '{filter_str}'")

    logger.info("\n3. Search Scope Validation:")

    # Test valid scopes
    test_cases = [
        ("dc=example,dc=com", FlextLdapModels.Scope(value="base"), True),
        ("ou=users,dc=example,dc=com", FlextLdapModels.Scope(value="one"), True),
        ("dc=example,dc=com", FlextLdapModels.Scope(value="subtree"), True),
    ]

    for base_dn, scope, should_pass in test_cases:
        result = FlextLdapDomain.SearchSpecification.validate_search_scope(
            base_dn, scope, max_depth=5
        )

        if result.is_success == should_pass:
            status = "✅" if should_pass else "✅ (correctly rejected)"
            logger.info(f"   {status} Base DN: {base_dn}, Scope: {scope.value}")
        else:
            logger.info(f"   ❌ Unexpected result for: {base_dn}, {scope.value}")

    # Test exceeding depth
    deep_dn = "cn=user,ou=level4,ou=level3,ou=level2,ou=level1,dc=example,dc=com"
    result = FlextLdapDomain.SearchSpecification.validate_search_scope(
        deep_dn, FlextLdapModels.Scope(value="subtree"), max_depth=5
    )

    if result.is_failure:
        logger.info("\n   ✅ Correctly rejected deep DN:")
        logger.info(f"      DN: {deep_dn}")
        logger.info(f"      Reason: {result.error}")


def demonstrate_domain_services() -> None:
    """Demonstrate DomainServices business logic."""
    logger.info("\n=== DomainServices - Business Logic ===")

    logger.info("\n1. User Display Name Calculation:")

    # Test different scenarios
    user_scenarios = [
        {
            "name": "User with display name",
            "user": FlextLdapModels.LdapUser(
                dn="cn=john,dc=example,dc=com",
                uid="john",
                cn="john",
                sn="Doe",
                display_name="John Doe (Executive)",
            ),
            "expected": "John Doe (Executive)",
        },
        {
            "name": "User with given name and surname",
            "user": FlextLdapModels.LdapUser(
                dn="cn=jane,dc=example,dc=com",
                uid="jane",
                cn="jane",
                sn="Smith",
                given_name="Jane",
            ),
            "expected": "Jane Smith",
        },
        {
            "name": "User with only CN",
            "user": FlextLdapModels.LdapUser(
                dn="cn=admin,dc=example,dc=com", uid="admin", cn="admin", sn="Admin"
            ),
            "expected": "admin",
        },
    ]

    for scenario in user_scenarios:
        display_name = FlextLdapDomain.DomainServices.calculate_user_display_name(
            scenario["user"]
        )
        is_correct = display_name == scenario["expected"]
        status = "✅" if is_correct else "❌"

        logger.info(f"   {status} {scenario['name']}")
        logger.info(f"      Result: {display_name}")
        logger.info(f"      Expected: {scenario['expected']}")


def demonstrate_specification_pattern_benefits() -> None:
    """Demonstrate Specification Pattern benefits (educational)."""
    logger.info("\n=== Specification Pattern Benefits ===")

    logger.info("\n1. Business Rule Encapsulation:")
    logger.info("   • Rules centralized in specification classes")
    logger.info("   • Reusable across application layers")
    logger.info("   • Testable in isolation")
    logger.info("   • Self-documenting business logic")

    logger.info("\n2. Specification Composition:")
    logger.info("   • AND specifications - All rules must pass")
    logger.info("   • OR specifications - object rule can pass")
    logger.info("   • NOT specifications - Inverse logic")
    logger.info("   • Complex business rules from simple building blocks")

    logger.info("\n3. Domain Logic Clarity:")
    logger.info("   Example code:")
    logger.info("   ```python")
    logger.info("   # Clear, readable business rule check")
    logger.info("   if not UserSpecification.is_valid_username(username):")
    logger.info("       return FlextResult.fail('Invalid username')")
    logger.info("   ")
    logger.info("   # vs scattered validation logic")
    logger.info("   if len(username) < 3 or not username.isalnum():")
    logger.info("       # Business rule unclear and duplicated")
    logger.info("   ```")

    logger.info("\n4. Testing Advantages:")
    logger.info("   • Test business rules independently")
    logger.info("   • NO infrastructure setup needed")
    logger.info("   • Fast unit tests for domain logic")
    logger.info("   • Clear test cases for each rule")


def demonstrate_domain_service_patterns() -> None:
    """Demonstrate Domain Service patterns (educational)."""
    logger.info("\n=== Domain Service Patterns ===")

    logger.info("\n1. When to Use Domain Services:")
    logger.info("   • Logic doesn't naturally fit in entities")
    logger.info("   • Operations involving multiple entities")
    logger.info("   • Business calculations and transformations")
    logger.info("   • Domain-specific algorithms")

    logger.info("\n2. Domain Service Characteristics:")
    logger.info("   • Stateless - NO instance variables")
    logger.info("   • Domain-focused - Pure business logic")
    logger.info("   • Infrastructure-free - NO database/LDAP dependencies")
    logger.info("   • Testable - Easy to unit test")

    logger.info("\n3. Example Domain Services:")
    logger.info("   • calculate_user_display_name() - Display name rules")
    logger.info("   • validate_user_credentials() - Authentication logic")
    logger.info("   • calculate_group_permissions() - Authorization logic")
    logger.info("   • generate_user_email() - Email generation rules")

    logger.info("\n4. Domain vs Application Services:")
    logger.info("   Domain Services:")
    logger.info("   • Pure business logic")
    logger.info("   • NO infrastructure dependencies")
    logger.info("   • Reusable domain knowledge")
    logger.info("   ")
    logger.info("   Application Services:")
    logger.info("   • Orchestrate use cases")
    logger.info("   • Coordinate domain objects")
    logger.info("   • May use infrastructure")


def main() -> int:
    """Run domain services demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 70)
    logger.info("FLEXT-LDAP Domain Services Example")
    logger.info("=" * 70)
    logger.info("Demonstrates: Domain-Driven Design, Specification Pattern")
    logger.info("Modules: domain.py, models.py")
    logger.info("NO connection needed - Pure domain logic")
    logger.info("=" * 70)

    try:
        # 1. DDD concepts
        demonstrate_domain_driven_design_concepts()

        # 2. UserSpecification
        demonstrate_user_specification()

        # 3. GroupSpecification
        demonstrate_group_specification()

        # 4. SearchSpecification
        demonstrate_search_specification()

        # 5. DomainServices
        demonstrate_domain_services()

        # 6. Specification Pattern benefits
        demonstrate_specification_pattern_benefits()

        # 7. Domain Service patterns
        demonstrate_domain_service_patterns()

        logger.info(f"\n{'=' * 70}")
        logger.info("✅ Domain services demonstration completed!")
        logger.info(f"{'=' * 70}")

        logger.info("\nKey Takeaways:")
        logger.info("  • FlextLdapDomain - Pure business logic layer")
        logger.info("  • UserSpecification - User business rules")
        logger.info("  • GroupSpecification - Group business rules")
        logger.info("  • SearchSpecification - Search validation rules")
        logger.info("  • DomainServices - Domain-level operations")

        logger.info("\nDomain-Driven Design Benefits:")
        logger.info("  • Business logic centralized and testable")
        logger.info("  • NO infrastructure dependencies in domain")
        logger.info("  • Specification Pattern for complex rules")
        logger.info("  • Clear separation of concerns")
        logger.info("  • Portable across different infrastructures")

        logger.info("\nSpecification Pattern Usage:")
        logger.info("  ```python")
        logger.info("  from flext_ldap.domain import FlextLdapDomain")
        logger.info("  ")
        logger.info("  # Validate username")
        logger.info(
            "  is_valid = FlextLdapDomain.UserSpecification.is_valid_username('john')"
        )
        logger.info("  ")
        logger.info("  # Check password policy")
        logger.info(
            "  result = FlextLdapDomain.UserSpecification.meets_password_policy('Passw0rd')"
        )
        logger.info("  if result.is_success:")
        logger.info("      print('Password meets policy')")
        logger.info("  ```")

        logger.info("\nDomain Service Usage:")
        logger.info("  ```python")
        logger.info("  from flext_ldap.domain import FlextLdapDomain")
        logger.info("  ")
        logger.info("  # Calculate display name")
        logger.info(
            "  display_name = FlextLdapDomain.DomainServices.calculate_user_display_name(user)"
        )
        logger.info("  ```")

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        return 1
    except Exception:
        logger.exception("Operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
