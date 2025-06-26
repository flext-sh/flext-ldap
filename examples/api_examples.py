"""🚀 LDAP Core Shared - Unified API Examples.

This module demonstrates the clean, unified LDAP API that provides
maximum functionality with minimum complexity.

Features Demonstrated:
    - Simple configuration setup
    - Fluent query building
    - Semantic operations
    - Context management
    - Error handling
    - Performance optimization

Examples cover:
    - Basic connection and setup
    - Simple and complex searches
    - User and group management
    - Directory statistics
    - Error handling patterns
"""

import asyncio

from ldap_core_shared.api import LDAP, LDAPConfig, connect, ldap_session

# ============================================================================
# 🎯 BASIC USAGE EXAMPLES - Simple, intuitive operations
# ============================================================================


async def basic_connection_example() -> None:
    """Demonstrate basic connection with simple configuration."""
    # Simple configuration
    config = LDAPConfig(
        server="ldaps://ldap.company.com:636",
        auth_dn="cn=admin,dc=company,dc=com",
        auth_password="secret123",
        base_dn="dc=company,dc=com",
    )

    # Use context manager for automatic resource management
    async with LDAP(config) as ldap:
        # Test connection
        await ldap.test_connection()

        # Find IT users
        users = await ldap.find_users_in_department("IT")

        if users.success:
            pass


async def fluent_query_examples() -> None:
    """Demonstrate fluent query interface for complex searches."""
    config = LDAPConfig(
        server="ldap://test-ldap.company.com:389",
        auth_dn="cn=readonly,dc=company,dc=com",
        auth_password="readonly123",
        base_dn="dc=company,dc=com",
    )

    async with LDAP(config) as ldap:

        # Example 1: Find IT department managers
        managers = await (ldap.query()
            .users()
            .in_department("IT")
            .with_title("*Manager*")
            .enabled_only()
            .select("cn", "mail", "title", "department")
            .limit(10)
            .sort_by("cn")
            .execute())

        if managers.success:
            for _user in managers.data[:3]:
                pass

        # Example 2: Find disabled user accounts
        disabled_users = await (ldap.query()
            .users()
            .disabled_only()
            .select("cn", "mail")
            .limit(5)
            .execute())

        if disabled_users.success:
            pass

        # Example 3: Find empty groups
        empty_groups = await ldap.find_empty_groups()

        if empty_groups.success:
            pass


async def semantic_operations_examples() -> None:
    """Demonstrate semantic, domain-specific operations."""
    config = LDAPConfig(
        server="ldap://prod-ldap.company.com:389",
        auth_dn="cn=service,dc=company,dc=com",
        auth_password="service123",
        base_dn="dc=company,dc=com",
    )

    async with LDAP(config) as ldap:

        # Example 1: Find user by email and get their groups
        user_email = "john.doe@company.com"

        user_result = await ldap.find_user_by_email(user_email)
        if user_result.success and user_result.data:
            user = user_result.data

            # Get user's groups
            groups_result = await ldap.get_user_groups(user.get_attribute("cn"))
            if groups_result.success:
                pass

        # Example 2: Check specific group membership
        is_admin = await ldap.is_user_in_group("john.doe", "Domain Admins")
        if is_admin.success:
            pass

        # Example 3: Directory statistics
        stats_result = await ldap.get_directory_stats()
        if stats_result.success:
            pass


async def convenience_functions_examples() -> None:
    """Demonstrate convenience functions for quick usage."""
    # Example 1: Quick connection function
    try:
        ldap = await connect(
            server="ldaps://ldap.company.com:636",
            auth_dn="cn=admin,dc=company,dc=com",
            auth_password="secret",
            base_dn="dc=company,dc=com",
        )

        # Use the connection
        await ldap.test_connection()

        # Don't forget to disconnect
        await ldap._disconnect()

    except Exception:
        pass

    # Example 2: Session context manager
    try:
        async with ldap_session(
            server="ldap://ldap.company.com",
            auth_dn="cn=admin,dc=company,dc=com",
            auth_password="secret",
            base_dn="dc=company,dc=com",
        ) as ldap:
            await ldap.find_users_in_department("IT")

    except Exception:
        pass


async def error_handling_examples() -> None:
    """Demonstrate comprehensive error handling patterns."""
    # Example 1: Connection errors with structured results
    config = LDAPConfig(
        server="ldap://nonexistent-server.com:389",
        auth_dn="cn=test,dc=test,dc=com",
        auth_password="wrongpassword",
        base_dn="dc=test,dc=com",
    )

    async with LDAP(config) as ldap:
        result = await ldap.find_users_in_department("IT")

        if not result.success and result.error_code:
            pass

    # Example 2: Graceful handling of missing data
    config = LDAPConfig(
        server="ldap://test-ldap.company.com:389",
        auth_dn="cn=readonly,dc=company,dc=com",
        auth_password="readonly123",
        base_dn="dc=company,dc=com",
    )

    async with LDAP(config) as ldap:
        # Search for non-existent user
        user_result = await ldap.find_user_by_email("nonexistent@company.com")

        if user_result.success and user_result.data:
            pass


async def performance_examples() -> None:
    """Demonstrate performance optimization patterns."""
    config = LDAPConfig(
        server="ldaps://ldap.company.com:636",
        auth_dn="cn=admin,dc=company,dc=com",
        auth_password="secret123",
        base_dn="dc=company,dc=com",
        pool_size=10,  # Optimize connection pooling
    )

    async with LDAP(config) as ldap:

        # Example 1: Efficient attribute selection
        asyncio.get_event_loop().time()

        # Only select needed attributes instead of "*"
        users = await (ldap.query()
            .users()
            .select("cn", "mail")  # Only essential attributes
            .limit(100)
            .execute())

        asyncio.get_event_loop().time()

        if users.success:
            pass

        # Example 2: Batch operations for efficiency
        departments = ["IT", "HR", "Engineering", "Sales"]

        asyncio.get_event_loop().time()

        # Process multiple departments concurrently
        tasks = [
            ldap.find_users_in_department(dept)
            for dept in departments
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        asyncio.get_event_loop().time()

        total_users = 0
        for _dept, result in zip(departments, results):
            if hasattr(result, "success") and result.success:
                count = len(result.data)
                total_users += count


# ============================================================================
# 🚀 MAIN EXECUTION - Run all examples
# ============================================================================

async def main() -> None:
    """Run all API examples to demonstrate functionality."""
    examples = [
        ("Basic Connection", basic_connection_example),
        ("Fluent Queries", fluent_query_examples),
        ("Semantic Operations", semantic_operations_examples),
        ("Convenience Functions", convenience_functions_examples),
        ("Error Handling", error_handling_examples),
        ("Performance Optimization", performance_examples),
    ]

    for _title, example_func in examples:
        try:
            await example_func()
        except Exception:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    # Run examples
    asyncio.run(main())
