#!/usr/bin/env python3
"""Repository Patterns Example - flext-ldap API.

This example demonstrates Domain-Driven Design repository patterns:
- FlextLdapRepositories.UserRepository for user entity management
- FlextLdapRepositories.GroupRepository for group entity management
- Domain.Repository protocol implementation
- CRUD operations through repository pattern
- Entity lifecycle management
- Repository pattern benefits for clean architecture

Uses api.py (FlextLdap) and repositories.py (FlextLdapRepositories).

Environment Variables:
    LDAP_SERVER_URI: LDAP server URI (default: ldap://localhost:389)
    LDAP_BIND_DN: Bind DN (default: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: REDACTED_LDAP_BIND_PASSWORD)
    LDAP_BASE_DN: Base DN (default: dc=example,dc=com)

Example:
    python examples/11_repository_patterns.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import sys
from typing import Final

from flext_core import FlextCore
from pydantic import SecretStr

from flext_ldap import (
    FlextLdap,
    FlextLdapClients,
    FlextLdapConfig,
    FlextLdapRepositories,
)

logger: FlextCore.Logger = FlextCore.Logger(__name__)

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
    FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD) if BIND_PASSWORD else None,
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap()

    # Use context manager for automatic connection/disconnection
    try:
        with api:
            return api
    except Exception:
        logger.exception("Connection failed")
        return None


def demonstrate_repository_pattern_basics() -> None:
    """Demonstrate basic repository pattern concepts (no connection needed)."""
    logger.info("=== Repository Pattern Basics ===")

    logger.info("\n1. Repository Pattern Benefits:")
    logger.info("   • Abstraction over data access layer")
    logger.info("   • Clean separation of domain and infrastructure")
    logger.info("   • Testability through interface substitution")
    logger.info("   • Centralized data access logic")
    logger.info("   • Domain-Driven Design alignment")

    logger.info("\n2. FlextLdapRepositories Structure:")
    logger.info("   • LdapRepository - Abstract base implementing Domain.Repository")
    logger.info("   • UserRepository - User entity management")
    logger.info("   • GroupRepository - Group entity management")
    logger.info("   • All implement flext-core Domain.Repository protocol")

    logger.info("\n3. Domain.Repository Protocol Methods:")
    logger.info("   • get_by_id(id) - Retrieve entity by identifier")
    logger.info("   • get_all() - Retrieve all entities")
    logger.info("   • add(entity) - Create new entity")
    logger.info("   • update(entity) - Update existing entity")
    logger.info("   • delete(id) - Remove entity")
    logger.info("   • exists(id) - Check entity existence")


def demonstrate_user_repository() -> None:
    """Demonstrate UserRepository operations."""
    logger.info("\n=== UserRepository Operations ===")

    # Create UserRepository instance
    config = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD) if BIND_PASSWORD else None,
        ldap_base_dn=BASE_DN,
    )
    client = FlextLdapClients(config=config)
    FlextLdapRepositories.UserRepository(client=client)

    logger.info("\n1. Creating UserRepository instance:")
    logger.info("   ✅ UserRepository initialized")
    logger.info("   • Type: FlextLdapRepositories.UserRepository")
    logger.info("   • Protocol: Implements Domain.Repository[User]")

    logger.info("\n2. Repository CRUD Operations:")
    logger.info("   Available methods (Domain.Repository protocol):")
    logger.info("   • get_by_id(id) -> FlextCore.Result[User | None]")
    logger.info("   • get_all() -> FlextCore.Result[list[User]]")
    logger.info("   • add(user) -> FlextCore.Result[User]")
    logger.info("   • update(user) -> FlextCore.Result[User]")
    logger.info("   • delete(id) -> FlextCore.Result[bool]")
    logger.info("   • exists(id) -> FlextCore.Result[bool]")

    logger.info("\n3. User Lookup by ID (DN or UID):")
    logger.info("   • Supports both DN and UID lookup")
    logger.info("   • Automatic fallback from DN to UID search")
    logger.info("   • Returns FlextCore.Result[User | None]")

    logger.info("\n4. Get All Users:")
    logger.info("   • Retrieves all users from user base DN")
    logger.info("   • Returns FlextCore.Result[list[User]]")
    logger.info("   • Efficient for bulk operations")


def demonstrate_group_repository() -> None:
    """Demonstrate GroupRepository operations."""
    logger.info("\n=== GroupRepository Operations ===")

    # Create GroupRepository instance
    config = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD) if BIND_PASSWORD else None,
        ldap_base_dn=BASE_DN,
    )
    client = FlextLdapClients(config=config)
    FlextLdapRepositories.GroupRepository(client=client)

    logger.info("\n1. Creating GroupRepository instance:")
    logger.info("   ✅ GroupRepository initialized")
    logger.info("   • Type: FlextLdapRepositories.GroupRepository")
    logger.info("   • Protocol: Implements Domain.Repository[Group]")

    logger.info("\n2. Repository CRUD Operations:")
    logger.info("   Available methods (Domain.Repository protocol):")
    logger.info("   • get_by_id(id) -> FlextCore.Result[Group | None]")
    logger.info("   • get_all() -> FlextCore.Result[list[Group]]")
    logger.info("   • add(group) -> FlextCore.Result[Group]")
    logger.info("   • update(group) -> FlextCore.Result[Group]")
    logger.info("   • delete(id) -> FlextCore.Result[bool]")
    logger.info("   • exists(id) -> FlextCore.Result[bool]")

    logger.info("\n3. Group Lookup by ID:")
    logger.info("   • Supports DN lookup")
    logger.info("   • Group-specific search capabilities")
    logger.info("   • Returns FlextCore.Result[Group | None]")

    logger.info("\n4. Group Management:")
    logger.info("   • Create new groups")
    logger.info("   • Update group attributes")
    logger.info("   • Delete groups")
    logger.info("   • List all groups")


def demonstrate_repository_entity_lifecycle() -> None:
    """Demonstrate entity lifecycle management through repositories."""
    logger.info("\n=== Entity Lifecycle Management ===")

    logger.info("\n1. Create Phase:")
    logger.info("   • Create domain entity (User, Group)")
    logger.info("   • Validate entity using Pydantic models")
    logger.info("   • Call repository.add(entity)")
    logger.info("   • Repository converts entity to LDAP entry")
    logger.info("   • Returns FlextCore.Result[Entity] with created entity")

    logger.info("\n2. Read Phase:")
    logger.info("   • Call repository.get_by_id(id)")
    logger.info("   • Repository queries LDAP server")
    logger.info("   • Converts LDAP entry to domain entity")
    logger.info("   • Returns FlextCore.Result[Entity | None]")

    logger.info("\n3. Update Phase:")
    logger.info("   • Modify entity attributes")
    logger.info("   • Call repository.update(entity)")
    logger.info("   • Repository calculates LDAP modifications")
    logger.info("   • Applies changes to LDAP server")
    logger.info("   • Returns FlextCore.Result[Entity] with updated entity")

    logger.info("\n4. Delete Phase:")
    logger.info("   • Call repository.delete(id)")
    logger.info("   • Repository removes LDAP entry")
    logger.info("   • Returns FlextCore.Result[bool]")
    logger.info("   • True if deleted, False if not found")


def demonstrate_repository_with_flextresult() -> None:
    """Demonstrate repository error handling with FlextCore.Result pattern."""
    logger.info("\n=== Repository Error Handling with FlextCore.Result ===")

    logger.info("\n1. Successful Operation:")
    logger.info("   Example code:")
    logger.info("   ```python")
    logger.info("   result = user_repo.get_by_id('john.doe')")
    logger.info("   if result.is_success:")
    logger.info("       user = result.unwrap()")
    logger.info("       print(f'Found user: {user.cn}')")
    logger.info("   ```")

    logger.info("\n2. Failure Handling:")
    logger.info("   Example code:")
    logger.info("   ```python")
    logger.info("   result = user_repo.get_by_id('nonexistent')")
    logger.info("   if result.is_failure:")
    logger.info("       error_msg = result.error")
    logger.info("       print(f'Lookup failed: {error_msg}')")
    logger.info("   ```")

    logger.info("\n3. Entity Not Found (None Result):")
    logger.info("   Example code:")
    logger.info("   ```python")
    logger.info("   result = user_repo.get_by_id('unknown')")
    logger.info("   if result.is_success:")
    logger.info("       user = result.unwrap()")
    logger.info("       if user is None:")
    logger.info("           print('User not found')")
    logger.info("   ```")

    logger.info("\n4. Railway-Oriented Programming:")
    logger.info("   • All repository methods return FlextCore.Result")
    logger.info("   • Chain operations safely")
    logger.info("   • NO try/except fallbacks needed")
    logger.info("   • Explicit error handling flow")


def demonstrate_repository_clean_architecture() -> None:
    """Demonstrate repository role in Clean Architecture."""
    logger.info("\n=== Repository in Clean Architecture ===")

    logger.info("\n1. Architecture Layers:")
    logger.info("   • Domain Layer - User, Group entities (models.py)")
    logger.info("   • Application Layer - FlextLdap API (api.py)")
    logger.info("   • Infrastructure Layer - Repositories (repositories.py)")
    logger.info("   • Infrastructure Layer - LDAP Client (clients.py)")

    logger.info("\n2. Repository Benefits:")
    logger.info("   • Isolates domain from infrastructure details")
    logger.info("   • Enables domain-focused business logic")
    logger.info("   • Testable through interface substitution")
    logger.info("   • Centralized data access patterns")

    logger.info("\n3. Dependency Flow:")
    logger.info("   Domain (entities) ← Application (API) ← Infrastructure (repos)")
    logger.info("   • Domain has NO dependencies")
    logger.info("   • Application depends on Domain")
    logger.info("   • Infrastructure depends on Domain + Application")
    logger.info("   • Infrastructure implements Domain.Repository protocol")

    logger.info("\n4. Repository Pattern vs Direct Client:")
    logger.info("   Repository Pattern:")
    logger.info("   • Domain-centric interface (User, Group)")
    logger.info("   • Protocol-based (Domain.Repository)")
    logger.info("   • Entity lifecycle management")
    logger.info("   • Easy to mock for testing")
    logger.info("   ")
    logger.info("   Direct Client:")
    logger.info("   • LDAP-centric operations")
    logger.info("   • Infrastructure details exposed")
    logger.info("   • Lower-level control")
    logger.info("   • More flexible for custom operations")


def demonstrate_repository_testing_benefits() -> None:
    """Demonstrate repository testing benefits (educational)."""
    logger.info("\n=== Repository Testing Benefits ===")

    logger.info("\n1. Unit Testing with Mocks:")
    logger.info("   Example test code:")
    logger.info("   ```python")
    logger.info("   # Create mock repository")
    logger.info("   class MockUserRepository(LdapRepository[User]):")
    logger.info("       def get_by_id(self, id: str) -> FlextCore.Result[User | None]:")
    logger.info("           return FlextCore.Result[User | None].ok(mock_user)")
    logger.info("   ")
    logger.info("   # Test business logic without LDAP")
    logger.info("   user_service = UserService(MockUserRepository())")
    logger.info("   result = user_service.process_user('john')")
    logger.info("   assert result.is_success")
    logger.info("   ```")

    logger.info("\n2. Integration Testing:")
    logger.info("   • Use real repository with test LDAP server")
    logger.info("   • Verify repository operations end-to-end")
    logger.info("   • Test LDAP protocol compliance")
    logger.info("   • Validate entity mapping accuracy")

    logger.info("\n3. Test Isolation:")
    logger.info("   • Repository interface enables test doubles")
    logger.info("   • Business logic tests independent of LDAP")
    logger.info("   • Fast unit tests without infrastructure")
    logger.info("   • Focused integration tests for data access")


def demonstrate_repository_advanced_patterns() -> None:
    """Demonstrate advanced repository patterns."""
    logger.info("\n=== Advanced Repository Patterns ===")

    logger.info("\n1. Specification Pattern (Future):")
    logger.info("   • Complex query objects")
    logger.info("   • Composable search criteria")
    logger.info("   • Domain-specific queries")
    logger.info("   • Reusable query logic")

    logger.info("\n2. Unit of Work Pattern (Future):")
    logger.info("   • Transaction-like semantics")
    logger.info("   • Batch operation coordination")
    logger.info("   • Consistent state management")
    logger.info("   • Atomic multi-entity operations")

    logger.info("\n3. Query Object Pattern:")
    logger.info("   • Separate read operations")
    logger.info("   • Optimized queries for reporting")
    logger.info("   • CQRS (Command Query Responsibility Segregation)")
    logger.info("   • Read models vs write models")

    logger.info("\n4. Repository Composition:")
    logger.info("   • Combine multiple repositories")
    logger.info("   • Cross-entity operations")
    logger.info("   • Coordinated data access")
    logger.info("   • Aggregate management")


def main() -> int:
    """Run repository patterns demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 70)
    logger.info("FLEXT-LDAP Repository Patterns Example")
    logger.info("=" * 70)
    logger.info("Demonstrates: Domain-Driven Design repository pattern")
    logger.info("Modules: repositories.py, models.py")
    logger.info("=" * 70)

    try:
        # 1. Repository basics (no connection needed)
        demonstrate_repository_pattern_basics()

        # 2. Connect to LDAP server
        logger.info(f"\n{'=' * 70}")
        logger.info("Connecting to LDAP server for repository demonstrations...")
        api = setup_api()

        if not api:
            logger.warning("Cannot demonstrate live operations without connection")
            logger.info("Continuing with conceptual demonstrations...")

        try:
            # 3. UserRepository
            if api:
                demonstrate_user_repository()

            # 4. GroupRepository
            if api:
                demonstrate_group_repository()

            # 5. Entity lifecycle
            demonstrate_repository_entity_lifecycle()

            # 6. FlextCore.Result error handling
            demonstrate_repository_with_flextresult()

            # 7. Clean Architecture
            demonstrate_repository_clean_architecture()

            # 8. Testing benefits
            demonstrate_repository_testing_benefits()

            # 9. Advanced patterns
            demonstrate_repository_advanced_patterns()

            logger.info(f"\n{'=' * 70}")
            logger.info("✅ Repository patterns demonstration completed!")
            logger.info("=" * 70)

            logger.info("\nKey Takeaways:")
            logger.info("  • FlextLdapRepositories - Domain-Driven Design pattern")
            logger.info("  • UserRepository & GroupRepository - Entity management")
            logger.info("  • Domain.Repository protocol - Standard interface")
            logger.info(
                "  • FlextCore.Result integration - Railway-oriented programming"
            )
            logger.info("  • Clean Architecture - Infrastructure abstraction")

            logger.info("\nRepository Pattern Benefits:")
            logger.info("  • Abstraction over LDAP complexity")
            logger.info("  • Domain-centric entity management")
            logger.info("  • Testability through interface substitution")
            logger.info("  • Centralized data access logic")
            logger.info("  • Clean Architecture compliance")

            logger.info("\nUsage Example:")
            logger.info("  ```python")
            logger.info(
                "  from flext_ldap import FlextLdapRepositories, FlextLdapClients"
            )
            logger.info("  ")
            logger.info("  client = FlextLdapClients(config)")
            logger.info("  user_repo = FlextLdapRepositories.UserRepository(client)")
            logger.info("  ")
            logger.info("  # Get user by ID")
            logger.info("  result = user_repo.get_by_id('john.doe')")
            logger.info("  if result.is_success:")
            logger.info("      user = result.unwrap()")
            logger.info("  ```")

        finally:
            # Always disconnect
            if api and api.is_connected():
                api.unbind()
                logger.info("\nDisconnected from LDAP server")

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        return 1
    except Exception:
        logger.exception("Operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
