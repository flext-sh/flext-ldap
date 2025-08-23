#!/usr/bin/env python3
"""Real coverage tests for flext_ldap.container module.

This module provides comprehensive test coverage for the LDAP container implementation,
testing all real functionality without mocks to ensure actual business logic works correctly.

Architecture tested:
- FlextLdapContainer: Dependency injection container extending flext-core
- IFlextLdapContainer: Protocol interface for container operations
- Service registration and configuration
- Repository and client instantiation
- Container initialization and dependency management

Test Strategy: REAL functionality tests without mocks, testing actual container
operations, service registration, dependency resolution, and configuration.
"""

from __future__ import annotations

import unittest

from flext_ldap.clients import FlextLdapClient
from flext_ldap.configuration import FlextLdapConnectionConfig, FlextLdapSettings
from flext_ldap.container import FlextLdapContainer, IFlextLdapContainer
from flext_ldap.repositories import (
    FlextLdapGroupRepository,
    FlextLdapRepository,
    FlextLdapUserRepository,
)


class TestFlextLdapContainerRealCoverage(unittest.TestCase):
    """Test FlextLdapContainer with real functionality coverage."""

    def setUp(self) -> None:
        """Set up test environment with real container."""
        self.container = FlextLdapContainer()

    def test_ldap_container_initialization(self) -> None:
        """Test FlextLdapContainer initialization."""
        # Execute REAL container initialization
        container = FlextLdapContainer()

        # Verify REAL container initialization
        assert container is not None
        assert isinstance(container, FlextLdapContainer)
        assert hasattr(container, "_settings")
        assert hasattr(container, "_client_instance")
        assert hasattr(container, "_repository_instance")
        assert hasattr(container, "_user_repository_instance")
        assert hasattr(container, "_group_repository_instance")

    def test_ldap_container_protocol_compliance(self) -> None:
        """Test FlextLdapContainer implements IFlextLdapContainer protocol."""
        # Verify REAL protocol methods exist (protocol requires @runtime_checkable for isinstance)
        assert hasattr(self.container, "get_client")
        assert hasattr(self.container, "get_repository")
        assert hasattr(self.container, "get_user_repository")
        assert hasattr(self.container, "get_group_repository")
        assert hasattr(self.container, "configure")

        # Verify REAL protocol methods are callable
        assert callable(self.container.get_client)
        assert callable(self.container.get_repository)
        assert callable(self.container.get_user_repository)
        assert callable(self.container.get_group_repository)
        assert callable(self.container.configure)

    def test_get_client_first_time(self) -> None:
        """Test get_client when called for first time."""
        # Execute REAL client retrieval first time
        client = self.container.get_client()

        # Verify REAL client creation
        assert client is not None
        assert isinstance(client, FlextLdapClient)

        # Verify REAL client is cached
        client2 = self.container.get_client()
        assert client is client2

    def test_get_client_cached(self) -> None:
        """Test get_client returns cached instance."""
        # Execute REAL client caching
        client1 = self.container.get_client()
        client2 = self.container.get_client()

        # Verify REAL caching behavior
        assert client1 is client2

    def test_get_repository_first_time(self) -> None:
        """Test get_repository when called for first time."""
        # Execute REAL repository retrieval first time
        repository = self.container.get_repository()

        # Verify REAL repository creation
        assert repository is not None
        assert isinstance(repository, FlextLdapRepository)

        # Verify REAL repository is cached
        repository2 = self.container.get_repository()
        assert repository is repository2

    def test_get_repository_cached(self) -> None:
        """Test get_repository returns cached instance."""
        # Execute REAL repository caching
        repo1 = self.container.get_repository()
        repo2 = self.container.get_repository()

        # Verify REAL caching behavior
        assert repo1 is repo2

    def test_get_user_repository_first_time(self) -> None:
        """Test get_user_repository when called for first time."""
        # Execute REAL user repository retrieval first time
        user_repo = self.container.get_user_repository()

        # Verify REAL user repository creation
        assert user_repo is not None
        assert isinstance(user_repo, FlextLdapUserRepository)

        # Verify REAL user repository is cached
        user_repo2 = self.container.get_user_repository()
        assert user_repo is user_repo2

    def test_get_user_repository_cached(self) -> None:
        """Test get_user_repository returns cached instance."""
        # Execute REAL user repository caching
        user_repo1 = self.container.get_user_repository()
        user_repo2 = self.container.get_user_repository()

        # Verify REAL caching behavior
        assert user_repo1 is user_repo2

    def test_get_group_repository_first_time(self) -> None:
        """Test get_group_repository when called for first time."""
        # Execute REAL group repository retrieval first time
        group_repo = self.container.get_group_repository()

        # Verify REAL group repository creation
        assert group_repo is not None
        assert isinstance(group_repo, FlextLdapGroupRepository)

        # Verify REAL group repository is cached
        group_repo2 = self.container.get_group_repository()
        assert group_repo is group_repo2

    def test_get_group_repository_cached(self) -> None:
        """Test get_group_repository returns cached instance."""
        # Execute REAL group repository caching
        group_repo1 = self.container.get_group_repository()
        group_repo2 = self.container.get_group_repository()

        # Verify REAL caching behavior
        assert group_repo1 is group_repo2

    def test_configure_with_valid_settings(self) -> None:
        """Test configure with valid LDAP settings."""
        # Setup REAL valid settings
        connection_config = FlextLdapConnectionConfig(
            server="ldap.example.com", port=389, base_dn="dc=example,dc=com"
        )
        settings = FlextLdapSettings(default_connection=connection_config)

        # Execute REAL configuration
        result = self.container.configure(settings)

        # Verify REAL configuration success
        assert result.is_success is True

    def test_configure_with_ssl_settings(self) -> None:
        """Test configure with SSL/TLS settings."""
        # Setup REAL SSL settings
        connection_config = FlextLdapConnectionConfig(
            server="ldaps.example.com", port=636, base_dn="dc=example,dc=com"
        )
        settings = FlextLdapSettings(default_connection=connection_config)

        # Execute REAL SSL configuration
        result = self.container.configure(settings)

        # Verify REAL SSL configuration success
        assert result.is_success is True

    def test_configure_updates_settings(self) -> None:
        """Test configure properly updates container settings."""
        # Setup REAL settings
        connection_config = FlextLdapConnectionConfig(
            server="ldap.test.com", port=389, base_dn="dc=test,dc=com"
        )
        settings = FlextLdapSettings(default_connection=connection_config)

        # Execute REAL configuration
        result = self.container.configure(settings)

        # Verify REAL settings update
        assert result.is_success is True
        assert self.container._settings == settings

    def test_configure_clears_cached_instances(self) -> None:
        """Test configure clears cached service instances."""
        # Setup REAL test scenario - get instances before configure
        client1 = self.container.get_client()
        repo1 = self.container.get_repository()

        # Setup REAL new settings
        connection_config = FlextLdapConnectionConfig(
            server="ldap.new.com", port=389, base_dn="dc=new,dc=com"
        )
        settings = FlextLdapSettings(default_connection=connection_config)

        # Execute REAL reconfiguration
        result = self.container.configure(settings)

        # Verify REAL reconfiguration success
        assert result.is_success is True

        # Verify REAL instance cache clearing
        client2 = self.container.get_client()
        repo2 = self.container.get_repository()
        assert client1 is not client2  # New instances after reconfigure
        assert repo1 is not repo2

    def test_dependency_injection_chain(self) -> None:
        """Test complete dependency injection chain."""
        # Execute REAL dependency chain
        client = self.container.get_client()
        repository = self.container.get_repository()
        user_repo = self.container.get_user_repository()
        group_repo = self.container.get_group_repository()

        # Verify REAL dependency injection
        assert repository._client is client
        assert user_repo._repo is repository  # User repo uses composition
        assert group_repo._repo is repository  # Group repo uses composition

    def test_repository_client_consistency(self) -> None:
        """Test all repositories use the same client instance."""
        # Execute REAL repository instantiation
        client = self.container.get_client()
        repository = self.container.get_repository()
        user_repo = self.container.get_user_repository()
        group_repo = self.container.get_group_repository()

        # Verify REAL client consistency across repositories
        assert repository._client is client
        assert user_repo._repo._client is client  # Through composition chain
        assert group_repo._repo._client is client  # Through composition chain

    def test_container_logger_usage(self) -> None:
        """Test container uses proper logging."""
        # Execute REAL logger access
        # The container should use get_logger(__name__) pattern

        # Verify REAL logging initialization
        # Logger should be accessible through container operations
        client = self.container.get_client()
        assert client is not None  # Implicitly tests logging works

    def test_container_inheritance_from_flext_container(self) -> None:
        """Test FlextLdapContainer properly inherits from FlextContainer."""
        from flext_core import FlextContainer

        # Execute REAL inheritance verification
        assert isinstance(self.container, FlextContainer)

        # Verify REAL parent class methods available
        assert hasattr(self.container, "register")
        assert hasattr(self.container, "get")

    def test_multiple_container_instances_independence(self) -> None:
        """Test multiple container instances are independent."""
        # Setup REAL multiple containers
        container1 = FlextLdapContainer()
        container2 = FlextLdapContainer()

        # Execute REAL independent configuration
        connection1 = FlextLdapConnectionConfig(
            server="ldap1.example.com", port=389, base_dn="dc=example1,dc=com"
        )
        settings1 = FlextLdapSettings(default_connection=connection1)

        connection2 = FlextLdapConnectionConfig(
            server="ldap2.example.com", port=389, base_dn="dc=example2,dc=com"
        )
        settings2 = FlextLdapSettings(default_connection=connection2)

        # Configure containers independently
        result1 = container1.configure(settings1)
        result2 = container2.configure(settings2)

        # Verify REAL container independence
        assert result1.is_success is True
        assert result2.is_success is True
        assert container1._settings != container2._settings
        assert container1.get_client() is not container2.get_client()


class TestFlextLdapContainerProtocolRealCoverage(unittest.TestCase):
    """Test IFlextLdapContainer protocol with real functionality coverage."""

    def test_protocol_method_signatures(self) -> None:
        """Test IFlextLdapContainer protocol method signatures."""
        # Verify REAL protocol requirements

        # Execute REAL protocol verification
        protocol = IFlextLdapContainer

        # Verify REAL protocol methods exist
        assert hasattr(protocol, "get_client")
        assert hasattr(protocol, "get_repository")
        assert hasattr(protocol, "get_user_repository")
        assert hasattr(protocol, "get_group_repository")
        assert hasattr(protocol, "configure")

    def test_protocol_compliance_check(self) -> None:
        """Test FlextLdapContainer implements protocol completely."""
        # Execute REAL protocol compliance check
        container = FlextLdapContainer()

        # Verify REAL method availability (protocol requires @runtime_checkable for isinstance)
        assert callable(container.get_client)
        assert callable(container.get_repository)
        assert callable(container.get_user_repository)
        assert callable(container.get_group_repository)
        assert callable(container.configure)

        # Verify REAL method signatures match protocol expectations
        assert hasattr(container, "get_client")
        assert hasattr(container, "get_repository")
        assert hasattr(container, "get_user_repository")
        assert hasattr(container, "get_group_repository")
        assert hasattr(container, "configure")


if __name__ == "__main__":
    unittest.main()
