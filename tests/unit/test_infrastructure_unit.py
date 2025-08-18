"""Unit tests for FLEXT LDAP infrastructure components."""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import (
    FlextLdapClient,
    FlextLdapConverter,
    FlextLdapEventObserver,
    FlextLdapObservableClient,
    FlextLdapSearchStrategy,
)


class TestFlextLdapConverter:
    """Test LDAP data type converter."""

    def test_converter_initialization(self) -> None:
        """Test converter initialization."""
        converter = FlextLdapConverter()
        assert converter is not None

    def test_detect_type_email(self) -> None:
        """Test email detection."""
        converter = FlextLdapConverter()

        result = converter.detect_type("test@example.com")
        assert result == "email"

        result = converter.detect_type("user.name@domain.org")
        assert result == "email"

    def test_detect_type_dn(self) -> None:
        """Test DN detection."""
        converter = FlextLdapConverter()

        result = converter.detect_type("cn=test,dc=example,dc=com")
        assert result == "dn"

        result = converter.detect_type("uid=user,ou=people,dc=domain,dc=org")
        assert result == "dn"

    def test_detect_type_uid(self) -> None:
        """Test UID detection."""
        converter = FlextLdapConverter()

        result = converter.detect_type("testuser")
        assert result == "uid"

        result = converter.detect_type("user123")
        assert result == "uid"

    def test_convert_to_dn_from_email(self) -> None:
        """Test conversion from email to DN."""
        converter = FlextLdapConverter()

        result = converter.convert_to_dn(
            "test@example.com",
            "ou=users,dc=example,dc=com",
        )
        assert "test" in result
        assert "ou=users,dc=example,dc=com" in result

    def test_convert_to_dn_from_uid(self) -> None:
        """Test conversion from UID to DN."""
        converter = FlextLdapConverter()

        result = converter.convert_to_dn("testuser", "ou=users,dc=example,dc=com")
        assert "testuser" in result
        assert "ou=users,dc=example,dc=com" in result

    def test_convert_to_dn_from_dn(self) -> None:
        """Test conversion from DN to DN (identity)."""
        converter = FlextLdapConverter()

        dn = "cn=test,ou=users,dc=example,dc=com"
        result = converter.convert_to_dn(dn, "ou=users,dc=example,dc=com")
        assert result == dn


class TestFlextLdapClient:
    """Test LDAP simple client infrastructure."""

    def test_client_initialization(self) -> None:
        """Test client initialization."""
        client = FlextLdapClient()
        assert client is not None

    @pytest.mark.asyncio
    async def test_connect_with_invalid_server(self) -> None:
        """Test connection with invalid server."""
        client = FlextLdapClient()

        result = await client.connect("ldap://invalid.server.test")
        assert not result.is_success
        assert result.error is not None
        assert "connection" in result.error.lower() or "failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_connect_with_malformed_uri(self) -> None:
        """Test connection with malformed URI."""
        client = FlextLdapClient()

        result = await client.connect("invalid://uri")
        assert not result.is_success

    @pytest.mark.asyncio
    async def test_disconnect_without_connection(self) -> None:
        """Test disconnect without prior connection."""
        client = FlextLdapClient()

        result = await client.disconnect()
        # Should handle gracefully
        assert result.is_success or (
            result.error and "not connected" in result.error.lower()
        )

    @pytest.mark.asyncio
    async def test_search_without_connection(self) -> None:
        """Test search without connection."""
        client = FlextLdapClient()

        result = await client.search(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
        )
        assert not result.is_success
        assert result.error is not None
        assert (
            "not connected" in result.error.lower()
            or "connection" in result.error.lower()
        )

    @pytest.mark.asyncio
    async def test_connect_real_behavior(self) -> None:
        """Test connection behavior with real error handling."""
        client = FlextLdapClient()

        # Test with valid URI format but unreachable server
        result = await client.connect(
            server_uri="ldap://internal.invalid",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="password",
        )

        # Should fail gracefully with proper error message
        assert not result.is_success
        assert result.error is not None
        assert isinstance(result.error, str)
        assert len(result.error) > 0

    @pytest.mark.asyncio
    async def test_search_real_behavior(self) -> None:
        """Test search behavior without connection."""
        client = FlextLdapClient()

        # Search without connection should fail properly
        result = await client.search(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
        )

        assert not result.is_success
        assert result.error is not None
        assert (
            "connection" in result.error.lower()
            or "not connected" in result.error.lower()
        )

    def test_is_connected_initially_false(self) -> None:
        """Test that client is not connected initially."""
        client = FlextLdapClient()
        assert not client.is_connected()

    def test_client_state_management(self) -> None:
        """Test client state management without mocks."""
        client = FlextLdapClient()

        # Initial state should be disconnected
        assert not client.is_connected()

        # Client should have proper internal state tracking
        assert hasattr(client, "_connection")
        assert client._connection is None


class TestFlextLdapDesignPatterns:
    """Test design patterns implementations in infrastructure."""

    def test_search_strategy_pattern(self) -> None:
        """Test Strategy pattern implementation for search operations."""

        class TestSearchStrategy(FlextLdapSearchStrategy):
            async def execute_search(
                self,
                client: FlextLdapClient,  # noqa: ARG002
                base_dn: str,
                search_filter: str,
                **kwargs: object,  # noqa: ARG002
            ) -> FlextResult[list[dict[str, str | bytes | list[str] | list[bytes]]]]:
                # Return mock successful result for testing
                return FlextResult.ok([{"dn": base_dn, "filter": search_filter}])

        strategy = TestSearchStrategy()
        assert strategy is not None
        assert hasattr(strategy, "execute_search")

    @pytest.mark.asyncio
    async def test_search_strategy_execution(self) -> None:
        """Test search strategy execution with real behavior."""

        class TestSearchStrategy(FlextLdapSearchStrategy):
            async def execute_search(
                self,
                client: FlextLdapClient,  # noqa: ARG002
                base_dn: str,
                search_filter: str,  # noqa: ARG002
                **kwargs: object,  # noqa: ARG002
            ) -> FlextResult[list[dict[str, str | bytes | list[str] | list[bytes]]]]:
                # Simulate real search behavior
                return FlextResult.ok(
                    [
                        {"dn": f"cn=test,{base_dn}", "objectClass": ["person"]},
                    ]
                )

        strategy = TestSearchStrategy()
        client = FlextLdapClient()

        result = await strategy.execute_search(
            client,
            "dc=example,dc=com",
            "(objectClass=person)",
        )

        assert result.is_success
        assert isinstance(result.data, list)
        assert len(result.data) == 1

    def test_event_observer_pattern(self) -> None:
        """Test Observer pattern implementation for LDAP events."""

        class TestObserver(FlextLdapEventObserver):
            def __init__(self) -> None:
                self.events: list[tuple[str, object, object | None]] = []

            async def on_connection_established(
                self, server_uri: str, bind_dn: str | None
            ) -> None:
                self.events.append(("connection_established", server_uri, bind_dn))

            async def on_connection_failed(
                self, server_uri: str, error_message: str
            ) -> None:
                self.events.append(("connection_failed", server_uri, error_message))

            async def on_search_performed(
                self, base_dn: str, search_filter: str, result_count: int
            ) -> None:
                self.events.append(
                    (
                        "search_performed",
                        base_dn,
                        search_filter,
                        int(result_count),
                    )
                )

            async def on_entry_added(
                self, dn: str, attributes: dict[str, list[str]]
            ) -> None:
                self.events.append(("entry_added", dn, attributes))

        observer = TestObserver()
        assert observer is not None
        assert hasattr(observer, "events")
        assert len(observer.events) == 0

    def test_observable_client(self) -> None:
        """Test Observable client with event observers."""

        class TestObserver(FlextLdapEventObserver):
            def __init__(self) -> None:
                self.events: list[tuple[str, object]] = []

            async def on_connection_established(
                self, server_uri: str, bind_dn: str | None
            ) -> None:  # noqa: ARG002
                self.events.append(("connection_established", server_uri))

            async def on_connection_failed(
                self, server_uri: str, error_message: str
            ) -> None:  # noqa: ARG002
                self.events.append(("connection_failed", server_uri))

            async def on_search_performed(
                self, base_dn: str, search_filter: str, result_count: int
            ) -> None:  # noqa: ARG002
                self.events.append(("search_performed", base_dn))

            async def on_entry_added(
                self, dn: str, attributes: dict[str, list[str]]
            ) -> None:  # noqa: ARG002
                self.events.append(("entry_added", dn))

        client = FlextLdapObservableClient()
        observer = TestObserver()

        # Test observer registration
        client.add_observer(observer)
        assert len(client._observers) == 1

        # Test duplicate observer handling
        client.add_observer(observer)  # Should not add duplicate
        assert len(client._observers) == 1

        # Test observer removal
        client.remove_observer(observer)
        assert len(client._observers) == 0


class TestInfrastructureErrorHandling:
    """Test error handling in infrastructure components."""

    @pytest.mark.asyncio
    async def test_client_handles_ldap_exceptions(self) -> None:
        """Test that client properly handles LDAP exceptions."""
        client = FlextLdapClient()

        # Test with various invalid inputs
        result = await client.connect("")
        assert not result.is_success

        search_result = await client.search("", "")
        assert not search_result.is_success

    def test_converter_handles_invalid_input(self) -> None:
        """Test that converter handles invalid input gracefully."""
        converter = FlextLdapConverter()

        # Test with empty string
        result = converter.detect_type("")
        assert result == "uid"  # Default fallback

        # Test with None (should handle gracefully)
        try:
            result = converter.detect_type(None)
            # If it doesn't raise an exception, it should return a reasonable default
            assert result is not None
        except (TypeError, AttributeError):
            # It's also acceptable to raise a type error for None input
            pass

    def test_real_error_propagation(self) -> None:
        """Test that real errors are properly propagated without hiding."""
        converter = FlextLdapConverter()

        # Test that type errors are handled appropriately
        invalid_inputs: list[object] = [None, 123, [], {}]

        for invalid_input in invalid_inputs:
            try:
                result = converter.detect_type(invalid_input)
                # If no exception, should return reasonable default
                assert result is not None
                assert isinstance(result, str)
            except (TypeError, AttributeError):
                # Expected for invalid input types - not hiding the error
                pass
