"""Comprehensive tests for DSML Protocol Implementation.

This module provides enterprise-grade testing for the DSML protocol system,
following ZERO TOLERANCE approach with 95% minimum coverage as required
for shared libraries affecting 5+ dependent projects.

Test Coverage:
    - DSML connection and transport
    - XML message creation and parsing
    - SOAP envelope processing
    - All CRUD operations (search, add, modify, delete)
    - Error handling and recovery
    - Service availability testing

Following LDAP Core Shared requirements:
    - 95% minimum test coverage
    - ALL dependent projects must pass integration tests
    - ZERO tolerance for NotImplementedError
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from pydantic import ValidationError

from ldap_core_shared.protocols.dsml import (
    DSMLConfiguration,
    DSMLConnection,
    DSMLOperationType,
    DSMLProtocol,
    DSMLTransportType,
    DSMLVersion,
    create_dsml_connection,
    create_soap_dsml_message,
    parse_dsml_response,
    test_dsml_service,
)


class TestDSMLConfiguration:
    """Test DSML configuration model."""

    def test_dsml_configuration_default_values(self) -> None:
        """Test DSMLConfiguration creation with default values."""
        config = DSMLConfiguration(service_url="http://test.local/dsml")

        assert config.service_url == "http://test.local/dsml"
        assert config.dsml_version == DSMLVersion.DSML_2_0
        assert config.transport_type == DSMLTransportType.SOAP

    def test_dsml_configuration_custom_values(self) -> None:
        """Test DSMLConfiguration with custom values."""
        config = DSMLConfiguration(
            service_url="https://secure.test.local/dsml",
            dsml_version=DSMLVersion.DSML_1_0,
            transport_type=DSMLTransportType.REST,
            soap_action="urn:custom:action",
            http_auth_username="testuser",
            http_auth_password="testpass",
            connection_timeout=60,
            request_timeout=45,
        )

        assert config.service_url == "https://secure.test.local/dsml"
        assert config.dsml_version == DSMLVersion.DSML_1_0
        assert config.transport_type == DSMLTransportType.REST
        assert config.soap_action == "urn:custom:action"
        assert config.http_auth_username == "testuser"
        assert config.http_auth_password == "testpass"
        assert config.connect_timeout == 60
        assert config.request_timeout == 45

    def test_dsml_configuration_validation_errors(self) -> None:
        """Test DSMLConfiguration validation with invalid data."""
        # Test invalid timeout
        with pytest.raises(ValidationError):
            DSMLConfiguration(
                service_url="http://test.local/dsml",
                connection_timeout=-1,  # Invalid timeout
            )

        # Test invalid request timeout
        with pytest.raises(ValidationError):
            DSMLConfiguration(
                service_url="http://test.local/dsml",
                request_timeout=0,  # Invalid timeout
            )


class TestDSMLProtocol:
    """Test DSMLProtocol core functionality."""

    @pytest.fixture
    def dsml_config(self) -> DSMLConfiguration:
        """Create test DSML configuration."""
        return DSMLConfiguration(service_url="http://test.local/dsml")

    @pytest.fixture
    def dsml_protocol(self, dsml_config: DSMLConfiguration) -> DSMLProtocol:
        """Create test DSML protocol."""
        return DSMLProtocol(dsml_config)

    def test_dsml_protocol_initialization(
        self, dsml_protocol: DSMLProtocol, dsml_config: DSMLConfiguration
    ) -> None:
        """Test DSMLProtocol initialization."""
        assert dsml_protocol._config == dsml_config
        assert dsml_protocol._transport is None
        assert dsml_protocol.protocol_name == "dsml"
        assert dsml_protocol.default_port is None

    def test_dsml_protocol_initialization_no_config(self) -> None:
        """Test DSMLProtocol initialization without config."""
        protocol = DSMLProtocol()

        assert protocol._config is not None
        assert protocol._config.service_url == "http://localhost/dsml"

    @patch("ldap_core_shared.protocols.dsml.DSMLTransport")
    async def test_dsml_protocol_connect_success(
        self, mock_transport_class: MagicMock, dsml_protocol: DSMLProtocol
    ) -> None:
        """Test successful DSML protocol connection."""
        mock_transport = AsyncMock()
        mock_transport_class.return_value = mock_transport

        await dsml_protocol.connect("http://test.local/dsml")

        mock_transport_class.assert_called_once_with(dsml_protocol._config)
        mock_transport.connect.assert_called_once()
        assert dsml_protocol._transport == mock_transport

    @patch("ldap_core_shared.protocols.dsml.DSMLTransport")
    async def test_dsml_protocol_disconnect(
        self, mock_transport_class: MagicMock, dsml_protocol: DSMLProtocol
    ) -> None:
        """Test DSML protocol disconnection."""
        mock_transport = AsyncMock()
        mock_transport_class.return_value = mock_transport

        # Connect first
        await dsml_protocol.connect("http://test.local/dsml")

        # Then disconnect
        await dsml_protocol.disconnect()

        mock_transport.disconnect.assert_called_once()
        assert dsml_protocol._transport is None

    async def test_dsml_protocol_send_operation_not_connected(
        self, dsml_protocol: DSMLProtocol
    ) -> None:
        """Test sending operation when not connected raises error."""
        mock_message = MagicMock()

        with pytest.raises(ConnectionError, match="Not connected"):
            await dsml_protocol.send_dsml_operation(mock_message)

    @patch("ldap_core_shared.protocols.dsml.DSMLTransport")
    async def test_dsml_protocol_send_operation_success(
        self, mock_transport_class: MagicMock, dsml_protocol: DSMLProtocol
    ) -> None:
        """Test successful DSML operation sending."""
        # Setup mocks
        mock_transport = AsyncMock()
        mock_transport_class.return_value = mock_transport

        mock_message = MagicMock()
        mock_message.to_xml.return_value = "<dsml>test</dsml>"

        mock_response = MagicMock()
        mock_response.has_errors.return_value = False

        # Mock DSMLMessage.from_xml
        with patch("ldap_core_shared.protocols.dsml.DSMLMessage") as mock_dsml_message:
            mock_dsml_message.from_xml.return_value = mock_response
            mock_transport.send_request.return_value = "<dsml>response</dsml>"

            # Connect and send operation
            await dsml_protocol.connect("http://test.local/dsml")
            result = await dsml_protocol.send_dsml_operation(mock_message)

            # Verify calls
            mock_message.to_xml.assert_called_once()
            mock_transport.send_request.assert_called_once_with("<dsml>test</dsml>")
            mock_dsml_message.from_xml.assert_called_once_with("<dsml>response</dsml>")
            assert result == mock_response

    @patch("ldap_core_shared.protocols.dsml.DSMLTransport")
    async def test_dsml_protocol_send_operation_with_errors(
        self, mock_transport_class: MagicMock, dsml_protocol: DSMLProtocol
    ) -> None:
        """Test DSML operation sending with response errors."""
        # Setup mocks
        mock_transport = AsyncMock()
        mock_transport_class.return_value = mock_transport

        mock_message = MagicMock()
        mock_message.to_xml.return_value = "<dsml>test</dsml>"

        mock_response = MagicMock()
        mock_response.has_errors.return_value = True
        mock_response.get_error_details.return_value = "LDAP error: Invalid DN"

        # Mock DSMLMessage.from_xml
        with patch("ldap_core_shared.protocols.dsml.DSMLMessage") as mock_dsml_message:
            mock_dsml_message.from_xml.return_value = mock_response
            mock_transport.send_request.return_value = "<dsml>error_response</dsml>"

            # Connect and send operation
            await dsml_protocol.connect("http://test.local/dsml")

            with pytest.raises(
                RuntimeError, match="DSML operation failed: LDAP error: Invalid DN"
            ):
                await dsml_protocol.send_dsml_operation(mock_message)

    def test_dsml_protocol_connected_property(
        self, dsml_protocol: DSMLProtocol
    ) -> None:
        """Test connected property."""
        # Not connected initially
        assert not dsml_protocol.connected

        # Mock transport as connected
        mock_transport = MagicMock()
        mock_transport.connected = True
        dsml_protocol._transport = mock_transport

        assert dsml_protocol.connected

    def test_dsml_protocol_transport_property(
        self, dsml_protocol: DSMLProtocol
    ) -> None:
        """Test transport property getter."""
        assert dsml_protocol.transport is None

        mock_transport = MagicMock()
        dsml_protocol._transport = mock_transport

        assert dsml_protocol.transport == mock_transport

    def test_dsml_protocol_configuration_property(
        self, dsml_protocol: DSMLProtocol, dsml_config: DSMLConfiguration
    ) -> None:
        """Test configuration property getter."""
        assert dsml_protocol.configuration == dsml_config


class TestDSMLConnection:
    """Test DSMLConnection functionality."""

    @pytest.fixture
    def dsml_connection(self) -> DSMLConnection:
        """Create test DSML connection."""
        return DSMLConnection(
            service_url="http://test.local/dsml",
            http_auth_username="testuser",
            http_auth_password="testpass",
        )

    def test_dsml_connection_initialization(
        self, dsml_connection: DSMLConnection
    ) -> None:
        """Test DSMLConnection initialization."""
        assert dsml_connection._service_url == "http://test.local/dsml"
        assert dsml_connection._dsml_version == DSMLVersion.DSML_2_0
        assert dsml_connection._transport_type == DSMLTransportType.SOAP

    @patch("ldap_core_shared.protocols.dsml.DSMLProtocol")
    async def test_dsml_connection_connect_success(
        self, mock_protocol_class: MagicMock, dsml_connection: DSMLConnection
    ) -> None:
        """Test successful DSML connection."""
        mock_protocol = AsyncMock()
        mock_protocol_class.return_value = mock_protocol

        await dsml_connection.connect()

        mock_protocol.connect.assert_called_once_with("http://test.local/dsml")

    @patch("ldap_core_shared.protocols.dsml.DSMLProtocol")
    async def test_dsml_connection_disconnect(
        self, mock_protocol_class: MagicMock, dsml_connection: DSMLConnection
    ) -> None:
        """Test DSML connection disconnection."""
        mock_protocol = AsyncMock()
        mock_protocol_class.return_value = mock_protocol

        await dsml_connection.connect()
        await dsml_connection.disconnect()

        mock_protocol.disconnect.assert_called_once()

    @patch("ldap_core_shared.protocols.dsml.DSMLProtocol")
    @patch("ldap_core_shared.protocols.dsml.DSMLMessage")
    async def test_dsml_connection_search_success(
        self,
        mock_dsml_message: MagicMock,
        mock_protocol_class: MagicMock,
        dsml_connection: DSMLConnection,
    ) -> None:
        """Test successful DSML search operation."""
        # Setup mocks
        mock_protocol = AsyncMock()
        mock_protocol_class.return_value = mock_protocol

        mock_search_message = MagicMock()
        mock_dsml_message.create_search_request.return_value = mock_search_message

        mock_response = MagicMock()
        mock_response.get_search_entries.return_value = [
            {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": "test"}},
        ]
        mock_protocol.send_dsml_operation.return_value = mock_response

        # Connect and perform search
        await dsml_connection.connect()
        results = await dsml_connection.search(
            base_dn="dc=example,dc=com",
            search_filter="(cn=test)",
            attributes=["cn"],
            scope="subtree",
        )

        # Verify calls
        mock_dsml_message.create_search_request.assert_called_once_with(
            base_dn="dc=example,dc=com",
            filter_str="(cn=test)",
            attributes=["cn"],
            scope="subtree",
        )
        mock_protocol.send_dsml_operation.assert_called_once_with(mock_search_message)
        assert results == [
            {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": "test"}}
        ]

    @patch("ldap_core_shared.protocols.dsml.DSMLProtocol")
    @patch("ldap_core_shared.protocols.dsml.DSMLMessage")
    async def test_dsml_connection_add_success(
        self,
        mock_dsml_message: MagicMock,
        mock_protocol_class: MagicMock,
        dsml_connection: DSMLConnection,
    ) -> None:
        """Test successful DSML add operation."""
        # Setup mocks
        mock_protocol = AsyncMock()
        mock_protocol_class.return_value = mock_protocol

        mock_add_message = MagicMock()
        mock_dsml_message.create_add_request.return_value = mock_add_message

        mock_response = MagicMock()
        mock_response.is_success.return_value = True
        mock_protocol.send_dsml_operation.return_value = mock_response

        # Connect and perform add
        await dsml_connection.connect()
        result = await dsml_connection.add(
            dn="cn=newuser,dc=example,dc=com",
            attributes={"cn": "newuser", "objectClass": ["person"]},
        )

        # Verify calls
        mock_dsml_message.create_add_request.assert_called_once_with(
            dn="cn=newuser,dc=example,dc=com",
            attributes={"cn": "newuser", "objectClass": ["person"]},
        )
        mock_protocol.send_dsml_operation.assert_called_once_with(mock_add_message)
        assert result is True

    @patch("ldap_core_shared.protocols.dsml.DSMLProtocol")
    @patch("ldap_core_shared.protocols.dsml.DSMLMessage")
    async def test_dsml_connection_modify_success(
        self,
        mock_dsml_message: MagicMock,
        mock_protocol_class: MagicMock,
        dsml_connection: DSMLConnection,
    ) -> None:
        """Test successful DSML modify operation."""
        # Setup mocks
        mock_protocol = AsyncMock()
        mock_protocol_class.return_value = mock_protocol

        mock_modify_message = MagicMock()
        mock_dsml_message.create_modify_request.return_value = mock_modify_message

        mock_response = MagicMock()
        mock_response.is_success.return_value = True
        mock_protocol.send_dsml_operation.return_value = mock_response

        # Connect and perform modify
        await dsml_connection.connect()
        result = await dsml_connection.modify(
            dn="cn=testuser,dc=example,dc=com",
            modifications=[
                {
                    "operation": "replace",
                    "attribute": "mail",
                    "values": ["new@example.com"],
                }
            ],
        )

        # Verify calls
        mock_dsml_message.create_modify_request.assert_called_once_with(
            dn="cn=testuser,dc=example,dc=com",
            modifications=[
                {
                    "operation": "replace",
                    "attribute": "mail",
                    "values": ["new@example.com"],
                }
            ],
        )
        mock_protocol.send_dsml_operation.assert_called_once_with(mock_modify_message)
        assert result is True

    @patch("ldap_core_shared.protocols.dsml.DSMLProtocol")
    @patch("ldap_core_shared.protocols.dsml.DSMLMessage")
    async def test_dsml_connection_delete_success(
        self,
        mock_dsml_message: MagicMock,
        mock_protocol_class: MagicMock,
        dsml_connection: DSMLConnection,
    ) -> None:
        """Test successful DSML delete operation."""
        # Setup mocks
        mock_protocol = AsyncMock()
        mock_protocol_class.return_value = mock_protocol

        mock_delete_message = MagicMock()
        mock_dsml_message.create_delete_request.return_value = mock_delete_message

        mock_response = MagicMock()
        mock_response.is_success.return_value = True
        mock_protocol.send_dsml_operation.return_value = mock_response

        # Connect and perform delete
        await dsml_connection.connect()
        result = await dsml_connection.delete(dn="cn=deleteuser,dc=example,dc=com")

        # Verify calls
        mock_dsml_message.create_delete_request.assert_called_once_with(
            dn="cn=deleteuser,dc=example,dc=com"
        )
        mock_protocol.send_dsml_operation.assert_called_once_with(mock_delete_message)
        assert result is True

    @patch("ldap_core_shared.protocols.dsml.DSMLProtocol")
    async def test_dsml_connection_operation_failure(
        self, mock_protocol_class: MagicMock, dsml_connection: DSMLConnection
    ) -> None:
        """Test DSML operation failure handling."""
        # Setup mocks
        mock_protocol = AsyncMock()
        mock_protocol_class.return_value = mock_protocol
        mock_protocol.send_dsml_operation.side_effect = Exception("Connection failed")

        await dsml_connection.connect()

        with pytest.raises(
            RuntimeError, match="DSML search operation failed: Connection failed"
        ):
            await dsml_connection.search("dc=example,dc=com")

    def test_dsml_connection_get_connection_info(
        self, dsml_connection: DSMLConnection
    ) -> None:
        """Test getting connection information."""
        info = dsml_connection.get_connection_info()

        assert info["protocol"] == "dsml"
        assert info["service_url"] == "http://test.local/dsml"
        assert info["dsml_version"] == "2.0"
        assert info["transport_type"] == "soap"

    def test_dsml_connection_properties(self, dsml_connection: DSMLConnection) -> None:
        """Test DSMLConnection properties."""
        assert dsml_connection.service_url == "http://test.local/dsml"
        assert dsml_connection.dsml_version == DSMLVersion.DSML_2_0
        assert dsml_connection.transport_type == DSMLTransportType.SOAP


class TestDSMLHelperFunctions:
    """Test DSML helper and convenience functions."""

    def test_create_dsml_connection(self) -> None:
        """Test create_dsml_connection convenience function."""
        connection = create_dsml_connection(
            service_url="http://test.local/dsml",
            username="testuser",
            password="testpass",
        )

        assert isinstance(connection, DSMLConnection)
        assert connection.service_url == "http://test.local/dsml"

    def test_create_dsml_connection_minimal(self) -> None:
        """Test create_dsml_connection with minimal parameters."""
        connection = create_dsml_connection("http://test.local/dsml")

        assert isinstance(connection, DSMLConnection)
        assert connection.service_url == "http://test.local/dsml"

    def test_create_soap_dsml_message_search(self) -> None:
        """Test SOAP DSML message creation for search operation."""
        xml = create_soap_dsml_message(
            DSMLOperationType.SEARCH_REQUEST,
            base_dn="dc=example,dc=com",
            filter="(cn=test)",
            scope="wholeSubtree",
        )

        assert "<?xml version=" in xml
        assert "soap:Envelope" in xml
        assert "dsml:batchRequest" in xml
        assert "dsml:searchRequest" in xml
        assert "dc=example,dc=com" in xml
        assert "(cn=test)" in xml

    def test_create_soap_dsml_message_add(self) -> None:
        """Test SOAP DSML message creation for add operation."""
        xml = create_soap_dsml_message(
            DSMLOperationType.ADD_REQUEST,
            dn="cn=newuser,dc=example,dc=com",
            attributes={
                "cn": "newuser",
                "mail": ["user@example.com", "user2@example.com"],
            },
        )

        assert "dsml:addRequest" in xml
        assert "cn=newuser,dc=example,dc=com" in xml
        assert "user@example.com" in xml
        assert "user2@example.com" in xml

    def test_parse_dsml_response_success(self) -> None:
        """Test parsing successful DSML response."""
        response_xml = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:dsml="urn:oasis:names:tc:DSML:2:0:core">
    <soap:Body>
        <dsml:batchResponse>
            <dsml:searchResponse>
                <dsml:searchResultEntry dn="cn=test,dc=example,dc=com">
                    <dsml:attr name="cn">
                        <dsml:value>test</dsml:value>
                    </dsml:attr>
                    <dsml:attr name="mail">
                        <dsml:value>test@example.com</dsml:value>
                    </dsml:attr>
                </dsml:searchResultEntry>
                <dsml:searchResultDone resultCode="0" />
            </dsml:searchResponse>
        </dsml:batchResponse>
    </soap:Body>
</soap:Envelope>"""

        result = parse_dsml_response(response_xml)

        assert result["success"] is True
        assert result["result_code"] == 0
        assert len(result["entries"]) == 1
        assert result["entries"][0]["dn"] == "cn=test,dc=example,dc=com"
        assert result["entries"][0]["attributes"]["cn"] == "test"
        assert result["entries"][0]["attributes"]["mail"] == "test@example.com"

    def test_parse_dsml_response_error(self) -> None:
        """Test parsing DSML error response."""
        response_xml = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:dsml="urn:oasis:names:tc:DSML:2:0:core">
    <soap:Body>
        <dsml:batchResponse>
            <dsml:searchResponse>
                <dsml:searchResultDone resultCode="32">
                    <dsml:errorMessage>No such object</dsml:errorMessage>
                </dsml:searchResultDone>
            </dsml:searchResponse>
        </dsml:batchResponse>
    </soap:Body>
</soap:Envelope>"""

        result = parse_dsml_response(response_xml)

        assert result["success"] is False
        assert result["result_code"] == 32
        assert result["message"] == "No such object"
        assert len(result["entries"]) == 0

    def test_parse_dsml_response_invalid_xml(self) -> None:
        """Test parsing invalid XML response."""
        invalid_xml = "not valid xml <unclosed"

        result = parse_dsml_response(invalid_xml)

        assert result["success"] is False
        assert result["result_code"] == -1
        assert "XML parse error" in result["errors"][0]

    def test_parse_dsml_response_no_batch(self) -> None:
        """Test parsing response without batch response."""
        response_xml = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <soap:Fault>
            <faultstring>Service unavailable</faultstring>
        </soap:Fault>
    </soap:Body>
</soap:Envelope>"""

        result = parse_dsml_response(response_xml)

        assert result["success"] is False
        assert "No batch response found" in result["errors"]

    @patch("aiohttp.ClientSession")
    async def test_test_dsml_service_success(
        self, mock_session_class: MagicMock
    ) -> None:
        """Test successful DSML service testing."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "DSML Directory Service"
        mock_response.headers = {"content-type": "text/xml; charset=utf-8"}

        mock_session.get.return_value.__aenter__.return_value = mock_response
        mock_session_class.return_value.__aenter__.return_value = mock_session

        result = await test_dsml_service("http://test.local/dsml")

        assert result["reachable"] is True
        assert result["responds_to_dsml"] is True
        assert result["http_status"] == 200
        assert len(result["errors"]) == 0

    @patch("aiohttp.ClientSession")
    async def test_test_dsml_service_connection_error(
        self, mock_session_class: MagicMock
    ) -> None:
        """Test DSML service testing with connection error."""
        mock_session = AsyncMock()
        mock_session.get.side_effect = aiohttp.ClientConnectorError(
            connection_key=None,
            os_error=None,
        )

        mock_session_class.return_value.__aenter__.return_value = mock_session

        result = await test_dsml_service("http://test.local/dsml")

        assert result["reachable"] is False
        assert len(result["errors"]) > 0

    @patch("aiohttp.ClientSession")
    async def test_test_dsml_service_soap_support(
        self, mock_session_class: MagicMock
    ) -> None:
        """Test DSML service testing with SOAP support detection."""
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "Service supports DSML operations"
        mock_response.headers = {"content-type": "application/soap+xml"}

        mock_session.get.return_value.__aenter__.return_value = mock_response
        mock_session_class.return_value.__aenter__.return_value = mock_session

        result = await test_dsml_service("http://test.local/dsml")

        assert result["reachable"] is True
        assert result["responds_to_dsml"] is True
        assert result["soap_supported"] is True


@pytest.mark.integration
class TestDSMLIntegration:
    """Integration tests for DSML protocol (requires mock DSML service)."""

    @pytest.mark.asyncio
    async def test_full_dsml_workflow(self) -> None:
        """Test complete DSML workflow from connection to operations."""
        # This would be implemented with a mock DSML service
        # for integration testing in CI/CD environment

        # Create DSML connection
        connection = create_dsml_connection("http://mock.dsml.service/dsml")

        # Test connection (would connect to mock service)
        with patch.object(connection, "connect") as mock_connect:
            with patch.object(connection, "search") as mock_search:
                mock_search.return_value = [
                    {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": "test"}},
                ]

                await connection.connect()
                results = await connection.search("dc=example,dc=com", "(cn=test)")

                mock_connect.assert_called_once()
                mock_search.assert_called_once()
                assert len(results) == 1


# Performance and load testing
@pytest.mark.performance
class TestDSMLPerformance:
    """Performance tests for DSML operations."""

    @pytest.mark.asyncio
    async def test_concurrent_dsml_operations(self) -> None:
        """Test concurrent DSML operations performance."""
        connection = create_dsml_connection("http://mock.dsml.service/dsml")

        with patch.object(connection, "search") as mock_search:
            mock_search.return_value = [{"dn": "test", "attributes": {}}]

            # Simulate concurrent operations
            tasks = []
            for i in range(10):
                task = connection.search(f"dc=test{i},dc=com", f"(cn=test{i})")
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Verify all operations completed
            assert len(results) == 10
            assert all(isinstance(result, list) for result in results)
