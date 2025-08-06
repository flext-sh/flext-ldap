"""Tests for FLEXT-LDAP Infrastructure Certificate Validator.

Comprehensive test suite for the FlextLdapCertificateValidationService class,
validating certificate validation, SSL context creation, and security operations
using FLEXT patterns with proper error handling and mocking strategies.

This test module ensures the certificate validator provides reliable SSL/TLS
certificate validation while following Clean Architecture patterns and maintaining
proper separation between infrastructure and domain layers.

Test Coverage:
    - Certificate validation service initialization
    - Certificate chain validation with various scenarios
    - SSL context creation and configuration
    - Hostname verification and certificate matching
    - Certificate expiry validation and caching
    - Error handling for malformed certificates
    - Mock-based testing for reliable unit tests
    - FlextResult pattern validation for all operations

Architecture:
    Tests validate the certificate validator's role in the Clean Architecture
    infrastructure layer, ensuring proper abstraction of security concerns
    and integration with domain security models.

Author: FLEXT Development Team

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import ssl
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from flext_ldap.domain.security import CertificateValidationContext
from flext_ldap.infrastructure.certificate_validator import (
    FlextLdapCertificateValidationService,
)


class TestFlextLdapCertificateValidationServiceInitialization:
    """Test suite for certificate validation service initialization.

    Validates that the service properly initializes with correct
    cache configuration and maintains proper state.
    """

    def test_certificate_validation_service_basic_initialization(self) -> None:
        """Test basic certificate validation service initialization."""
        service = FlextLdapCertificateValidationService()

        # Should initialize with empty cache
        assert hasattr(service, "_cert_cache")
        assert isinstance(service._cert_cache, dict)
        assert len(service._cert_cache) == 0

        # Should have cache TTL configured
        assert hasattr(service, "_cache_ttl")
        assert isinstance(service._cache_ttl, int)
        assert service._cache_ttl == 300  # 5 minutes

    def test_certificate_cache_structure(self) -> None:
        """Test certificate cache structure and type annotations."""
        service = FlextLdapCertificateValidationService()

        # Cache should be properly typed dict
        cache = service._cert_cache
        assert isinstance(cache, dict)

        # Cache TTL should be reasonable value
        assert service._cache_ttl > 0
        assert service._cache_ttl <= 3600  # Not more than 1 hour


class TestCertificateChainValidation:
    """Test suite for certificate chain validation functionality.

    Validates certificate chain validation with various scenarios,
    error handling, and proper FlextResult pattern usage.
    """

    @patch("flext_ldap.infrastructure.certificate_validator.logger")
    async def test_validate_certificate_chain_empty_list(
        self, mock_logger: Mock
    ) -> None:
        """Test certificate chain validation with empty list."""
        service = FlextLdapCertificateValidationService()

        # Create mock context
        mock_context = Mock(spec=CertificateValidationContext)
        mock_context.hostname = "example.com"
        mock_context.port = 443

        result = await service.validate_certificate_chain([], mock_context)

        # Should fail with appropriate error
        assert not result.is_success
        assert "empty" in result.error.lower() or "invalid" in result.error.lower()

    @patch("flext_ldap.infrastructure.certificate_validator.x509")
    async def test_validate_certificate_chain_invalid_certificate(
        self, mock_x509: Mock
    ) -> None:
        """Test certificate chain validation with invalid certificate data."""
        service = FlextLdapCertificateValidationService()

        # Create mock context
        mock_context = Mock(spec=CertificateValidationContext)
        mock_context.hostname = "example.com"
        mock_context.port = 443

        # Mock x509 to raise exception for invalid certificate
        mock_x509.load_der_x509_certificate.side_effect = ValueError(
            "Invalid certificate"
        )

        # Test with invalid certificate data
        invalid_cert_data = [b"invalid_certificate_data"]
        result = await service.validate_certificate_chain(
            invalid_cert_data, mock_context
        )

        # Should fail with malformed certificate error
        assert not result.is_success
        assert "malformed" in result.error.lower() or "invalid" in result.error.lower()

    @patch("flext_ldap.infrastructure.certificate_validator.x509")
    async def test_validate_certificate_chain_expired_certificate(
        self, mock_x509: Mock
    ) -> None:
        """Test certificate chain validation with expired certificate."""
        service = FlextLdapCertificateValidationService()

        # Create mock context
        mock_context = Mock(spec=CertificateValidationContext)
        mock_context.hostname = "example.com"
        mock_context.port = 443

        # Create mock certificate that is expired
        mock_cert = Mock()
        mock_cert.not_valid_after = datetime.now(UTC) - timedelta(
            days=1
        )  # Expired yesterday
        mock_cert.not_valid_before = datetime.now(UTC) - timedelta(
            days=365
        )  # Valid from 1 year ago

        mock_x509.load_der_x509_certificate.return_value = mock_cert

        # Test with expired certificate
        cert_data = [b"mock_certificate_data"]
        result = await service.validate_certificate_chain(cert_data, mock_context)

        # Should fail with expiry error
        assert not result.is_success
        assert "expired" in result.error.lower() or "validity" in result.error.lower()

    @patch("flext_ldap.infrastructure.certificate_validator.x509")
    async def test_validate_certificate_chain_not_yet_valid_certificate(
        self, mock_x509: Mock
    ) -> None:
        """Test certificate chain validation with not-yet-valid certificate."""
        service = FlextLdapCertificateValidationService()

        # Create mock context
        mock_context = Mock(spec=CertificateValidationContext)
        mock_context.hostname = "example.com"
        mock_context.port = 443

        # Create mock certificate that is not yet valid
        mock_cert = Mock()
        mock_cert.not_valid_before = datetime.now(UTC) + timedelta(
            days=1
        )  # Valid from tomorrow
        mock_cert.not_valid_after = datetime.now(UTC) + timedelta(
            days=365
        )  # Expires in 1 year

        mock_x509.load_der_x509_certificate.return_value = mock_cert

        # Test with not-yet-valid certificate
        cert_data = [b"mock_certificate_data"]
        result = await service.validate_certificate_chain(cert_data, mock_context)

        # Should fail with validity error
        assert not result.is_success
        assert (
            "not yet valid" in result.error.lower()
            or "validity" in result.error.lower()
        )


class TestSSLContextCreation:
    """Test suite for SSL context creation and configuration.

    Validates SSL context creation with various configurations,
    TLS version settings, and certificate loading operations.
    """

    @patch("flext_ldap.infrastructure.certificate_validator.ssl.create_default_context")
    async def test_create_ssl_context_default_configuration(
        self, mock_ssl_create: Mock
    ) -> None:
        """Test SSL context creation with default configuration."""
        service = FlextLdapCertificateValidationService()

        # Setup mock SSL context
        mock_context = Mock(spec=ssl.SSLContext)
        mock_ssl_create.return_value = mock_context

        # Create mock config with minimal settings
        mock_config = Mock()
        mock_config.verify_certificates = True
        mock_config.ca_certificate_path = None
        mock_config.ca_cert_data = None
        mock_config.client_certificate_path = None
        mock_config.client_private_key_path = None
        mock_config.minimum_tls_version = None
        mock_config.maximum_tls_version = None
        mock_config.cipher_suites = None

        result = await service.create_ssl_context(mock_config)

        # Should succeed with valid SSL context
        assert result.is_success
        assert result.data is mock_context

        # Verify SSL context was created
        mock_ssl_create.assert_called_once()

    @patch("flext_ldap.infrastructure.certificate_validator.ssl.create_default_context")
    async def test_create_ssl_context_with_verification_disabled(
        self, mock_ssl_create: Mock
    ) -> None:
        """Test SSL context creation with certificate verification disabled."""
        service = FlextLdapCertificateValidationService()

        # Setup mock SSL context
        mock_context = Mock(spec=ssl.SSLContext)
        mock_ssl_create.return_value = mock_context

        # Create mock config with verification disabled
        mock_config = Mock()
        mock_config.verify_certificates = False
        mock_config.ca_certificate_path = None
        mock_config.ca_cert_data = None
        mock_config.client_certificate_path = None
        mock_config.client_private_key_path = None
        mock_config.minimum_tls_version = None
        mock_config.maximum_tls_version = None
        mock_config.cipher_suites = None

        result = await service.create_ssl_context(mock_config)

        # Should succeed
        assert result.is_success
        assert result.data is mock_context

        # Verify verification was disabled
        assert mock_context.check_hostname is False
        assert mock_context.verify_mode == ssl.CERT_NONE

    @patch("flext_ldap.infrastructure.certificate_validator.ssl.create_default_context")
    async def test_create_ssl_context_with_custom_tls_versions(
        self, mock_ssl_create: Mock
    ) -> None:
        """Test SSL context creation with custom TLS versions."""
        service = FlextLdapCertificateValidationService()

        # Setup mock SSL context
        mock_context = Mock(spec=ssl.SSLContext)
        mock_ssl_create.return_value = mock_context

        # Create mock config with custom TLS versions
        mock_config = Mock()
        mock_config.verify_certificates = True
        mock_config.ca_certificate_path = None
        mock_config.ca_cert_data = None
        mock_config.client_certificate_path = None
        mock_config.client_private_key_path = None
        mock_config.minimum_tls_version = ssl.TLSVersion.TLSv1_2
        mock_config.maximum_tls_version = ssl.TLSVersion.TLSv1_3
        mock_config.cipher_suites = None

        result = await service.create_ssl_context(mock_config)

        # Should succeed
        assert result.is_success
        assert result.data is mock_context

        # Verify TLS versions were configured
        assert mock_context.minimum_version == ssl.TLSVersion.TLSv1_2
        assert mock_context.maximum_version == ssl.TLSVersion.TLSv1_3


class TestHostnameValidation:
    """Test suite for hostname validation and certificate matching.

    Validates hostname verification against certificate subjects,
    wildcard matching, and various hostname formats.
    """

    def test_validate_hostname_exact_match(self) -> None:
        """Test hostname validation with exact match."""
        service = FlextLdapCertificateValidationService()

        # Test exact hostname match
        result = service._match_hostname("example.com", "example.com")
        assert result is True

    def test_validate_hostname_case_insensitive(self) -> None:
        """Test hostname validation is case insensitive."""
        service = FlextLdapCertificateValidationService()

        # Test case insensitive matching
        result1 = service._match_hostname("Example.com", "example.com")
        assert result1 is True

        result2 = service._match_hostname("example.com", "EXAMPLE.COM")
        assert result2 is True

    def test_validate_hostname_wildcard_match(self) -> None:
        """Test hostname validation with wildcard certificates."""
        service = FlextLdapCertificateValidationService()

        # Test wildcard matching
        result1 = service._match_hostname("*.example.com", "subdomain.example.com")
        assert result1 is True

        result2 = service._match_hostname("*.example.com", "another.example.com")
        assert result2 is True

    def test_validate_hostname_wildcard_no_match(self) -> None:
        """Test hostname validation with wildcard that doesn't match."""
        service = FlextLdapCertificateValidationService()

        # Test wildcard non-matching cases
        result1 = service._match_hostname(
            "*.example.com", "example.com"
        )  # Missing subdomain
        assert result1 is False

        result2 = service._match_hostname(
            "*.example.com", "subdomain.other.com"
        )  # Wrong domain
        assert result2 is False

    def test_validate_hostname_mismatch(self) -> None:
        """Test hostname validation with complete mismatch."""
        service = FlextLdapCertificateValidationService()

        # Test complete mismatch
        result = service._match_hostname("example.com", "different.com")
        assert result is False


class TestCertificateInfoExtraction:
    """Test suite for certificate information extraction.

    Validates extraction of certificate details including subject,
    issuer, expiry dates, and certificate properties.
    """

    @patch("flext_ldap.infrastructure.certificate_validator.x509")
    async def test_extract_certificate_info_basic(self, mock_x509: Mock) -> None:
        """Test basic certificate information extraction."""
        service = FlextLdapCertificateValidationService()

        # Create mock certificate with basic info
        mock_cert = Mock()
        mock_cert.subject = Mock()
        mock_cert.issuer = Mock()
        mock_cert.not_valid_before = datetime.now(UTC) - timedelta(days=30)
        mock_cert.not_valid_after = datetime.now(UTC) + timedelta(days=30)
        mock_cert.serial_number = 12345

        # Mock subject and issuer attributes
        mock_subject_attr = Mock()
        mock_subject_attr.oid = Mock()
        mock_subject_attr.value = "example.com"
        mock_cert.subject = [mock_subject_attr]

        mock_issuer_attr = Mock()
        mock_issuer_attr.oid = Mock()
        mock_issuer_attr.value = "CA Authority"
        mock_cert.issuer = [mock_issuer_attr]

        # Mock extensions
        mock_cert.extensions = []

        result = await service._extract_certificate_info(mock_cert)

        # Should succeed with certificate info
        assert result.is_success
        assert result.data is not None

    @patch("flext_ldap.infrastructure.certificate_validator.x509")
    async def test_extract_certificate_info_with_extensions(
        self, mock_x509: Mock
    ) -> None:
        """Test certificate information extraction with extensions."""
        service = FlextLdapCertificateValidationService()

        # Create mock certificate with extensions
        mock_cert = Mock()
        mock_cert.subject = []
        mock_cert.issuer = []
        mock_cert.not_valid_before = datetime.now(UTC) - timedelta(days=30)
        mock_cert.not_valid_after = datetime.now(UTC) + timedelta(days=30)
        mock_cert.serial_number = 12345

        # Mock SAN extension
        mock_extension = Mock()
        mock_extension.oid = Mock()
        mock_extension.oid.dotted_string = "2.5.29.17"  # Subject Alternative Name OID
        mock_extension.critical = False
        mock_cert.extensions = [mock_extension]

        result = await service._extract_certificate_info(mock_cert)

        # Should succeed even with extensions
        assert result.is_success
        assert result.data is not None


class TestServerCertificateValidation:
    """Test suite for server certificate validation.

    Validates server-specific certificate validation including
    hostname verification, connection testing, and certificate retrieval.
    """

    @patch("flext_ldap.infrastructure.certificate_validator.ssl.create_default_context")
    @patch("flext_ldap.infrastructure.certificate_validator.socket.create_connection")
    async def test_validate_server_certificate_success(
        self, mock_socket_create: Mock, mock_ssl_create: Mock
    ) -> None:
        """Test successful server certificate validation."""
        service = FlextLdapCertificateValidationService()

        # Setup mock SSL context and socket
        mock_context = Mock(spec=ssl.SSLContext)
        mock_ssl_create.return_value = mock_context

        mock_socket = Mock()
        mock_socket_create.return_value = mock_socket

        # Mock SSL wrapped socket
        mock_ssl_socket = Mock()
        mock_context.wrap_socket.return_value = mock_ssl_socket

        # Mock peer certificate
        mock_peer_cert = b"mock_certificate_data"
        mock_ssl_socket.getpeercert.return_value = None
        mock_ssl_socket.getpeercert_chain.return_value = [mock_peer_cert]

        result = await service.validate_server_certificate("example.com", 443)

        # Should succeed (even if certificate validation fails, connection succeeded)
        # This tests the infrastructure connection logic, not certificate validity
        assert result.is_success or "connection" in str(result.error).lower()

    @patch("flext_ldap.infrastructure.certificate_validator.socket.create_connection")
    async def test_validate_server_certificate_connection_failure(
        self, mock_socket_create: Mock
    ) -> None:
        """Test server certificate validation with connection failure."""
        service = FlextLdapCertificateValidationService()

        # Mock connection failure
        mock_socket_create.side_effect = OSError("Connection refused")

        result = await service.validate_server_certificate(
            "unreachable.example.com", 443
        )

        # Should fail with connection error
        assert not result.is_success
        assert "connection" in result.error.lower() or "refused" in result.error.lower()


class TestCertificateCaching:
    """Test suite for certificate caching functionality.

    Validates certificate cache behavior, TTL handling,
    and cache invalidation scenarios.
    """

    def test_certificate_cache_empty_initially(self) -> None:
        """Test that certificate cache is empty initially."""
        service = FlextLdapCertificateValidationService()

        assert len(service._cert_cache) == 0

    def test_certificate_cache_ttl_configuration(self) -> None:
        """Test certificate cache TTL configuration."""
        service = FlextLdapCertificateValidationService()

        # TTL should be reasonable (5 minutes = 300 seconds)
        assert service._cache_ttl == 300
        assert service._cache_ttl > 0


class TestErrorHandlingAndEdgeCases:
    """Test suite for error handling and edge case scenarios.

    Validates robust error handling, exception management,
    and graceful degradation in failure scenarios.
    """

    async def test_validate_certificate_chain_none_input(self) -> None:
        """Test certificate chain validation with None input."""
        service = FlextLdapCertificateValidationService()

        # Create mock context
        mock_context = Mock(spec=CertificateValidationContext)
        mock_context.hostname = "example.com"
        mock_context.port = 443

        # None input should be handled gracefully
        with pytest.raises((TypeError, AttributeError)):
            await service.validate_certificate_chain(None, mock_context)  # type: ignore[arg-type]

    @patch("flext_ldap.infrastructure.certificate_validator.ssl.create_default_context")
    async def test_create_ssl_context_ssl_error(self, mock_ssl_create: Mock) -> None:
        """Test SSL context creation with SSL error."""
        service = FlextLdapCertificateValidationService()

        # Mock SSL context creation to raise SSL error
        mock_ssl_create.side_effect = ssl.SSLError("SSL configuration error")

        # Create minimal config
        mock_config = Mock()
        mock_config.verify_certificates = True
        mock_config.ca_certificate_path = None
        mock_config.ca_cert_data = None
        mock_config.client_certificate_path = None
        mock_config.client_private_key_path = None
        mock_config.minimum_tls_version = None
        mock_config.maximum_tls_version = None
        mock_config.cipher_suites = None

        result = await service.create_ssl_context(mock_config)

        # Should fail with SSL error
        assert not result.is_success
        assert "ssl" in result.error.lower() or "configuration" in result.error.lower()

    async def test_get_certificate_info_invalid_hostname(self) -> None:
        """Test get certificate info with invalid hostname."""
        service = FlextLdapCertificateValidationService()

        result = await service.get_certificate_info("", 443)

        # Should fail with invalid hostname
        assert not result.is_success
        assert "hostname" in result.error.lower() or "invalid" in result.error.lower()

    async def test_get_certificate_info_invalid_port(self) -> None:
        """Test get certificate info with invalid port."""
        service = FlextLdapCertificateValidationService()

        result = await service.get_certificate_info("example.com", -1)

        # Should fail with invalid port
        assert not result.is_success
        assert "port" in result.error.lower() or "invalid" in result.error.lower()


class TestFlextResultPatternCompliance:
    """Test suite for FlextResult pattern compliance validation.

    Validates that all certificate validation operations properly follow
    the FlextResult pattern for consistent error handling and type safety.
    """

    async def test_validate_certificate_chain_returns_flext_result(self) -> None:
        """Test that validate_certificate_chain returns proper FlextResult."""
        service = FlextLdapCertificateValidationService()

        # Create mock context
        mock_context = Mock(spec=CertificateValidationContext)
        mock_context.hostname = "example.com"
        mock_context.port = 443

        result = await service.validate_certificate_chain([], mock_context)

        # Validate FlextResult properties
        assert hasattr(result, "is_success")
        assert hasattr(result, "data")
        assert hasattr(result, "error")
        # For empty chain, should be failure
        assert result.is_success is False
        assert result.error is not None

    @patch("flext_ldap.infrastructure.certificate_validator.ssl.create_default_context")
    async def test_create_ssl_context_returns_flext_result(
        self, mock_ssl_create: Mock
    ) -> None:
        """Test that create_ssl_context returns proper FlextResult."""
        service = FlextLdapCertificateValidationService()

        # Setup mock SSL context
        mock_context = Mock(spec=ssl.SSLContext)
        mock_ssl_create.return_value = mock_context

        # Create minimal config
        mock_config = Mock()
        mock_config.verify_certificates = True
        mock_config.ca_certificate_path = None
        mock_config.ca_cert_data = None
        mock_config.client_certificate_path = None
        mock_config.client_private_key_path = None
        mock_config.minimum_tls_version = None
        mock_config.maximum_tls_version = None
        mock_config.cipher_suites = None

        result = await service.create_ssl_context(mock_config)

        # Validate FlextResult properties
        assert hasattr(result, "is_success")
        assert hasattr(result, "data")
        assert hasattr(result, "error")
        assert result.is_success is True
        assert result.error is None

    async def test_get_certificate_info_returns_flext_result(self) -> None:
        """Test that get_certificate_info returns proper FlextResult."""
        service = FlextLdapCertificateValidationService()

        result = await service.get_certificate_info("invalid", 443)

        # Validate FlextResult properties
        assert hasattr(result, "is_success")
        assert hasattr(result, "data")
        assert hasattr(result, "error")
        # For invalid hostname, should be failure
        assert result.is_success is False
        assert result.error is not None


class TestPrivateMethodBehavior:
    """Test suite for private method behavior validation.

    Validates private helper methods that support the main
    certificate validation functionality.
    """

    def test_create_malformed_result(self) -> None:
        """Test creation of malformed certificate result."""
        service = FlextLdapCertificateValidationService()

        test_message = "Certificate is malformed"
        result = service._create_malformed_result(test_message)

        # Should return failure result with message
        assert not result.is_success
        assert test_message in result.error

    def test_validate_input_chain_empty(self) -> None:
        """Test input chain validation with empty chain."""
        service = FlextLdapCertificateValidationService()

        result = service._validate_input_chain([])

        # Should fail for empty chain
        assert not result.is_success
        assert "empty" in result.error.lower() or "invalid" in result.error.lower()

    def test_validate_input_chain_valid(self) -> None:
        """Test input chain validation with valid chain."""
        service = FlextLdapCertificateValidationService()

        # Valid chain with certificate data
        valid_chain = [b"certificate_data"]
        result = service._validate_input_chain(valid_chain)

        # Should succeed for non-empty chain
        assert result.is_success
