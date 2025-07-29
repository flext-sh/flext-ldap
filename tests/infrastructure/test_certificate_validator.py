"""Tests for Certificate Validation Service Infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import ssl
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext_core root imports
from flext_core import FlextResult
from pydantic import ValidationError

from flext_ldap.domain.security import (
    CertificateInfo,
    CertificateValidationContext,
    CertificateValidationResult,
    SSLContextConfig,
    ValidationResult,
)
from flext_ldap.infrastructure.certificate_validator import (
    CertificateValidationService,
)


class TestCertificateValidationService:
    """Test suite for certificate validation service."""

    @pytest.fixture
    def cert_validator(self) -> CertificateValidationService:
        """Certificate validation service instance."""
        return CertificateValidationService()

    @pytest.fixture
    def validation_context(self) -> CertificateValidationContext:
        """Sample validation context."""
        return CertificateValidationContext(
            hostname="ldap.example.com",
            port=636,
            verify_hostname=True,
            verify_chain=True,
        )

    @pytest.mark.asyncio
    async def test_validate_certificate_chain_empty(
        self,
        cert_validator: CertificateValidationService,
        validation_context: CertificateValidationContext,
    ) -> None:
        """Test validation with empty certificate chain."""
        result = await cert_validator.validate_certificate_chain([], validation_context)

        assert result.is_success
        assert result.data is not None
        if result.data.result_type != CertificateValidationResult.MALFORMED:
            raise AssertionError(f"Expected {CertificateValidationResult.MALFORMED}, got {result.data.result_type}")
        if "Empty certificate chain" not in result.data.message:
            raise AssertionError(f"Expected {"Empty certificate chain"} in {result.data.message}")

    @pytest.mark.asyncio
    async def test_validate_certificate_chain_malformed(
        self,
        cert_validator: CertificateValidationService,
        validation_context: CertificateValidationContext,
    ) -> None:
        """Test validation with malformed certificate."""
        result = await cert_validator.validate_certificate_chain(
            [b"invalid"],
            validation_context,
        )

        assert result.is_success
        assert result.data is not None
        if result.data.result_type != CertificateValidationResult.MALFORMED:
            raise AssertionError(f"Expected {CertificateValidationResult.MALFORMED}, got {result.data.result_type}")
        if "Failed to parse certificate" not in result.data.message:
            raise AssertionError(f"Expected {"Failed to parse certificate"} in {result.data.message}")

    @pytest.mark.asyncio
    @patch("flext_ldap.infrastructure.certificate_validator.x509")
    async def test_validate_certificate_chain_expired(
        self,
        mock_x509: MagicMock,
        cert_validator: CertificateValidationService,
        validation_context: CertificateValidationContext,
    ) -> None:
        """Test validation with expired certificate."""
        # Mock expired certificate
        mock_cert = MagicMock()
        mock_cert.not_valid_after = datetime(2020, 1, 1, tzinfo=UTC)
        mock_cert.not_valid_before = datetime(2019, 1, 1, tzinfo=UTC)
        mock_x509.load_der_x509_certificate.return_value = mock_cert

        result = await cert_validator.validate_certificate_chain(
            [b"cert"],
            validation_context,
        )

        assert result.is_success
        assert result.data is not None
        if result.data.result_type != CertificateValidationResult.EXPIRED:
            raise AssertionError(f"Expected {CertificateValidationResult.EXPIRED}, got {result.data.result_type}")
        if "Certificate expired" not in result.data.message:
            raise AssertionError(f"Expected {"Certificate expired"} in {result.data.message}")

    @pytest.mark.asyncio
    @patch("flext_ldap.infrastructure.certificate_validator.x509")
    async def test_validate_certificate_chain_valid(
        self,
        mock_x509: MagicMock,
        cert_validator: CertificateValidationService,
        validation_context: CertificateValidationContext,
    ) -> None:
        """Test validation with valid certificate."""
        # Mock valid certificate
        mock_cert = MagicMock()
        mock_cert.not_valid_after = datetime(2030, 1, 1, tzinfo=UTC)
        mock_cert.not_valid_before = datetime(2020, 1, 1, tzinfo=UTC)
        mock_x509.load_der_x509_certificate.return_value = mock_cert

        # Mock certificate info extraction
        mock_cert_info = CertificateInfo(
            subject="CN=ldap.example.com",
            issuer="CN=Test CA",
            serial_number="12345",
            not_before=datetime(2020, 1, 1, tzinfo=UTC),
            not_after=datetime(2030, 1, 1, tzinfo=UTC),
            signature_algorithm="sha256WithRSAEncryption",
            public_key_algorithm="RSA",
            public_key_size=2048,
            fingerprint_sha256="abcdef123456",
        )

        with patch.object(cert_validator, "_extract_certificate_info") as mock_extract:
            mock_extract.return_value = FlextResult.ok(mock_cert_info)

            result = await cert_validator.validate_certificate_chain(
                [b"cert"],
                validation_context,
            )

            assert result.is_success
            assert result.data is not None
            if result.data.result_type != CertificateValidationResult.VALID:
                raise AssertionError(f"Expected {CertificateValidationResult.VALID}, got {result.data.result_type}")
            if "Certificate validation successful" not in result.data.message:
                raise AssertionError(f"Expected {"Certificate validation successful"} in {result.data.message}")

    @pytest.mark.asyncio
    async def test_create_ssl_context_default(
        self,
        cert_validator: CertificateValidationService,
    ) -> None:
        """Test SSL context creation with default settings."""
        config = SSLContextConfig()

        result = await cert_validator.create_ssl_context(config)

        assert result.is_success
        assert result.data is not None
        assert isinstance(result.data, ssl.SSLContext)
        if result.data.verify_mode != ssl.CERT_REQUIRED:
            raise AssertionError(f"Expected {ssl.CERT_REQUIRED}, got {result.data.verify_mode}")
        if not (result.data.check_hostname):
            raise AssertionError(f"Expected True, got {result.data.check_hostname}")

    @pytest.mark.asyncio
    async def test_create_ssl_context_no_verification(
        self,
        cert_validator: CertificateValidationService,
    ) -> None:
        """Test SSL context creation with no verification."""
        config = SSLContextConfig(
            verify_mode="CERT_NONE",
            check_hostname=False,
        )

        result = await cert_validator.create_ssl_context(config)

        assert result.is_success
        assert result.data is not None
        assert isinstance(result.data, ssl.SSLContext)
        if result.data.verify_mode != ssl.CERT_NONE:
            raise AssertionError(f"Expected {ssl.CERT_NONE}, got {result.data.verify_mode}")
        if result.data.check_hostname:
            raise AssertionError(f"Expected False, got {result.data.check_hostname}")\ n
    def test_match_hostname_exact(
        self,
        cert_validator: CertificateValidationService,
    ) -> None:
        """Test exact hostname matching."""
        assert cert_validator._match_hostname("ldap.example.com", "ldap.example.com")
        assert not cert_validator._match_hostname(
            "ldap.example.com",
            "ldap.example.org",
        )

    def test_match_hostname_wildcard(
        self,
        cert_validator: CertificateValidationService,
    ) -> None:
        """Test wildcard hostname matching."""
        assert cert_validator._match_hostname("*.example.com", "ldap.example.com")
        assert cert_validator._match_hostname("*.example.com", "mail.example.com")
        assert not cert_validator._match_hostname("*.example.com", "example.com")
        assert not cert_validator._match_hostname("*.example.com", "ldap.example.org")

    def test_certificate_info_methods(self) -> None:
        """Test CertificateInfo helper methods."""
        # Test expired certificate
        expired_cert = CertificateInfo(
            subject="CN=test",
            issuer="CN=Test CA",
            serial_number="12345",
            not_before=datetime(2020, 1, 1, tzinfo=UTC),
            not_after=datetime(2020, 12, 31, tzinfo=UTC),  # Expired
            signature_algorithm="sha256WithRSAEncryption",
            public_key_algorithm="RSA",
            public_key_size=2048,
            fingerprint_sha256="abcdef123456",
        )

        assert expired_cert.is_expired()
        assert not expired_cert.is_not_yet_valid()

        # Test not yet valid certificate
        future_cert = CertificateInfo(
            subject="CN=test",
            issuer="CN=Test CA",
            serial_number="12345",
            not_before=datetime(2030, 1, 1, tzinfo=UTC),  # Future
            not_after=datetime(2030, 12, 31, tzinfo=UTC),
            signature_algorithm="sha256WithRSAEncryption",
            public_key_algorithm="RSA",
            public_key_size=2048,
            fingerprint_sha256="abcdef123456",
        )

        assert not future_cert.is_expired()
        assert future_cert.is_not_yet_valid()

    def test_certificate_info_hostname_validation(self) -> None:
        """Test CertificateInfo hostname validation."""
        # Test exact match
        cert_info = CertificateInfo(
            subject="CN=ldap.example.com",
            issuer="CN=Test CA",
            serial_number="12345",
            not_before=datetime(2020, 1, 1, tzinfo=UTC),
            not_after=datetime(2030, 1, 1, tzinfo=UTC),
            signature_algorithm="sha256WithRSAEncryption",
            public_key_algorithm="RSA",
            public_key_size=2048,
            fingerprint_sha256="abcdef123456",
        )

        assert cert_info.is_valid_for_hostname("ldap.example.com")
        assert not cert_info.is_valid_for_hostname("ldap.example.org")

        # Test wildcard match
        wildcard_cert = CertificateInfo(
            subject="CN=*.example.com",
            issuer="CN=Test CA",
            serial_number="12345",
            not_before=datetime(2020, 1, 1, tzinfo=UTC),
            not_after=datetime(2030, 1, 1, tzinfo=UTC),
            signature_algorithm="sha256WithRSAEncryption",
            public_key_algorithm="RSA",
            public_key_size=2048,
            fingerprint_sha256="abcdef123456",
        )

        assert wildcard_cert.is_valid_for_hostname("ldap.example.com")
        assert wildcard_cert.is_valid_for_hostname("mail.example.com")
        assert not wildcard_cert.is_valid_for_hostname("example.com")

    def test_validation_result_properties(self) -> None:
        """Test ValidationResult properties."""
        # Test valid result
        valid_result = ValidationResult(
            result_type=CertificateValidationResult.VALID,
            message="Valid certificate",
        )

        assert valid_result.is_valid
        assert not valid_result.has_errors
        assert not valid_result.has_warnings

        # Test invalid result with errors
        invalid_result = ValidationResult(
            result_type=CertificateValidationResult.EXPIRED,
            message="Expired certificate",
            validation_errors=["Certificate expired"],
            validation_warnings=["Certificate expires soon"],
        )

        assert not invalid_result.is_valid
        assert invalid_result.has_errors
        assert invalid_result.has_warnings

    def test_ssl_context_config_validation(self) -> None:
        """Test SSLContextConfig validation."""
        # Test invalid verify mode
        with pytest.raises(ValueError, match="Invalid verify_mode"):
            SSLContextConfig(verify_mode="INVALID_MODE")

        # Test invalid minimum version
        with pytest.raises(ValueError, match="Invalid minimum_version"):
            SSLContextConfig(minimum_version="TLSv1.1")

        # Test invalid maximum version
        with pytest.raises(ValueError, match="Invalid maximum_version"):
            SSLContextConfig(maximum_version="TLSv1.1")

        # Test valid config
        config = SSLContextConfig(
            verify_mode="CERT_REQUIRED",
            minimum_version="TLSv1.2",
            maximum_version="TLSv1.3",
        )
        if config.verify_mode != "CERT_REQUIRED":
            raise AssertionError(f"Expected {"CERT_REQUIRED"}, got {config.verify_mode}")

    def test_certificate_validation_context_validation(self) -> None:
        """Test CertificateValidationContext validation."""
        # Test invalid port
        with pytest.raises(ValidationError, match="Port must be between 1 and 65535"):
            CertificateValidationContext(hostname="test.com", port=0)

        with pytest.raises(ValidationError, match="Port must be between 1 and 65535"):
            CertificateValidationContext(hostname="test.com", port=65536)

        # Test empty hostname
        with pytest.raises(ValueError, match="Hostname cannot be empty"):
            CertificateValidationContext(hostname="", port=636)

        # Test valid context
        context = CertificateValidationContext(hostname="ldap.example.com", port=636)
        if context.hostname != "ldap.example.com":
            raise AssertionError(f"Expected {"ldap.example.com"}, got {context.hostname}")
        assert context.port == 636
