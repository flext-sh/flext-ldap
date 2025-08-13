"""Test FLEXT LDAP Infrastructure - Infrastructure layer functionality."""

from __future__ import annotations

import pytest

from flext_ldap.infrastructure import (
    FlextLdapCertificateValidationService,
    FlextLdapClient,
    FlextLDAPConnectionManager,
    FlextLdapSecurityEventLogger,
)


class TestFlextLdapClient:
    """Test LDAP client infrastructure."""

    def test_client_creation(self) -> None:
        """Test client instance creation."""
        client = FlextLdapClient()
        assert client is not None

    @pytest.mark.asyncio
    async def test_connect_basic(self) -> None:
        """Test basic connection functionality."""
        client = FlextLdapClient()
        result = await client.connect("ldap://example.com")
        # For now, this is just a stub that succeeds
        assert result.is_success

    @pytest.mark.asyncio
    async def test_disconnect_basic(self) -> None:
        """Test basic disconnection functionality."""
        client = FlextLdapClient()
        result = await client.disconnect()
        assert result.is_success


class TestFlextLDAPConnectionManager:
    """Test connection manager functionality."""

    def test_connection_manager_creation(self) -> None:
        """Test connection manager creation."""
        manager = FlextLDAPConnectionManager()
        assert manager is not None

    @pytest.mark.asyncio
    async def test_get_connection_basic(self) -> None:
        """Test basic connection acquisition."""
        manager = FlextLDAPConnectionManager()
        result = await manager.get_connection("test-conn-1", "ldap://example.com")
        assert result.is_success
        assert result.data is not None


class TestFlextLdapCertificateValidationService:
    """Test certificate validation service."""

    def test_certificate_validator_creation(self) -> None:
        """Test certificate validator creation."""
        validator = FlextLdapCertificateValidationService()
        assert validator is not None

    def test_validate_certificate_basic(self) -> None:
        """Test basic certificate validation."""
        validator = FlextLdapCertificateValidationService()
        result = validator.validate_certificate(b"fake-cert", "example.com")
        assert result.is_success


class TestFlextLdapSecurityEventLogger:
    """Test security event logger."""

    def test_security_logger_creation(self) -> None:
        """Test security logger creation."""
        logger = FlextLdapSecurityEventLogger()
        assert logger is not None

    def test_log_authentication_attempt(self) -> None:
        """Test authentication attempt logging."""
        logger = FlextLdapSecurityEventLogger()
        logger.log_authentication_attempt(
            "cn=test,dc=example,dc=com",
            success=True,
            source_ip="127.0.0.1",
        )
        # Should not raise any exceptions

    def test_get_security_events(self) -> None:
        """Test retrieving security events."""
        logger = FlextLdapSecurityEventLogger()
        logger.log_authentication_attempt("cn=test,dc=example,dc=com", success=True)
        events = logger.get_security_events()
        assert len(events) >= 1
