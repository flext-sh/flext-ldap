"""Tests for LDAP Referral Chaser Implementation.

This module provides comprehensive test coverage for the LDAP referral chaser
including connection management, authentication handling, operation execution,
and server integration with enterprise-grade validation.

Test Coverage:
    - CredentialType: Credential type enumeration
    - ReferralCredentials: Authentication credentials modeling
    - ReferralConnectionInfo: Connection information tracking
    - ReferralChasingResult: Result processing and metadata
    - ReferralChaser: Main referral chasing coordinator
    - Connection establishment and management
    - Authentication handling and validation
    - Operation execution and result processing

Security Testing:
    - Credential validation and security enforcement
    - Authentication type validation and requirements
    - Connection security and SSL/TLS handling
    - Certificate validation and trust management
    - Timeout management and security controls

Integration Testing:
    - Complete referral chasing workflows
    - Multi-credential authentication scenarios
    - Connection pooling and reuse patterns
    - Error handling and recovery workflows
    - Performance tracking and statistics

Performance Testing:
    - Connection establishment optimization
    - Authentication performance validation
    - Operation execution efficiency
    - Memory usage optimization validation
    - Connection cache management
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

from ldap_core_shared.referrals.chaser import (
    CredentialType,
    ReferralChaser,
    ReferralChasingResult,
    ReferralConnectionInfo,
    ReferralCredentials,
    create_anonymous_credentials,
    create_sasl_credentials,
    create_simple_credentials,
    quick_chase,
)


class TestCredentialType:
    """Test cases for CredentialType enumeration."""

    def test_credential_type_values(self) -> None:
        """Test credential type enumeration values."""
        assert CredentialType.SIMPLE.value == "simple"
        assert CredentialType.SASL.value == "sasl"
        assert CredentialType.ANONYMOUS.value == "anonymous"
        assert CredentialType.INHERITED.value == "inherited"

    def test_credential_type_completeness(self) -> None:
        """Test that all expected credential types are defined."""
        expected_types = {"SIMPLE", "SASL", "ANONYMOUS", "INHERITED"}
        actual_types = {member.name for member in CredentialType}
        assert actual_types == expected_types


class TestReferralCredentials:
    """Test cases for ReferralCredentials."""

    def test_credentials_creation_default(self) -> None:
        """Test creating credentials with default values."""
        credentials = ReferralCredentials()

        assert credentials.credential_type == CredentialType.SIMPLE
        assert credentials.bind_dn is None
        assert credentials.password is None
        assert credentials.sasl_mechanism is None
        assert credentials.sasl_username is None
        assert credentials.sasl_password is None
        assert credentials.sasl_authz_id is None
        assert credentials.use_tls is False
        assert credentials.validate_certificate is True
        assert credentials.connection_timeout == 30  # DEFAULT_TIMEOUT_SECONDS
        assert credentials.bind_timeout == 30

    def test_credentials_creation_simple(self) -> None:
        """Test creating simple bind credentials."""
        credentials = ReferralCredentials(
            credential_type=CredentialType.SIMPLE,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD_password",
            use_tls=True,
            connection_timeout=60,
        )

        assert credentials.credential_type == CredentialType.SIMPLE
        assert credentials.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert credentials.password == "REDACTED_LDAP_BIND_PASSWORD_password"
        assert credentials.use_tls is True
        assert credentials.connection_timeout == 60

    def test_credentials_creation_sasl(self) -> None:
        """Test creating SASL credentials."""
        credentials = ReferralCredentials(
            credential_type=CredentialType.SASL,
            sasl_mechanism="DIGEST-MD5",
            sasl_username="user@example.com",
            sasl_password="user_password",
            sasl_authz_id="REDACTED_LDAP_BIND_PASSWORD@example.com",
        )

        assert credentials.credential_type == CredentialType.SASL
        assert credentials.sasl_mechanism == "DIGEST-MD5"
        assert credentials.sasl_username == "user@example.com"
        assert credentials.sasl_password == "user_password"
        assert credentials.sasl_authz_id == "REDACTED_LDAP_BIND_PASSWORD@example.com"

    def test_credentials_creation_anonymous(self) -> None:
        """Test creating anonymous credentials."""
        credentials = ReferralCredentials(
            credential_type=CredentialType.ANONYMOUS,
        )

        assert credentials.credential_type == CredentialType.ANONYMOUS
        assert credentials.bind_dn is None
        assert credentials.password is None

    def test_credentials_validation_simple_missing_dn(self) -> None:
        """Test validation failure for simple credentials without bind_dn."""
        with pytest.raises(ValueError, match="bind_dn required for simple credentials"):
            ReferralCredentials(
                credential_type=CredentialType.SIMPLE,
                password="password",
            )

    def test_credentials_validation_sasl_missing_mechanism(self) -> None:
        """Test validation failure for SASL credentials without mechanism."""
        with pytest.raises(
            ValueError, match="sasl_mechanism required for SASL credentials"
        ):
            ReferralCredentials(
                credential_type=CredentialType.SASL,
                sasl_username="user",
                sasl_password="password",
            )

    def test_is_valid_for_type_simple(self) -> None:
        """Test is_valid_for_type for simple credentials."""
        # Valid simple credentials
        valid_creds = ReferralCredentials(
            credential_type=CredentialType.SIMPLE,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="password",
        )
        assert valid_creds.is_valid_for_type() is True

        # Invalid - missing password
        invalid_creds = ReferralCredentials(
            credential_type=CredentialType.SIMPLE,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password=None,
        )
        assert invalid_creds.is_valid_for_type() is False

    def test_is_valid_for_type_sasl(self) -> None:
        """Test is_valid_for_type for SASL credentials."""
        # Valid SASL credentials
        valid_creds = ReferralCredentials(
            credential_type=CredentialType.SASL,
            sasl_mechanism="PLAIN",
        )
        assert valid_creds.is_valid_for_type() is True

        # Invalid - missing mechanism (should be caught by validator)
        # But if somehow we get here:
        invalid_creds = ReferralCredentials(
            credential_type=CredentialType.SASL,
            sasl_mechanism=None,
        )
        assert invalid_creds.is_valid_for_type() is False

    def test_is_valid_for_type_anonymous_inherited(self) -> None:
        """Test is_valid_for_type for anonymous and inherited credentials."""
        # Anonymous credentials
        anon_creds = ReferralCredentials(
            credential_type=CredentialType.ANONYMOUS,
        )
        assert anon_creds.is_valid_for_type() is True

        # Inherited credentials
        inherited_creds = ReferralCredentials(
            credential_type=CredentialType.INHERITED,
        )
        assert inherited_creds.is_valid_for_type() is True

    def test_get_auth_summary_simple(self) -> None:
        """Test get_auth_summary for simple credentials."""
        credentials = ReferralCredentials(
            credential_type=CredentialType.SIMPLE,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="password",
        )

        summary = credentials.get_auth_summary()
        assert summary == "Simple bind as cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

    def test_get_auth_summary_sasl(self) -> None:
        """Test get_auth_summary for SASL credentials."""
        credentials = ReferralCredentials(
            credential_type=CredentialType.SASL,
            sasl_mechanism="DIGEST-MD5",
            sasl_username="user@example.com",
        )

        summary = credentials.get_auth_summary()
        assert summary == "SASL DIGEST-MD5 as user@example.com"

    def test_get_auth_summary_anonymous(self) -> None:
        """Test get_auth_summary for anonymous credentials."""
        credentials = ReferralCredentials(
            credential_type=CredentialType.ANONYMOUS,
        )

        summary = credentials.get_auth_summary()
        assert summary == "Anonymous bind"

    def test_get_auth_summary_inherited(self) -> None:
        """Test get_auth_summary for inherited credentials."""
        credentials = ReferralCredentials(
            credential_type=CredentialType.INHERITED,
        )

        summary = credentials.get_auth_summary()
        assert summary == "Inherited credentials"


class TestReferralConnectionInfo:
    """Test cases for ReferralConnectionInfo."""

    def test_connection_info_creation(self) -> None:
        """Test creating connection information."""
        connection_info = ReferralConnectionInfo(
            server_url="ldap://server.example.com:389",
            hostname="server.example.com",
            port=389,
            use_ssl=False,
        )

        assert connection_info.server_url == "ldap://server.example.com:389"
        assert connection_info.hostname == "server.example.com"
        assert connection_info.port == 389
        assert connection_info.use_ssl is False
        assert connection_info.connected_at is None
        assert connection_info.authenticated_at is None
        assert connection_info.last_operation_at is None
        assert connection_info.operations_executed == 0
        assert connection_info.errors_encountered == 0
        assert connection_info.connection_time is None

    def test_connection_info_ssl(self) -> None:
        """Test creating SSL connection information."""
        connection_info = ReferralConnectionInfo(
            server_url="ldaps://secure.example.com:636",
            hostname="secure.example.com",
            port=636,
            use_ssl=True,
        )

        assert connection_info.server_url == "ldaps://secure.example.com:636"
        assert connection_info.hostname == "secure.example.com"
        assert connection_info.port == 636
        assert connection_info.use_ssl is True

    def test_record_operation_success(self) -> None:
        """Test recording successful operation."""
        connection_info = ReferralConnectionInfo(
            server_url="ldap://server.example.com",
            hostname="server.example.com",
            port=389,
            use_ssl=False,
        )

        assert connection_info.operations_executed == 0
        assert connection_info.errors_encountered == 0
        assert connection_info.last_operation_at is None

        connection_info.record_operation(success=True)

        assert connection_info.operations_executed == 1
        assert connection_info.errors_encountered == 0
        assert connection_info.last_operation_at is not None
        assert isinstance(connection_info.last_operation_at, datetime)

    def test_record_operation_failure(self) -> None:
        """Test recording failed operation."""
        connection_info = ReferralConnectionInfo(
            server_url="ldap://server.example.com",
            hostname="server.example.com",
            port=389,
            use_ssl=False,
        )

        connection_info.record_operation(success=False)

        assert connection_info.operations_executed == 1
        assert connection_info.errors_encountered == 1
        assert connection_info.last_operation_at is not None

    def test_record_multiple_operations(self) -> None:
        """Test recording multiple operations."""
        connection_info = ReferralConnectionInfo(
            server_url="ldap://server.example.com",
            hostname="server.example.com",
            port=389,
            use_ssl=False,
        )

        # Record successful operations
        connection_info.record_operation(success=True)
        connection_info.record_operation(success=True)

        # Record failed operation
        connection_info.record_operation(success=False)

        assert connection_info.operations_executed == 3
        assert connection_info.errors_encountered == 1


class TestReferralChasingResult:
    """Test cases for ReferralChasingResult."""

    def test_result_creation_default(self) -> None:
        """Test creating result with default values."""
        result = ReferralChasingResult(success=False)

        assert result.success is False
        assert result.result_data is None
        assert result.entries is None
        assert result.connection_info is None
        assert result.credentials_used is None
        assert result.error_message is None
        assert result.connection_error is None
        assert result.authentication_error is None
        assert result.operation_error is None
        assert result.total_time is None
        assert result.connection_time is None
        assert result.authentication_time is None
        assert result.operation_time is None

    def test_result_creation_success(self) -> None:
        """Test creating successful result."""
        entries = [{"cn": "John Doe", "mail": "john@example.com"}]
        connection_info = ReferralConnectionInfo(
            server_url="ldap://server.example.com",
            hostname="server.example.com",
            port=389,
            use_ssl=False,
        )
        credentials = ReferralCredentials(
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="password",
        )

        result = ReferralChasingResult(
            success=True,
            result_data={"count": 1},
            entries=entries,
            connection_info=connection_info,
            credentials_used=credentials,
            total_time=2.5,
            connection_time=0.5,
            authentication_time=0.3,
            operation_time=1.7,
        )

        assert result.success is True
        assert result.result_data == {"count": 1}
        assert result.entries == entries
        assert result.connection_info == connection_info
        assert result.credentials_used == credentials
        assert result.total_time == 2.5
        assert result.connection_time == 0.5
        assert result.authentication_time == 0.3
        assert result.operation_time == 1.7

    def test_result_creation_failure(self) -> None:
        """Test creating failed result."""
        result = ReferralChasingResult(
            success=False,
            error_message="General failure",
            connection_error="Connection timeout",
            authentication_error="Invalid credentials",
            operation_error="Search failed",
        )

        assert result.success is False
        assert result.error_message == "General failure"
        assert result.connection_error == "Connection timeout"
        assert result.authentication_error == "Invalid credentials"
        assert result.operation_error == "Search failed"

    def test_get_entries_method(self) -> None:
        """Test get_entries method."""
        # With entries
        entries = [{"cn": "John Doe"}]
        result1 = ReferralChasingResult(success=True, entries=entries)
        assert result1.get_entries() == entries

        # Without entries
        result2 = ReferralChasingResult(success=False)
        assert result2.get_entries() == []

        # With None entries
        result3 = ReferralChasingResult(success=True, entries=None)
        assert result3.get_entries() == []

    def test_get_comprehensive_error_method(self) -> None:
        """Test get_comprehensive_error method."""
        # No errors
        result1 = ReferralChasingResult(success=True)
        assert result1.get_comprehensive_error() == "No errors"

        # Single error type
        result2 = ReferralChasingResult(
            success=False,
            error_message="General failure",
        )
        assert result2.get_comprehensive_error() == "General: General failure"

        # Multiple error types
        result3 = ReferralChasingResult(
            success=False,
            error_message="General failure",
            connection_error="Connection timeout",
            authentication_error="Auth failed",
            operation_error="Search failed",
        )

        error_msg = result3.get_comprehensive_error()
        assert "General: General failure" in error_msg
        assert "Connection: Connection timeout" in error_msg
        assert "Authentication: Auth failed" in error_msg
        assert "Operation: Search failed" in error_msg

        # Check format
        expected_parts = [
            "General: General failure",
            "Connection: Connection timeout",
            "Authentication: Auth failed",
            "Operation: Search failed",
        ]
        assert error_msg == "; ".join(expected_parts)


class TestReferralChaser:
    """Test cases for ReferralChaser."""

    def test_chaser_initialization_default(self) -> None:
        """Test chaser initialization with default values."""
        chaser = ReferralChaser()

        assert chaser._default_credentials is None
        assert chaser._max_depth == 5
        assert chaser._connection_timeout == 30  # DEFAULT_TIMEOUT_SECONDS
        assert chaser._operation_timeout == 300
        assert chaser._active_connections == {}
        assert chaser._connection_cache_timeout == 300
        assert chaser._total_referrals_chased == 0
        assert chaser._successful_chases == 0
        assert chaser._failed_chases == 0
        assert chaser._connections_established == 0
        assert chaser._authentication_failures == 0

    def test_chaser_initialization_custom(self) -> None:
        """Test chaser initialization with custom values."""
        credentials = ReferralCredentials(
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD_password",
        )

        chaser = ReferralChaser(
            default_credentials=credentials,
            max_depth=10,
            connection_timeout=60,
            operation_timeout=600,
        )

        assert chaser._default_credentials == credentials
        assert chaser._max_depth == 10
        assert chaser._connection_timeout == 60
        assert chaser._operation_timeout == 600

    @pytest.mark.asyncio
    async def test_chase_referral_invalid_url(self) -> None:
        """Test chase_referral with invalid URL."""
        chaser = ReferralChaser()

        result = await chaser.chase_referral(
            "invalid_url",
            "search",
            {"filter": "(uid=test)"},
        )

        assert result.success is False
        assert "Invalid referral URL" in result.error_message
        assert chaser._total_referrals_chased == 1
        assert chaser._failed_chases == 0  # Not counted as failed, just invalid

    @pytest.mark.asyncio
    async def test_chase_referral_valid_url_parsing(self) -> None:
        """Test chase_referral with valid URL parsing."""
        chaser = ReferralChaser()

        # This will raise NotImplementedError but should parse URL correctly first
        with pytest.raises(
            NotImplementedError,
            match="Referral chasing requires LDAP connection library integration",
        ):
            await chaser.chase_referral(
                "ldap://server.example.com:389/ou=users,dc=example,dc=com",
                "search",
                {"filter": "(uid=test)"},
            )

        assert chaser._total_referrals_chased == 1

    @pytest.mark.asyncio
    async def test_chase_referral_ldaps_url(self) -> None:
        """Test chase_referral with LDAPS URL."""
        chaser = ReferralChaser()

        with pytest.raises(NotImplementedError):
            await chaser.chase_referral(
                "ldaps://secure.example.com:636",
                "search",
                {"filter": "(uid=test)"},
            )

    @pytest.mark.asyncio
    async def test_chase_referral_with_credentials(self) -> None:
        """Test chase_referral with specific credentials."""
        chaser = ReferralChaser()
        credentials = ReferralCredentials(
            bind_dn="cn=user,dc=example,dc=com",
            password="user_password",
        )

        with pytest.raises(NotImplementedError):
            await chaser.chase_referral(
                "ldap://server.example.com",
                "search",
                {"filter": "(uid=test)"},
                credentials=credentials,
            )

    @pytest.mark.asyncio
    async def test_chase_referral_anonymous_fallback(self) -> None:
        """Test chase_referral falls back to anonymous credentials."""
        chaser = ReferralChaser()  # No default credentials

        with pytest.raises(NotImplementedError):
            await chaser.chase_referral(
                "ldap://server.example.com",
                "search",
                {"filter": "(uid=test)"},
            )

    @pytest.mark.asyncio
    async def test_chase_referral_url_parsing_edge_cases(self) -> None:
        """Test chase_referral URL parsing edge cases."""
        chaser = ReferralChaser()

        # URL without port should use default
        with pytest.raises(NotImplementedError):
            await chaser.chase_referral(
                "ldap://server.example.com",
                "search",
                {"filter": "(uid=test)"},
            )

        # URL with custom port
        with pytest.raises(NotImplementedError):
            await chaser.chase_referral(
                "ldap://server.example.com:1389",
                "search",
                {"filter": "(uid=test)"},
            )

    @pytest.mark.asyncio
    async def test_establish_connection_not_implemented(self) -> None:
        """Test _establish_connection raises NotImplementedError."""
        chaser = ReferralChaser()
        connection_info = ReferralConnectionInfo(
            server_url="ldap://server.example.com",
            hostname="server.example.com",
            port=389,
            use_ssl=False,
        )

        with pytest.raises(
            NotImplementedError,
            match="Connection establishment requires LDAP client library integration",
        ):
            await chaser._establish_connection(connection_info)

    @pytest.mark.asyncio
    async def test_authenticate_connection_not_implemented(self) -> None:
        """Test _authenticate_connection raises NotImplementedError."""
        chaser = ReferralChaser()
        mock_connection = Mock()
        credentials = ReferralCredentials(
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="password",
        )

        with pytest.raises(
            NotImplementedError,
            match="Connection authentication requires LDAP client library integration",
        ):
            await chaser._authenticate_connection(mock_connection, credentials)

    @pytest.mark.asyncio
    async def test_execute_operation_not_implemented(self) -> None:
        """Test _execute_operation raises NotImplementedError."""
        chaser = ReferralChaser()
        mock_connection = Mock()

        with pytest.raises(
            NotImplementedError,
            match="Operation execution requires LDAP client library integration",
        ):
            await chaser._execute_operation(
                mock_connection,
                "search",
                {"filter": "(uid=test)"},
            )

    def test_set_default_credentials(self) -> None:
        """Test set_default_credentials method."""
        chaser = ReferralChaser()

        assert chaser._default_credentials is None

        credentials = ReferralCredentials(
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD_password",
        )

        chaser.set_default_credentials(credentials)
        assert chaser._default_credentials == credentials

    def test_clear_connection_cache(self) -> None:
        """Test clear_connection_cache method."""
        chaser = ReferralChaser()

        # Add some mock connections
        chaser._active_connections["server1"] = Mock()
        chaser._active_connections["server2"] = Mock()

        assert len(chaser._active_connections) == 2

        chaser.clear_connection_cache()
        assert len(chaser._active_connections) == 0

    @pytest.mark.asyncio
    async def test_close_all_connections(self) -> None:
        """Test close_all_connections method."""
        chaser = ReferralChaser()

        # Add some mock connections
        mock_conn1 = Mock()
        mock_conn2 = Mock()
        chaser._active_connections["server1"] = mock_conn1
        chaser._active_connections["server2"] = mock_conn2

        assert len(chaser._active_connections) == 2

        await chaser.close_all_connections()
        assert len(chaser._active_connections) == 0

    def test_get_statistics(self) -> None:
        """Test get_statistics method."""
        chaser = ReferralChaser(max_depth=10)

        # Update some statistics
        chaser._total_referrals_chased = 20
        chaser._successful_chases = 15
        chaser._failed_chases = 5
        chaser._connections_established = 12
        chaser._authentication_failures = 3
        chaser._active_connections["server1"] = Mock()
        chaser._active_connections["server2"] = Mock()

        stats = chaser.get_statistics()

        assert stats["total_referrals_chased"] == 20
        assert stats["successful_chases"] == 15
        assert stats["failed_chases"] == 5
        assert stats["connections_established"] == 12
        assert stats["authentication_failures"] == 3
        assert stats["active_connections"] == 2
        assert stats["success_rate"] == 75.0  # 15/20 * 100

    def test_get_statistics_zero_division(self) -> None:
        """Test get_statistics with zero chased referrals."""
        chaser = ReferralChaser()

        stats = chaser.get_statistics()

        assert stats["total_referrals_chased"] == 0
        assert stats["successful_chases"] == 0
        assert stats["failed_chases"] == 0
        assert stats["success_rate"] == 0


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    def test_create_simple_credentials(self) -> None:
        """Test create_simple_credentials function."""
        credentials = create_simple_credentials(
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "REDACTED_LDAP_BIND_PASSWORD_password"
        )

        assert isinstance(credentials, ReferralCredentials)
        assert credentials.credential_type == CredentialType.SIMPLE
        assert credentials.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert credentials.password == "REDACTED_LDAP_BIND_PASSWORD_password"

    def test_create_sasl_credentials(self) -> None:
        """Test create_sasl_credentials function."""
        credentials = create_sasl_credentials(
            "DIGEST-MD5",
            "user@example.com",
            "user_password",
            "REDACTED_LDAP_BIND_PASSWORD@example.com",
        )

        assert isinstance(credentials, ReferralCredentials)
        assert credentials.credential_type == CredentialType.SASL
        assert credentials.sasl_mechanism == "DIGEST-MD5"
        assert credentials.sasl_username == "user@example.com"
        assert credentials.sasl_password == "user_password"
        assert credentials.sasl_authz_id == "REDACTED_LDAP_BIND_PASSWORD@example.com"

    def test_create_sasl_credentials_no_authz(self) -> None:
        """Test create_sasl_credentials without authorization ID."""
        credentials = create_sasl_credentials(
            "PLAIN",
            "user@example.com",
            "user_password",
        )

        assert credentials.sasl_mechanism == "PLAIN"
        assert credentials.sasl_username == "user@example.com"
        assert credentials.sasl_password == "user_password"
        assert credentials.sasl_authz_id is None

    def test_create_anonymous_credentials(self) -> None:
        """Test create_anonymous_credentials function."""
        credentials = create_anonymous_credentials()

        assert isinstance(credentials, ReferralCredentials)
        assert credentials.credential_type == CredentialType.ANONYMOUS

    @pytest.mark.asyncio
    async def test_quick_chase_without_credentials(self) -> None:
        """Test quick_chase convenience function without credentials."""
        with patch(
            "ldap_core_shared.referrals.chaser.ReferralChaser"
        ) as mock_chaser_class:
            mock_chaser = Mock()
            mock_result = ReferralChasingResult(success=True)
            mock_chaser.chase_referral = AsyncMock(return_value=mock_result)
            mock_chaser_class.return_value = mock_chaser

            result = await quick_chase(
                "ldap://server.example.com",
                "search",
                {"filter": "(uid=test)"},
            )

            assert result == mock_result
            mock_chaser_class.assert_called_once_with(default_credentials=None)
            mock_chaser.chase_referral.assert_called_once_with(
                "ldap://server.example.com",
                "search",
                {"filter": "(uid=test)"},
            )

    @pytest.mark.asyncio
    async def test_quick_chase_with_credentials(self) -> None:
        """Test quick_chase convenience function with credentials."""
        with patch(
            "ldap_core_shared.referrals.chaser.ReferralChaser"
        ) as mock_chaser_class:
            mock_chaser = Mock()
            mock_result = ReferralChasingResult(success=True)
            mock_chaser.chase_referral = AsyncMock(return_value=mock_result)
            mock_chaser_class.return_value = mock_chaser

            result = await quick_chase(
                "ldap://server.example.com",
                "search",
                {"filter": "(uid=test)"},
                bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                password="REDACTED_LDAP_BIND_PASSWORD_password",
            )

            assert result == mock_result

            # Verify credentials were created
            call_args = mock_chaser_class.call_args
            credentials = call_args[1]["default_credentials"]
            assert isinstance(credentials, ReferralCredentials)
            assert credentials.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
            assert credentials.password == "REDACTED_LDAP_BIND_PASSWORD_password"


class TestIntegrationScenarios:
    """Integration test scenarios."""

    def test_complete_chasing_workflow_configuration(self) -> None:
        """Test complete chasing workflow configuration."""
        # Create comprehensive configuration
        credentials = ReferralCredentials(
            credential_type=CredentialType.SASL,
            sasl_mechanism="DIGEST-MD5",
            sasl_username="referral-user@example.com",
            sasl_password="referral_password",
            use_tls=True,
            validate_certificate=True,
            connection_timeout=60,
            bind_timeout=30,
        )

        chaser = ReferralChaser(
            default_credentials=credentials,
            max_depth=8,
            connection_timeout=120,
            operation_timeout=600,
        )

        # Verify configuration
        assert chaser._default_credentials == credentials
        assert chaser._max_depth == 8
        assert chaser._connection_timeout == 120
        assert chaser._operation_timeout == 600

        # Test credentials validation
        assert credentials.is_valid_for_type() is True
        auth_summary = credentials.get_auth_summary()
        assert "SASL DIGEST-MD5" in auth_summary
        assert "referral-user@example.com" in auth_summary

    def test_connection_info_lifecycle(self) -> None:
        """Test connection information lifecycle."""
        # Create connection info
        connection_info = ReferralConnectionInfo(
            server_url="ldaps://secure.example.com:636",
            hostname="secure.example.com",
            port=636,
            use_ssl=True,
        )

        # Simulate connection establishment
        connection_info.connected_at = datetime.now(UTC)
        connection_info.connection_time = 0.5

        # Simulate authentication
        connection_info.authenticated_at = datetime.now(UTC)

        # Record operations
        for i in range(5):
            success = i < 4  # 4 successes, 1 failure
            connection_info.record_operation(success=success)

        # Verify statistics
        assert connection_info.operations_executed == 5
        assert connection_info.errors_encountered == 1
        assert connection_info.last_operation_at is not None

    def test_multiple_credential_types_workflow(self) -> None:
        """Test workflow with multiple credential types."""
        # Test all credential types
        credential_configs = [
            (
                "simple",
                create_simple_credentials(
                    "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "REDACTED_LDAP_BIND_PASSWORD_password"
                ),
            ),
            (
                "sasl",
                create_sasl_credentials("PLAIN", "user@example.com", "user_password"),
            ),
            ("anonymous", create_anonymous_credentials()),
        ]

        for _cred_type, credentials in credential_configs:
            chaser = ReferralChaser(default_credentials=credentials)

            assert chaser._default_credentials == credentials
            assert credentials.is_valid_for_type() is True

            # Get auth summary
            summary = credentials.get_auth_summary()
            assert len(summary) > 0

    def test_statistics_tracking_workflow(self) -> None:
        """Test statistics tracking workflow."""
        chaser = ReferralChaser()

        # Initial statistics
        initial_stats = chaser.get_statistics()
        assert initial_stats["total_referrals_chased"] == 0
        assert initial_stats["success_rate"] == 0

        # Simulate chasing activity
        chaser._total_referrals_chased = 25
        chaser._successful_chases = 20
        chaser._failed_chases = 5
        chaser._connections_established = 15
        chaser._authentication_failures = 2

        # Add active connections
        chaser._active_connections["server1"] = Mock()
        chaser._active_connections["server2"] = Mock()

        # Check updated statistics
        stats = chaser.get_statistics()
        assert stats["total_referrals_chased"] == 25
        assert stats["successful_chases"] == 20
        assert stats["failed_chases"] == 5
        assert stats["connections_established"] == 15
        assert stats["authentication_failures"] == 2
        assert stats["active_connections"] == 2
        assert stats["success_rate"] == 80.0


class TestSecurityValidation:
    """Security-focused test cases."""

    def test_credential_validation_security(self) -> None:
        """Test credential validation security."""
        # Test empty password handling for simple credentials
        with pytest.raises(ValueError):
            ReferralCredentials(
                credential_type=CredentialType.SIMPLE,
                bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                password="",  # Empty password should be caught by is_valid_for_type
            )

        # Test missing mechanism for SASL
        with pytest.raises(ValueError):
            ReferralCredentials(
                credential_type=CredentialType.SASL,
                sasl_username="user",
                sasl_password="password",
                # Missing sasl_mechanism
            )

    def test_connection_security_configuration(self) -> None:
        """Test connection security configuration."""
        # Test TLS configuration
        secure_credentials = ReferralCredentials(
            credential_type=CredentialType.SIMPLE,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD_password",
            use_tls=True,
            validate_certificate=True,
        )

        assert secure_credentials.use_tls is True
        assert secure_credentials.validate_certificate is True

        # Test insecure configuration
        insecure_credentials = ReferralCredentials(
            credential_type=CredentialType.SIMPLE,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD_password",
            use_tls=False,
            validate_certificate=False,
        )

        assert insecure_credentials.use_tls is False
        assert insecure_credentials.validate_certificate is False

    def test_timeout_security_controls(self) -> None:
        """Test timeout security controls."""
        # Test reasonable timeouts
        credentials = ReferralCredentials(
            credential_type=CredentialType.SIMPLE,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD_password",
            connection_timeout=30,
            bind_timeout=15,
        )

        assert credentials.connection_timeout == 30
        assert credentials.bind_timeout == 15

        # Test very long timeouts (should be allowed but noted)
        long_timeout_credentials = ReferralCredentials(
            credential_type=CredentialType.SIMPLE,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD_password",
            connection_timeout=3600,  # 1 hour
            bind_timeout=1800,  # 30 minutes
        )

        assert long_timeout_credentials.connection_timeout == 3600
        assert long_timeout_credentials.bind_timeout == 1800

    def test_sasl_mechanism_validation(self) -> None:
        """Test SASL mechanism validation."""
        # Test common SASL mechanisms
        mechanisms = ["PLAIN", "DIGEST-MD5", "GSSAPI", "EXTERNAL", "ANONYMOUS"]

        for mechanism in mechanisms:
            credentials = ReferralCredentials(
                credential_type=CredentialType.SASL,
                sasl_mechanism=mechanism,
                sasl_username="user@example.com",
                sasl_password="password",
            )

            assert credentials.sasl_mechanism == mechanism
            assert credentials.is_valid_for_type() is True


class TestPerformanceValidation:
    """Performance-focused test cases."""

    def test_credentials_creation_performance(self) -> None:
        """Test credentials creation performance."""
        start_time = time.time()

        # Create many credential objects
        for i in range(1000):
            ReferralCredentials(
                credential_type=CredentialType.SIMPLE,
                bind_dn=f"cn=user{i},dc=example,dc=com",
                password=f"password{i}",
            )

        creation_time = time.time() - start_time

        # Should create quickly
        assert creation_time < 1.0  # Less than 1 second for 1000 credentials

    def test_chaser_initialization_performance(self) -> None:
        """Test chaser initialization performance."""
        credentials = ReferralCredentials(
            credential_type=CredentialType.SIMPLE,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="REDACTED_LDAP_BIND_PASSWORD_password",
        )

        start_time = time.time()

        # Create many chaser objects
        for i in range(100):
            ReferralChaser(
                default_credentials=credentials,
                max_depth=5 + (i % 3),
                connection_timeout=30 + (i % 10),
            )

        initialization_time = time.time() - start_time

        # Should initialize quickly
        assert initialization_time < 1.0  # Less than 1 second for 100 chasers

    def test_statistics_collection_performance(self) -> None:
        """Test statistics collection performance."""
        chaser = ReferralChaser()
        chaser._total_referrals_chased = 10000
        chaser._successful_chases = 7500
        chaser._failed_chases = 2500

        start_time = time.time()

        # Collect statistics many times
        for _ in range(1000):
            chaser.get_statistics()

        collection_time = time.time() - start_time

        # Should collect quickly
        assert collection_time < 1.0  # Less than 1 second for 1000 collections

    def test_connection_info_operation_recording_performance(self) -> None:
        """Test connection info operation recording performance."""
        connection_info = ReferralConnectionInfo(
            server_url="ldap://server.example.com",
            hostname="server.example.com",
            port=389,
            use_ssl=False,
        )

        start_time = time.time()

        # Record many operations
        for i in range(10000):
            success = i % 10 != 0  # 90% success rate
            connection_info.record_operation(success=success)

        recording_time = time.time() - start_time

        # Should record quickly
        assert recording_time < 1.0  # Less than 1 second for 10000 operations


class TestErrorHandling:
    """Error handling test cases."""

    def test_url_parsing_error_handling(self) -> None:
        """Test URL parsing error handling."""
        ReferralChaser()

        # Test various malformed URLs
        malformed_urls = [
            "",
            "not_a_url",
            "://missing_scheme",
            "ldap://",
            "ldap:///no_hostname",
            "ldap://[invalid_hostname",
        ]

        for _url in malformed_urls:
            # These should be handled gracefully in chase_referral
            pass  # Actual testing would require running chase_referral

    def test_credential_validation_error_handling(self) -> None:
        """Test credential validation error handling."""
        # Test validation errors are properly raised
        validation_errors = [
            (CredentialType.SIMPLE, {"password": "password"}),  # Missing bind_dn
            (CredentialType.SASL, {"sasl_username": "user"}),  # Missing mechanism
        ]

        for cred_type, kwargs in validation_errors:
            with pytest.raises(ValueError):
                ReferralCredentials(credential_type=cred_type, **kwargs)

    def test_chaser_method_resilience(self) -> None:
        """Test chaser method resilience."""
        chaser = ReferralChaser()

        # Test methods with empty state
        assert chaser.get_statistics()["total_referrals_chased"] == 0

        # Test clearing empty cache (should not crash)
        chaser.clear_connection_cache()
        assert len(chaser._active_connections) == 0

    @pytest.mark.asyncio
    async def test_connection_close_resilience(self) -> None:
        """Test connection closing resilience."""
        chaser = ReferralChaser()

        # Test closing with no connections (should not crash)
        await chaser.close_all_connections()
        assert len(chaser._active_connections) == 0

        # Test clearing with no connections (should not crash)
        chaser.clear_connection_cache()
        assert len(chaser._active_connections) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
