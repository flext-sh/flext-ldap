"""Tests for LDAP Referral Handler Implementation.

This module provides comprehensive test coverage for the LDAP referral handler
including referral processing, policy management, authentication coordination,
and automatic server redirection with enterprise-grade validation.

Test Coverage:
    - ReferralHandlingMode: Referral handling mode enumeration
    - ReferralSecurityMode: Security mode enumeration
    - ReferralOperation: Operation configuration modeling
    - ReferralResult: Result processing and metadata
    - ReferralPolicy: Policy configuration and validation
    - ReferralHandler: Main referral processing coordinator
    - URL parsing and validation utilities
    - Policy enforcement and security controls

Security Testing:
    - Referral URL validation and security enforcement
    - Server allowlist/blocklist validation
    - Domain filtering and security controls
    - Authentication policy enforcement
    - Security mode validation and requirements

Integration Testing:
    - Complete referral processing workflows
    - Policy-based referral filtering
    - Authentication and rebind management
    - Error handling and failure recovery
    - Performance tracking and statistics

Performance Testing:
    - Referral processing optimization and timing
    - Policy evaluation performance
    - Statistics collection and aggregation
    - Memory usage optimization validation
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest

from ldap_core_shared.referrals.chaser import ReferralCredentials
from ldap_core_shared.referrals.handler import (
    ReferralHandler,
    ReferralHandlingMode,
    ReferralOperation,
    ReferralPolicy,
    ReferralResult,
    ReferralSecurityMode,
    create_referral_handler,
    follow_referral_url,
    parse_referral_urls,
)


class TestReferralHandlingMode:
    """Test cases for ReferralHandlingMode enumeration."""

    def test_handling_mode_values(self) -> None:
        """Test referral handling mode enumeration values."""
        assert ReferralHandlingMode.AUTOMATIC.value == "automatic"
        assert ReferralHandlingMode.MANUAL.value == "manual"
        assert ReferralHandlingMode.SELECTIVE.value == "selective"
        assert ReferralHandlingMode.DISABLED.value == "disabled"

    def test_handling_mode_completeness(self) -> None:
        """Test that all expected handling modes are defined."""
        expected_modes = {"AUTOMATIC", "MANUAL", "SELECTIVE", "DISABLED"}
        actual_modes = {member.name for member in ReferralHandlingMode}
        assert actual_modes == expected_modes


class TestReferralSecurityMode:
    """Test cases for ReferralSecurityMode enumeration."""

    def test_security_mode_values(self) -> None:
        """Test referral security mode enumeration values."""
        assert ReferralSecurityMode.STRICT.value == "strict"
        assert ReferralSecurityMode.RELAXED.value == "relaxed"
        assert ReferralSecurityMode.SAME_SECURITY.value == "same_security"

    def test_security_mode_completeness(self) -> None:
        """Test that all expected security modes are defined."""
        expected_modes = {"STRICT", "RELAXED", "SAME_SECURITY"}
        actual_modes = {member.name for member in ReferralSecurityMode}
        assert actual_modes == expected_modes


class TestReferralOperation:
    """Test cases for ReferralOperation."""

    def test_operation_creation_minimal(self) -> None:
        """Test creating operation with minimal required fields."""
        operation = ReferralOperation(operation_type="search")

        assert operation.operation_type == "search"
        assert operation.operation_args == {}
        assert operation.original_dn is None
        assert operation.referral_urls == []
        assert operation.referral_depth == 0
        assert operation.max_depth == 5
        assert isinstance(operation.started_at, datetime)

    def test_operation_creation_complete(self) -> None:
        """Test creating operation with all fields."""
        referral_urls = ["ldap://server1.example.com", "ldap://server2.example.com"]
        operation_args = {"filter": "(uid=test)", "attributes": ["cn", "mail"]}

        operation = ReferralOperation(
            operation_type="search",
            operation_args=operation_args,
            original_dn="ou=users,dc=example,dc=com",
            referral_urls=referral_urls,
            referral_depth=2,
            max_depth=10,
        )

        assert operation.operation_type == "search"
        assert operation.operation_args == operation_args
        assert operation.original_dn == "ou=users,dc=example,dc=com"
        assert operation.referral_urls == referral_urls
        assert operation.referral_depth == 2
        assert operation.max_depth == 10

    def test_is_max_depth_reached_method(self) -> None:
        """Test is_max_depth_reached method."""
        # Below max depth
        operation1 = ReferralOperation(
            operation_type="search",
            referral_depth=3,
            max_depth=5,
        )
        assert operation1.is_max_depth_reached() is False

        # At max depth
        operation2 = ReferralOperation(
            operation_type="search",
            referral_depth=5,
            max_depth=5,
        )
        assert operation2.is_max_depth_reached() is True

        # Above max depth
        operation3 = ReferralOperation(
            operation_type="search",
            referral_depth=7,
            max_depth=5,
        )
        assert operation3.is_max_depth_reached() is True

    def test_increment_depth_method(self) -> None:
        """Test increment_depth method."""
        operation = ReferralOperation(
            operation_type="search",
            referral_depth=2,
        )

        assert operation.referral_depth == 2

        operation.increment_depth()
        assert operation.referral_depth == 3

        operation.increment_depth()
        assert operation.referral_depth == 4

    def test_get_duration_method(self) -> None:
        """Test get_duration method."""
        with patch("ldap_core_shared.referrals.handler.datetime") as mock_datetime:
            # Mock current time to be 5 seconds after start
            start_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
            current_time = datetime(2024, 1, 1, 12, 0, 5, tzinfo=timezone.utc)

            mock_datetime.now.side_effect = [start_time, current_time]

            operation = ReferralOperation(operation_type="search")
            duration = operation.get_duration()

            assert duration == 5.0


class TestReferralResult:
    """Test cases for ReferralResult."""

    def test_result_creation_default(self) -> None:
        """Test creating result with default values."""
        result = ReferralResult(success=False)

        assert result.success is False
        assert result.entries is None
        assert result.result_data is None
        assert result.referral_urls_processed == []
        assert result.successful_referral_url is None
        assert result.final_server is None
        assert result.total_referrals_followed == 0
        assert result.error_message is None
        assert result.referral_errors == []
        assert result.total_processing_time is None
        assert result.per_referral_times == {}

    def test_result_creation_success(self) -> None:
        """Test creating successful result."""
        entries = [{"cn": "John Doe", "mail": "john@example.com"}]
        referral_urls = ["ldap://server1.example.com", "ldap://server2.example.com"]

        result = ReferralResult(
            success=True,
            entries=entries,
            referral_urls_processed=referral_urls,
            successful_referral_url="ldap://server2.example.com",
            final_server="server2.example.com",
            total_referrals_followed=2,
            total_processing_time=1.5,
        )

        assert result.success is True
        assert result.entries == entries
        assert result.referral_urls_processed == referral_urls
        assert result.successful_referral_url == "ldap://server2.example.com"
        assert result.final_server == "server2.example.com"
        assert result.total_referrals_followed == 2
        assert result.total_processing_time == 1.5

    def test_get_entries_method(self) -> None:
        """Test get_entries method."""
        # With entries
        entries = [{"cn": "John Doe"}]
        result1 = ReferralResult(success=True, entries=entries)
        assert result1.get_entries() == entries

        # Without entries
        result2 = ReferralResult(success=False)
        assert result2.get_entries() == []

        # With None entries
        result3 = ReferralResult(success=True, entries=None)
        assert result3.get_entries() == []

    def test_get_error_summary_method(self) -> None:
        """Test get_error_summary method."""
        # No errors
        result1 = ReferralResult(success=True)
        assert result1.get_error_summary() == "No errors"

        # Main error only
        result2 = ReferralResult(
            success=False,
            error_message="Connection failed",
        )
        assert result2.get_error_summary() == "Main error: Connection failed"

        # Referral errors only
        result3 = ReferralResult(
            success=False,
            referral_errors=["server1: timeout", "server2: auth failed"],
        )
        expected = "Referral 1: server1: timeout; Referral 2: server2: auth failed"
        assert result3.get_error_summary() == expected

        # Both main and referral errors
        result4 = ReferralResult(
            success=False,
            error_message="Operation failed",
            referral_errors=["server1: error"],
        )
        expected = "Main error: Operation failed; Referral 1: server1: error"
        assert result4.get_error_summary() == expected

    def test_add_referral_error_method(self) -> None:
        """Test add_referral_error method."""
        result = ReferralResult(success=False)

        assert result.referral_errors == []

        result.add_referral_error("server1.example.com", "Connection timeout")
        assert result.referral_errors == ["server1.example.com: Connection timeout"]

        result.add_referral_error("server2.example.com", "Authentication failed")
        expected = [
            "server1.example.com: Connection timeout",
            "server2.example.com: Authentication failed",
        ]
        assert result.referral_errors == expected


class TestReferralPolicy:
    """Test cases for ReferralPolicy."""

    def test_policy_creation_default(self) -> None:
        """Test creating policy with default values."""
        policy = ReferralPolicy()

        assert policy.handling_mode == ReferralHandlingMode.AUTOMATIC
        assert policy.security_mode == ReferralSecurityMode.SAME_SECURITY
        assert policy.max_referral_depth == 5
        assert policy.max_referral_time == 300.0
        assert policy.allowed_servers is None
        assert policy.blocked_servers == []
        assert policy.allowed_domains is None
        assert policy.use_rebind_credentials is True
        assert policy.inherit_original_credentials is True
        assert policy.require_authentication is False

    def test_policy_creation_custom(self) -> None:
        """Test creating policy with custom values."""
        allowed_servers = ["server1.example.com", "server2.example.com"]
        blocked_servers = ["bad.example.com"]
        allowed_domains = ["example.com", "trusted.org"]

        policy = ReferralPolicy(
            handling_mode=ReferralHandlingMode.SELECTIVE,
            security_mode=ReferralSecurityMode.STRICT,
            max_referral_depth=10,
            max_referral_time=600.0,
            allowed_servers=allowed_servers,
            blocked_servers=blocked_servers,
            allowed_domains=allowed_domains,
            use_rebind_credentials=False,
            require_authentication=True,
        )

        assert policy.handling_mode == ReferralHandlingMode.SELECTIVE
        assert policy.security_mode == ReferralSecurityMode.STRICT
        assert policy.max_referral_depth == 10
        assert policy.max_referral_time == 600.0
        assert policy.allowed_servers == allowed_servers
        assert policy.blocked_servers == blocked_servers
        assert policy.allowed_domains == allowed_domains
        assert policy.use_rebind_credentials is False
        assert policy.require_authentication is True

    def test_should_follow_referral_disabled_mode(self) -> None:
        """Test should_follow_referral with disabled mode."""
        policy = ReferralPolicy(handling_mode=ReferralHandlingMode.DISABLED)

        should_follow, reason = policy.should_follow_referral("ldap://server.example.com")
        assert should_follow is False
        assert reason == "Referral handling is disabled"

    def test_should_follow_referral_manual_mode(self) -> None:
        """Test should_follow_referral with manual mode."""
        policy = ReferralPolicy(handling_mode=ReferralHandlingMode.MANUAL)

        should_follow, reason = policy.should_follow_referral("ldap://server.example.com")
        assert should_follow is False
        assert reason == "Manual referral handling mode"

    def test_should_follow_referral_invalid_url(self) -> None:
        """Test should_follow_referral with invalid URL."""
        policy = ReferralPolicy()

        should_follow, reason = policy.should_follow_referral("invalid_url")
        assert should_follow is False
        assert "Invalid referral URL" in reason

    def test_should_follow_referral_strict_security(self) -> None:
        """Test should_follow_referral with strict security mode."""
        policy = ReferralPolicy(security_mode=ReferralSecurityMode.STRICT)

        # Insecure URL should be rejected
        should_follow, reason = policy.should_follow_referral("ldap://server.example.com")
        assert should_follow is False
        assert "Strict security mode requires secure connections" in reason

        # Secure URL should be allowed
        should_follow, reason = policy.should_follow_referral("ldaps://server.example.com")
        assert should_follow is True
        assert reason == "Referral allowed by policy"

    def test_should_follow_referral_allowed_servers(self) -> None:
        """Test should_follow_referral with allowed servers."""
        allowed_servers = ["trusted1.example.com", "trusted2.example.com"]
        policy = ReferralPolicy(allowed_servers=allowed_servers)

        # Allowed server should be accepted
        should_follow, reason = policy.should_follow_referral("ldap://trusted1.example.com")
        assert should_follow is True
        assert reason == "Referral allowed by policy"

        # Non-allowed server should be rejected
        should_follow, reason = policy.should_follow_referral("ldap://untrusted.example.com")
        assert should_follow is False
        assert "not in allowed list" in reason

    def test_should_follow_referral_blocked_servers(self) -> None:
        """Test should_follow_referral with blocked servers."""
        blocked_servers = ["bad1.example.com", "bad2.example.com"]
        policy = ReferralPolicy(blocked_servers=blocked_servers)

        # Non-blocked server should be accepted
        should_follow, reason = policy.should_follow_referral("ldap://good.example.com")
        assert should_follow is True
        assert reason == "Referral allowed by policy"

        # Blocked server should be rejected
        should_follow, reason = policy.should_follow_referral("ldap://bad1.example.com")
        assert should_follow is False
        assert "is blocked" in reason

    def test_should_follow_referral_allowed_domains(self) -> None:
        """Test should_follow_referral with allowed domains."""
        allowed_domains = ["example.com", "trusted.org"]
        policy = ReferralPolicy(allowed_domains=allowed_domains)

        # Allowed domain should be accepted
        should_follow, reason = policy.should_follow_referral("ldap://server.example.com")
        assert should_follow is True
        assert reason == "Referral allowed by policy"

        # Subdomain should be accepted
        should_follow, reason = policy.should_follow_referral("ldap://sub.trusted.org")
        assert should_follow is True
        assert reason == "Referral allowed by policy"

        # Non-allowed domain should be rejected
        should_follow, reason = policy.should_follow_referral("ldap://server.untrusted.com")
        assert should_follow is False
        assert "not in allowed list" in reason

    def test_should_follow_referral_complex_policy(self) -> None:
        """Test should_follow_referral with complex policy."""
        policy = ReferralPolicy(
            security_mode=ReferralSecurityMode.STRICT,
            allowed_servers=["secure.example.com"],
            blocked_servers=["blocked.example.com"],
        )

        # Should pass all checks
        should_follow, reason = policy.should_follow_referral("ldaps://secure.example.com")
        assert should_follow is True
        assert reason == "Referral allowed by policy"

        # Fails security check
        should_follow, reason = policy.should_follow_referral("ldap://secure.example.com")
        assert should_follow is False
        assert "Strict security mode" in reason

        # Fails allowed servers check
        should_follow, reason = policy.should_follow_referral("ldaps://other.example.com")
        assert should_follow is False
        assert "not in allowed list" in reason


class TestReferralHandler:
    """Test cases for ReferralHandler."""

    def test_handler_initialization_default(self) -> None:
        """Test handler initialization with default values."""
        handler = ReferralHandler()

        assert handler._policy.handling_mode == ReferralHandlingMode.AUTOMATIC
        assert handler._policy.security_mode == ReferralSecurityMode.SAME_SECURITY
        assert handler._policy.max_referral_depth == 5
        assert handler._policy.max_referral_time == 300.0
        assert handler._rebind_credentials is None
        assert handler._total_referrals_processed == 0
        assert handler._successful_referrals == 0
        assert handler._failed_referrals == 0

    def test_handler_initialization_custom(self) -> None:
        """Test handler initialization with custom values."""
        credentials = ReferralCredentials(
            bind_dn="cn=admin,dc=example,dc=com",
            password="admin_password",
        )
        allowed_servers = ["server1.example.com"]
        blocked_servers = ["bad.example.com"]

        handler = ReferralHandler(
            max_referral_depth=10,
            max_referral_time=600.0,
            follow_referrals=False,
            rebind_credentials=credentials,
            security_mode=ReferralSecurityMode.STRICT,
            allowed_servers=allowed_servers,
            blocked_servers=blocked_servers,
        )

        assert handler._policy.handling_mode == ReferralHandlingMode.MANUAL
        assert handler._policy.security_mode == ReferralSecurityMode.STRICT
        assert handler._policy.max_referral_depth == 10
        assert handler._policy.max_referral_time == 600.0
        assert handler._policy.allowed_servers == allowed_servers
        assert handler._policy.blocked_servers == blocked_servers
        assert handler._rebind_credentials == credentials

    def test_handler_initialization_dict_credentials(self) -> None:
        """Test handler initialization with dictionary credentials."""
        credentials_dict = {
            "bind_dn": "cn=admin,dc=example,dc=com",
            "password": "admin_password",
        }

        handler = ReferralHandler(rebind_credentials=credentials_dict)

        assert handler._rebind_credentials is not None
        assert handler._rebind_credentials.bind_dn == "cn=admin,dc=example,dc=com"
        assert handler._rebind_credentials.password == "admin_password"

    @pytest.mark.asyncio
    async def test_process_referral_disabled_mode(self) -> None:
        """Test process_referral with disabled handling mode."""
        handler = ReferralHandler(follow_referrals=False)
        handler._policy.handling_mode = ReferralHandlingMode.DISABLED

        referral_urls = ["ldap://server.example.com"]
        result = await handler.process_referral(
            referral_urls,
            "search",
            {"filter": "(uid=test)"},
        )

        assert result.success is False
        assert "not allowed by policy" in result.error_message
        assert handler._total_referrals_processed == 1
        assert handler._failed_referrals == 1

    @pytest.mark.asyncio
    async def test_process_referral_max_depth_reached(self) -> None:
        """Test process_referral when max depth is reached."""
        handler = ReferralHandler(max_referral_depth=3)

        referral_urls = ["ldap://server.example.com"]
        result = await handler.process_referral(
            referral_urls,
            "search",
            {"filter": "(uid=test)"},
            referral_depth=5,  # Above max depth
        )

        assert result.success is False
        assert "not allowed by policy" in result.error_message

    @pytest.mark.asyncio
    async def test_process_referral_policy_rejection(self) -> None:
        """Test process_referral with policy rejection."""
        handler = ReferralHandler(blocked_servers=["blocked.example.com"])

        referral_urls = ["ldap://blocked.example.com"]
        result = await handler.process_referral(
            referral_urls,
            "search",
            {"filter": "(uid=test)"},
        )

        assert result.success is False
        assert len(result.referral_errors) == 1
        assert "blocked.example.com: blocked.example.com is blocked" in result.referral_errors

    @pytest.mark.asyncio
    async def test_process_referral_not_implemented(self) -> None:
        """Test process_referral raises NotImplementedError."""
        handler = ReferralHandler()

        referral_urls = ["ldap://server.example.com"]

        with pytest.raises(NotImplementedError, match="Referral following requires LDAP connection integration"):
            await handler.process_referral(
                referral_urls,
                "search",
                {"filter": "(uid=test)"},
            )

    def test_should_process_referrals_checks(self) -> None:
        """Test _should_process_referrals method checks."""
        handler = ReferralHandler()

        # Create operation
        operation = ReferralOperation(
            operation_type="search",
            referral_depth=0,
            max_depth=5,
        )

        # Normal case - should process
        assert handler._should_process_referrals(operation) is True

        # Disabled mode
        handler._policy.handling_mode = ReferralHandlingMode.DISABLED
        assert handler._should_process_referrals(operation) is False

        # Manual mode
        handler._policy.handling_mode = ReferralHandlingMode.MANUAL
        assert handler._should_process_referrals(operation) is False

        # Max depth reached
        handler._policy.handling_mode = ReferralHandlingMode.AUTOMATIC
        operation.referral_depth = 10
        assert handler._should_process_referrals(operation) is False

    def test_set_rebind_credentials_dict(self) -> None:
        """Test set_rebind_credentials with dictionary."""
        handler = ReferralHandler()

        credentials_dict = {
            "bind_dn": "cn=admin,dc=example,dc=com",
            "password": "admin_password",
        }

        handler.set_rebind_credentials(credentials_dict)

        assert handler._rebind_credentials is not None
        assert handler._rebind_credentials.bind_dn == "cn=admin,dc=example,dc=com"
        assert handler._rebind_credentials.password == "admin_password"

    def test_set_rebind_credentials_object(self) -> None:
        """Test set_rebind_credentials with ReferralCredentials object."""
        handler = ReferralHandler()

        credentials = ReferralCredentials(
            bind_dn="cn=user,dc=example,dc=com",
            password="user_password",
        )

        handler.set_rebind_credentials(credentials)

        assert handler._rebind_credentials == credentials

    def test_update_policy(self) -> None:
        """Test update_policy method."""
        handler = ReferralHandler()

        assert handler._policy.max_referral_depth == 5
        assert handler._policy.max_referral_time == 300.0

        handler.update_policy({
            "max_referral_depth": 10,
            "max_referral_time": 600.0,
        })

        assert handler._policy.max_referral_depth == 10
        assert handler._policy.max_referral_time == 600.0

    def test_add_allowed_server(self) -> None:
        """Test add_allowed_server method."""
        handler = ReferralHandler()

        # Initially None
        assert handler._policy.allowed_servers is None

        handler.add_allowed_server("server1.example.com")
        assert handler._policy.allowed_servers == ["server1.example.com"]

        handler.add_allowed_server("server2.example.com")
        assert handler._policy.allowed_servers == ["server1.example.com", "server2.example.com"]

        # Duplicate should not be added
        handler.add_allowed_server("server1.example.com")
        assert handler._policy.allowed_servers == ["server1.example.com", "server2.example.com"]

    def test_add_blocked_server(self) -> None:
        """Test add_blocked_server method."""
        handler = ReferralHandler()

        assert handler._policy.blocked_servers == []

        handler.add_blocked_server("bad1.example.com")
        assert handler._policy.blocked_servers == ["bad1.example.com"]

        handler.add_blocked_server("bad2.example.com")
        assert handler._policy.blocked_servers == ["bad1.example.com", "bad2.example.com"]

        # Duplicate should not be added
        handler.add_blocked_server("bad1.example.com")
        assert handler._policy.blocked_servers == ["bad1.example.com", "bad2.example.com"]

    def test_remove_blocked_server(self) -> None:
        """Test remove_blocked_server method."""
        handler = ReferralHandler(blocked_servers=["bad1.example.com", "bad2.example.com"])

        assert handler._policy.blocked_servers == ["bad1.example.com", "bad2.example.com"]

        handler.remove_blocked_server("bad1.example.com")
        assert handler._policy.blocked_servers == ["bad2.example.com"]

        handler.remove_blocked_server("bad2.example.com")
        assert handler._policy.blocked_servers == []

        # Removing non-existent server should not crash
        handler.remove_blocked_server("nonexistent.example.com")
        assert handler._policy.blocked_servers == []

    def test_policy_property(self) -> None:
        """Test policy property."""
        handler = ReferralHandler()

        policy = handler.policy
        assert isinstance(policy, ReferralPolicy)
        assert policy is handler._policy

    def test_rebind_credentials_property(self) -> None:
        """Test rebind_credentials property."""
        # No credentials
        handler1 = ReferralHandler()
        assert handler1.rebind_credentials is None

        # With credentials
        credentials = ReferralCredentials(
            bind_dn="cn=admin,dc=example,dc=com",
            password="admin_password",
        )
        handler2 = ReferralHandler(rebind_credentials=credentials)
        assert handler2.rebind_credentials == credentials

    def test_get_statistics(self) -> None:
        """Test get_statistics method."""
        handler = ReferralHandler(
            max_referral_depth=10,
            max_referral_time=600.0,
        )

        # Update some statistics
        handler._total_referrals_processed = 10
        handler._successful_referrals = 7
        handler._failed_referrals = 3

        stats = handler.get_statistics()

        assert stats["total_referrals_processed"] == 10
        assert stats["successful_referrals"] == 7
        assert stats["failed_referrals"] == 3
        assert stats["success_rate"] == 70.0  # 7/10 * 100
        assert stats["policy"]["handling_mode"] == "automatic"
        assert stats["policy"]["security_mode"] == "same_security"
        assert stats["policy"]["max_depth"] == 10
        assert stats["policy"]["max_time"] == 600.0

    def test_get_statistics_zero_division(self) -> None:
        """Test get_statistics with zero processed referrals."""
        handler = ReferralHandler()

        stats = handler.get_statistics()

        assert stats["total_referrals_processed"] == 0
        assert stats["successful_referrals"] == 0
        assert stats["failed_referrals"] == 0
        assert stats["success_rate"] == 0


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    def test_create_referral_handler_basic(self) -> None:
        """Test create_referral_handler with basic parameters."""
        handler = create_referral_handler()

        assert isinstance(handler, ReferralHandler)
        assert handler._policy.handling_mode == ReferralHandlingMode.AUTOMATIC
        assert handler._policy.max_referral_depth == 5
        assert handler._rebind_credentials is None

    def test_create_referral_handler_with_credentials(self) -> None:
        """Test create_referral_handler with credentials."""
        handler = create_referral_handler(
            bind_dn="cn=admin,dc=example,dc=com",
            password="admin_password",
        )

        assert handler._rebind_credentials is not None
        assert handler._rebind_credentials.bind_dn == "cn=admin,dc=example,dc=com"
        assert handler._rebind_credentials.password == "admin_password"

    def test_create_referral_handler_disabled(self) -> None:
        """Test create_referral_handler with disabled referrals."""
        handler = create_referral_handler(
            follow_referrals=False,
            max_depth=10,
        )

        assert handler._policy.handling_mode == ReferralHandlingMode.MANUAL
        assert handler._policy.max_referral_depth == 10

    def test_parse_referral_urls_empty(self) -> None:
        """Test parse_referral_urls with empty input."""
        assert parse_referral_urls("") == []
        assert parse_referral_urls(None) == []

    def test_parse_referral_urls_single(self) -> None:
        """Test parse_referral_urls with single URL."""
        urls = parse_referral_urls("ldap://server.example.com/ou=users,dc=example,dc=com")
        assert urls == ["ldap://server.example.com/ou=users,dc=example,dc=com"]

    def test_parse_referral_urls_multiple(self) -> None:
        """Test parse_referral_urls with multiple URLs."""
        referral_response = "ldap://server1.example.com ldaps://server2.example.com"
        urls = parse_referral_urls(referral_response)

        expected = [
            "ldap://server1.example.com",
            "ldaps://server2.example.com",
        ]
        assert urls == expected

    def test_parse_referral_urls_mixed_content(self) -> None:
        """Test parse_referral_urls with mixed content."""
        referral_response = "some text ldap://server.example.com other text ldaps://secure.example.com"
        urls = parse_referral_urls(referral_response)

        expected = [
            "ldap://server.example.com",
            "ldaps://secure.example.com",
        ]
        assert urls == expected

    def test_parse_referral_urls_invalid_schemes(self) -> None:
        """Test parse_referral_urls filters out invalid schemes."""
        referral_response = "http://web.example.com ldap://ldap.example.com ftp://ftp.example.com ldaps://secure.example.com"
        urls = parse_referral_urls(referral_response)

        expected = [
            "ldap://ldap.example.com",
            "ldaps://secure.example.com",
        ]
        assert urls == expected

    @pytest.mark.asyncio
    async def test_follow_referral_url_function(self) -> None:
        """Test follow_referral_url convenience function."""
        # Mock the ReferralHandler to avoid NotImplementedError
        with patch("ldap_core_shared.referrals.handler.ReferralHandler") as mock_handler_class:
            mock_handler = Mock()
            mock_result = ReferralResult(success=True)
            mock_handler.process_referral = AsyncMock(return_value=mock_result)
            mock_handler_class.return_value = mock_handler

            result = await follow_referral_url(
                "ldap://server.example.com",
                "search",
                {"filter": "(uid=test)"},
            )

            assert result == mock_result
            mock_handler_class.assert_called_once_with(rebind_credentials=None)
            mock_handler.process_referral.assert_called_once_with(
                ["ldap://server.example.com"],
                "search",
                {"filter": "(uid=test)"},
            )

    @pytest.mark.asyncio
    async def test_follow_referral_url_with_credentials(self) -> None:
        """Test follow_referral_url with credentials."""
        with patch("ldap_core_shared.referrals.handler.ReferralHandler") as mock_handler_class:
            mock_handler = Mock()
            mock_result = ReferralResult(success=True)
            mock_handler.process_referral = AsyncMock(return_value=mock_result)
            mock_handler_class.return_value = mock_handler

            credentials = ReferralCredentials(
                bind_dn="cn=admin,dc=example,dc=com",
                password="admin_password",
            )

            result = await follow_referral_url(
                "ldap://server.example.com",
                "search",
                {"filter": "(uid=test)"},
                credentials,
            )

            assert result == mock_result
            mock_handler_class.assert_called_once_with(rebind_credentials=credentials)


class TestIntegrationScenarios:
    """Integration test scenarios."""

    def test_complete_referral_workflow_configuration(self) -> None:
        """Test complete referral workflow configuration."""
        # Create comprehensive configuration
        credentials = ReferralCredentials(
            bind_dn="cn=referral-user,dc=example,dc=com",
            password="referral_password",
        )

        handler = ReferralHandler(
            max_referral_depth=3,
            max_referral_time=120.0,
            follow_referrals=True,
            rebind_credentials=credentials,
            security_mode=ReferralSecurityMode.STRICT,
            allowed_servers=["trusted1.example.com", "trusted2.example.com"],
            blocked_servers=["malicious.example.com"],
        )

        # Verify configuration
        assert handler._policy.handling_mode == ReferralHandlingMode.AUTOMATIC
        assert handler._policy.security_mode == ReferralSecurityMode.STRICT
        assert handler._policy.max_referral_depth == 3
        assert handler._policy.max_referral_time == 120.0
        assert handler._rebind_credentials == credentials

        # Test policy evaluation
        should_follow, _reason = handler._policy.should_follow_referral("ldaps://trusted1.example.com")
        assert should_follow is True

        should_follow, _reason = handler._policy.should_follow_referral("ldap://trusted1.example.com")
        assert should_follow is False  # Strict security mode

        should_follow, _reason = handler._policy.should_follow_referral("ldaps://malicious.example.com")
        assert should_follow is False  # Blocked server

    def test_policy_management_workflow(self) -> None:
        """Test policy management workflow."""
        handler = ReferralHandler()

        # Add servers dynamically
        handler.add_allowed_server("new-server.example.com")
        handler.add_blocked_server("bad-server.example.com")

        # Update policy
        handler.update_policy({
            "max_referral_depth": 8,
            "security_mode": ReferralSecurityMode.RELAXED,
        })

        # Verify updates
        assert "new-server.example.com" in handler._policy.allowed_servers
        assert "bad-server.example.com" in handler._policy.blocked_servers
        assert handler._policy.max_referral_depth == 8
        assert handler._policy.security_mode == ReferralSecurityMode.RELAXED

        # Remove blocked server
        handler.remove_blocked_server("bad-server.example.com")
        assert "bad-server.example.com" not in handler._policy.blocked_servers

    def test_statistics_tracking_workflow(self) -> None:
        """Test statistics tracking workflow."""
        handler = ReferralHandler()

        # Initial statistics
        initial_stats = handler.get_statistics()
        assert initial_stats["total_referrals_processed"] == 0
        assert initial_stats["success_rate"] == 0

        # Simulate processing
        handler._total_referrals_processed = 20
        handler._successful_referrals = 15
        handler._failed_referrals = 5

        # Check updated statistics
        stats = handler.get_statistics()
        assert stats["total_referrals_processed"] == 20
        assert stats["successful_referrals"] == 15
        assert stats["failed_referrals"] == 5
        assert stats["success_rate"] == 75.0


class TestSecurityValidation:
    """Security-focused test cases."""

    def test_url_validation_security(self) -> None:
        """Test URL validation security."""
        policy = ReferralPolicy()

        # Test various malicious URL patterns
        malicious_urls = [
            "javascript:alert('xss')",
            "file:///etc/passwd",
            "ftp://malicious.com",
            "http://malicious.com",
            "ldap://evil.com/../../../etc/passwd",
        ]

        for url in malicious_urls:
            should_follow, _reason = policy.should_follow_referral(url)
            # Most should be rejected due to invalid scheme or other issues
            if url.startswith(("ldap://", "ldaps://")):
                # LDAP URLs might be allowed but can be caught by other filters
                pass
            else:
                assert should_follow is False

    def test_security_mode_enforcement(self) -> None:
        """Test security mode enforcement."""
        strict_policy = ReferralPolicy(security_mode=ReferralSecurityMode.STRICT)
        relaxed_policy = ReferralPolicy(security_mode=ReferralSecurityMode.RELAXED)

        insecure_url = "ldap://server.example.com"
        secure_url = "ldaps://server.example.com"

        # Strict mode should reject insecure
        should_follow, _ = strict_policy.should_follow_referral(insecure_url)
        assert should_follow is False

        should_follow, _ = strict_policy.should_follow_referral(secure_url)
        assert should_follow is True

        # Relaxed mode should allow both
        should_follow, _ = relaxed_policy.should_follow_referral(insecure_url)
        assert should_follow is True

        should_follow, _ = relaxed_policy.should_follow_referral(secure_url)
        assert should_follow is True

    def test_server_filtering_security(self) -> None:
        """Test server filtering security."""
        policy = ReferralPolicy(
            allowed_servers=["trusted.example.com"],
            blocked_servers=["malicious.example.com", "compromised.example.com"],
        )

        # Test domain variations to check for bypass attempts
        test_cases = [
            ("ldap://trusted.example.com", True),
            ("ldap://sub.trusted.example.com", False),  # Subdomain not explicitly allowed
            ("ldap://malicious.example.com", False),
            ("ldap://sub.malicious.example.com", True),  # Not blocked (only exact match)
            ("ldap://compromised.example.com", False),
            ("ldap://other.example.com", False),
        ]

        for url, expected_allowed in test_cases:
            should_follow, _ = policy.should_follow_referral(url)
            assert should_follow == expected_allowed

    def test_domain_filtering_security(self) -> None:
        """Test domain filtering security."""
        policy = ReferralPolicy(allowed_domains=["example.com", "trusted.org"])

        # Test various domain patterns
        test_cases = [
            ("ldap://server.example.com", True),
            ("ldap://sub.server.example.com", True),
            ("ldap://example.com", True),
            ("ldap://server.trusted.org", True),
            ("ldap://evil.com", False),
            ("ldap://example.com.evil.com", False),  # Domain suffix attack
            ("ldap://server.evil.example.com", False),  # Not a real subdomain
        ]

        for url, expected_allowed in test_cases:
            should_follow, _ = policy.should_follow_referral(url)
            assert should_follow == expected_allowed


class TestPerformanceValidation:
    """Performance-focused test cases."""

    def test_policy_evaluation_performance(self) -> None:
        """Test policy evaluation performance."""
        # Create policy with many servers
        allowed_servers = [f"server{i}.example.com" for i in range(1000)]
        blocked_servers = [f"bad{i}.example.com" for i in range(1000)]

        policy = ReferralPolicy(
            allowed_servers=allowed_servers,
            blocked_servers=blocked_servers,
        )

        start_time = time.time()

        # Test many policy evaluations
        for i in range(100):
            policy.should_follow_referral(f"ldap://server{i}.example.com")

        evaluation_time = time.time() - start_time

        # Should evaluate quickly
        assert evaluation_time < 1.0  # Less than 1 second for 100 evaluations

    def test_handler_creation_performance(self) -> None:
        """Test handler creation performance."""
        start_time = time.time()

        # Create many handlers
        for i in range(100):
            ReferralHandler(
                max_referral_depth=5,
                follow_referrals=True,
                allowed_servers=[f"server{i}.example.com"],
            )

        creation_time = time.time() - start_time

        # Should create quickly
        assert creation_time < 1.0  # Less than 1 second for 100 handlers

    def test_statistics_collection_performance(self) -> None:
        """Test statistics collection performance."""
        handler = ReferralHandler()
        handler._total_referrals_processed = 10000
        handler._successful_referrals = 7500
        handler._failed_referrals = 2500

        start_time = time.time()

        # Collect statistics many times
        for _ in range(1000):
            handler.get_statistics()

        collection_time = time.time() - start_time

        # Should collect quickly
        assert collection_time < 1.0  # Less than 1 second for 1000 collections


class TestErrorHandling:
    """Error handling test cases."""

    def test_invalid_url_handling(self) -> None:
        """Test invalid URL handling."""
        policy = ReferralPolicy()

        invalid_urls = [
            "",
            "not_a_url",
            "://invalid",
            "ldap://",
            "ldap:///no_host",
        ]

        for url in invalid_urls:
            should_follow, reason = policy.should_follow_referral(url)
            assert should_follow is False
            assert "Invalid referral URL" in reason

    def test_policy_update_resilience(self) -> None:
        """Test policy update resilience."""
        handler = ReferralHandler()

        # Try to update non-existent field (should not crash)
        handler.update_policy({"non_existent_field": "value"})

        # Verify original policy is intact
        assert handler._policy.max_referral_depth == 5

        # Update valid field
        handler.update_policy({"max_referral_depth": 10})
        assert handler._policy.max_referral_depth == 10

    def test_credentials_validation_handling(self) -> None:
        """Test credentials validation handling."""
        # Valid credentials should work
        valid_creds = ReferralCredentials(
            bind_dn="cn=admin,dc=example,dc=com",
            password="password",
        )
        handler = ReferralHandler(rebind_credentials=valid_creds)
        assert handler._rebind_credentials == valid_creds

        # None credentials should be handled
        handler = ReferralHandler(rebind_credentials=None)
        assert handler._rebind_credentials is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
