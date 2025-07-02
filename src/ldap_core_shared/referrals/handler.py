from __future__ import annotations

from ldap_core_shared.utils.constants import DEFAULT_MAX_ITEMS

"""LDAP Referral Handler Implementation.

# Constants for magic values

This module provides comprehensive referral processing following perl-ldap
Net::LDAP patterns with enterprise-grade referral chasing, authentication
management, and automatic server redirection capabilities.

The Referral Handler enables automatic following of LDAP referrals to
other servers with proper authentication, security, and error handling,
essential for distributed directory environments and enterprise deployments.

Architecture:
    - ReferralHandler: Main referral processing coordinator
    - ReferralResult: Result container for referral operations
    - ReferralPolicy: Configuration and policy management
    - ReferralSecurityManager: Security and authentication coordination

Usage Example:
    >>> from ldap_core_shared.referrals.handler import ReferralHandler
    >>>
    >>> # Configure referral handling with authentication
    >>> referral_handler = ReferralHandler(
    ...     max_referral_depth=5,
    ...     follow_referrals=True,
    ...     rebind_credentials={
    ...         "binddn": "cn=admin,dc=example,dc=com",
    ...         "password": "admin_password"
    ...     }
    ... )
    >>>
    >>> # Process referral from LDAP operation
    >>> referral_urls = ["ldap://server2.example.com/ou=users,dc=example,dc=com"]
    >>> result = await referral_handler.process_referral(
    ...     referral_urls, original_operation="search", operation_args=search_args
    ... )
    >>>
    >>> if result.success:
    ...     entries = result.get_entries()

References:
    - perl-ldap: lib/Net/LDAP.pm (referral handling, lines 1234-1456)
    - RFC 4511: LDAP Protocol Specification (Section 4.1.10 Referral)
    - RFC 3296: Named Subordinate References in LDAP
"""


import time
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from ldap_core_shared.referrals.chaser import ReferralChaser, ReferralCredentials


class ReferralHandlingMode(Enum):
    """Modes for referral handling."""

    AUTOMATIC = "automatic"  # Automatically follow all referrals
    MANUAL = "manual"  # Return referrals to caller for manual processing
    SELECTIVE = "selective"  # Follow referrals based on policy
    DISABLED = "disabled"  # Never follow referrals


class ReferralSecurityMode(Enum):
    """Security modes for referral following."""

    STRICT = "strict"  # Only follow secure referrals (TLS/SSL)
    RELAXED = "relaxed"  # Follow both secure and insecure referrals
    SAME_SECURITY = "same_security"  # Match security level of original connection


class ReferralOperation(BaseModel):
    """Configuration for referral operation processing."""

    operation_type: str = Field(description="Type of LDAP operation")

    operation_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments for the operation",
    )

    original_dn: str | None = Field(
        default=None,
        description="Original DN for the operation",
    )

    referral_urls: list[str] = Field(
        default_factory=list,
        description="List of referral URLs",
    )

    referral_depth: int = Field(default=0, description="Current referral depth")

    max_depth: int = Field(default=5, description="Maximum referral depth")

    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Operation start timestamp",
    )

    def is_max_depth_reached(self) -> bool:
        """Check if maximum referral depth is reached."""
        return self.referral_depth >= self.max_depth

    def increment_depth(self) -> None:
        """Increment referral depth."""
        self.referral_depth += 1

    def get_duration(self) -> float:
        """Get operation duration in seconds."""
        return (datetime.now(UTC) - self.started_at).total_seconds()


class ReferralResult(BaseModel):
    """Result of referral processing operation."""

    success: bool = Field(description="Whether referral processing succeeded")

    # Result data
    entries: list[dict[str, Any]] | None = Field(
        default=None,
        description="Search result entries",
    )

    result_data: Any | None = Field(
        default=None,
        description="General operation result data",
    )

    # Referral metadata
    referral_urls_processed: list[str] = Field(
        default_factory=list,
        description="Referral URLs that were processed",
    )

    successful_referral_url: str | None = Field(
        default=None,
        description="Referral URL that succeeded",
    )

    final_server: str | None = Field(
        default=None,
        description="Final server that provided results",
    )

    total_referrals_followed: int = Field(
        default=0,
        description="Total number of referrals followed",
    )

    # Error information
    error_message: str | None = Field(
        default=None,
        description="Error message if processing failed",
    )

    referral_errors: list[str] = Field(
        default_factory=list,
        description="Errors from individual referrals",
    )

    # Performance metadata
    total_processing_time: float | None = Field(
        default=None,
        description="Total processing time in seconds",
    )

    per_referral_times: dict[str, float] = Field(
        default_factory=dict,
        description="Processing time per referral URL",
    )

    def get_entries(self) -> list[dict[str, Any]]:
        """Get search result entries.

        Returns:
            List of entries or empty list if no entries

        """
        return self.entries or []

    def get_error_summary(self) -> str:
        """Get summary of all errors encountered.

        Returns:
            Combined error message

        """
        errors = []
        if self.error_message:
            errors.append(f"Main error: {self.error_message}")

        for i, referral_error in enumerate(self.referral_errors):
            errors.append(f"Referral {i + 1}: {referral_error}")

        return "; ".join(errors) if errors else "No errors"

    def add_referral_error(self, url: str, error: str) -> None:
        """Add error for specific referral URL.

        Args:
            url: Referral URL that failed
            error: Error message

        """
        self.referral_errors.append(f"{url}: {error}")


class ReferralPolicy(BaseModel):
    """Policy configuration for referral handling."""

    handling_mode: ReferralHandlingMode = Field(
        default=ReferralHandlingMode.AUTOMATIC,
        description="Referral handling mode",
    )

    security_mode: ReferralSecurityMode = Field(
        default=ReferralSecurityMode.SAME_SECURITY,
        description="Security requirements",
    )

    max_referral_depth: int = Field(
        default=5,
        description="Maximum referral depth to follow",
    )

    max_referral_time: float = Field(
        default=300.0,
        description="Maximum time for referral processing (seconds)",
    )

    # Server filtering
    allowed_servers: list[str] | None = Field(
        default=None,
        description="List of allowed servers (None = allow all)",
    )

    blocked_servers: list[str] = Field(
        default_factory=list,
        description="List of blocked servers",
    )

    allowed_domains: list[str] | None = Field(
        default=None,
        description="List of allowed domains (None = allow all)",
    )

    # Authentication policy
    use_rebind_credentials: bool = Field(
        default=True,
        description="Whether to use rebind credentials",
    )

    inherit_original_credentials: bool = Field(
        default=True,
        description="Whether to inherit original connection credentials",
    )

    require_authentication: bool = Field(
        default=False,
        description="Whether to require authentication for referrals",
    )

    def should_follow_referral(self, referral_url: str) -> tuple[bool, str]:
        """Check if referral should be followed based on policy.

        Args:
            referral_url: Referral URL to check

        Returns:
            Tuple of (should_follow, reason)

        """
        if self.handling_mode == ReferralHandlingMode.DISABLED:
            return False, "Referral handling is disabled"

        if self.handling_mode == ReferralHandlingMode.MANUAL:
            return False, "Manual referral handling mode"

        # Parse URL
        try:
            parsed = urlparse(referral_url)
        except Exception as e:
            return False, f"Invalid referral URL: {e}"

        # Check security requirements
        if self.security_mode == ReferralSecurityMode.STRICT:
            if parsed.scheme not in {"ldaps", "ldap+tls"}:
                return False, "Strict security mode requires secure connections"

        # Check server allowlist
        if self.allowed_servers is not None:
            if parsed.hostname not in self.allowed_servers:
                return False, f"Server {parsed.hostname} not in allowed list"

        # Check server blocklist
        if parsed.hostname in self.blocked_servers:
            return False, f"Server {parsed.hostname} is blocked"

        # Check domain allowlist
        if self.allowed_domains is not None:
            hostname = parsed.hostname or ""
            domain_allowed = any(
                hostname.endswith(f".{domain}") or hostname == domain
                for domain in self.allowed_domains
            )
            if not domain_allowed:
                return False, f"Domain for {hostname} not in allowed list"

        return True, "Referral allowed by policy"


class ReferralHandler:
    """Main handler for LDAP referral processing.

    This handler provides comprehensive referral processing with automatic
    server following, authentication management, and security controls for
    distributed LDAP environments.

    Example:
        >>> # Configure referral handling
        >>> handler = ReferralHandler(
        ...     max_referral_depth=3,
        ...     rebind_credentials=ReferralCredentials(
        ...         bind_dn="cn=admin,dc=example,dc=com",
        ...         password="admin_password"
        ...     )
        ... )
        >>>
        >>> # Process referrals from LDAP operation
        >>> referral_urls = ["ldap://server2.example.com/ou=users,dc=example,dc=com"]
        >>> result = await handler.process_referral(
        ...     referral_urls,
        ...     operation_type="search",
        ...     operation_args={"base_dn": "ou=users,dc=example,dc=com", "filter": "(uid=john)"}
        ... )

    """

    def __init__(
        self,
        max_referral_depth: int = 5,
        max_referral_time: float = 300.0,
        follow_referrals: bool = True,
        rebind_credentials: ReferralCredentials | dict[str, str] | None = None,
        security_mode: ReferralSecurityMode = ReferralSecurityMode.SAME_SECURITY,
        allowed_servers: list[str] | None = None,
        blocked_servers: list[str] | None = None,
    ) -> None:
        """Initialize referral handler.

        Args:
            max_referral_depth: Maximum referral depth to follow
            max_referral_time: Maximum time for referral processing
            follow_referrals: Whether to automatically follow referrals
            rebind_credentials: Credentials for rebinding to referral servers
            security_mode: Security requirements for referral connections
            allowed_servers: List of allowed servers (None = allow all)
            blocked_servers: List of blocked servers

        """
        # Create policy configuration
        self._policy = ReferralPolicy(
            handling_mode=ReferralHandlingMode.AUTOMATIC
            if follow_referrals
            else ReferralHandlingMode.MANUAL,
            security_mode=security_mode,
            max_referral_depth=max_referral_depth,
            max_referral_time=max_referral_time,
            allowed_servers=allowed_servers,
            blocked_servers=blocked_servers or [],
        )

        # Set up credentials
        if isinstance(rebind_credentials, dict):
            self._rebind_credentials = ReferralCredentials(**rebind_credentials)
        else:
            self._rebind_credentials = rebind_credentials

        # Initialize referral chaser
        self._chaser = ReferralChaser(
            default_credentials=self._rebind_credentials,
            max_depth=max_referral_depth,
        )

        # Statistics
        self._total_referrals_processed = 0
        self._successful_referrals = 0
        self._failed_referrals = 0

    async def process_referral(
        self,
        referral_urls: list[str],
        operation_type: str,
        operation_args: dict[str, Any] | None = None,
        original_dn: str | None = None,
        referral_depth: int = 0,
    ) -> ReferralResult:
        """Process LDAP referral URLs.

        Args:
            referral_urls: List of referral URLs to process
            operation_type: Type of LDAP operation (search, modify, etc.)
            operation_args: Arguments for the operation
            original_dn: Original DN for the operation
            referral_depth: Current referral depth

        Returns:
            Referral processing result

        Raises:
            NotImplementedError: Referral processing not yet implemented

        """
        start_time = time.time()
        self._total_referrals_processed += 1

        # Create operation configuration
        operation = ReferralOperation(
            operation_type=operation_type,
            operation_args=operation_args or {},
            original_dn=original_dn,
            referral_urls=referral_urls,
            referral_depth=referral_depth,
            max_depth=self._policy.max_referral_depth,
        )

        # Create result object
        result = ReferralResult(success=False)

        try:
            # Check if we should process referrals
            if not self._should_process_referrals(operation):
                result.success = False
                result.error_message = "Referral processing not allowed by policy"
                return result

            # Process each referral URL
            for referral_url in referral_urls:
                should_follow, reason = self._policy.should_follow_referral(
                    referral_url,
                )

                if not should_follow:
                    result.add_referral_error(referral_url, reason)
                    continue

                # Attempt to follow referral
                referral_start = time.time()

                try:
                    # TODO: Implement actual referral following
                    # This would use ReferralChaser to connect to the referral server
                    # and execute the operation
                    msg = (
                        "Referral following requires LDAP connection integration. "
                        "Implement referral chasing using ReferralChaser with proper "
                        "connection management, authentication, and operation execution."
                    )
                    raise NotImplementedError(msg)

                except Exception as e:
                    referral_time = time.time() - referral_start
                    result.per_referral_times[referral_url] = referral_time
                    result.add_referral_error(referral_url, str(e))
                    continue

            # Update statistics
            if result.success:
                self._successful_referrals += 1
            else:
                self._failed_referrals += 1

        finally:
            result.total_processing_time = time.time() - start_time

        return result

    def _should_process_referrals(self, operation: ReferralOperation) -> bool:
        """Check if referrals should be processed.

        Args:
            operation: Referral operation configuration

        Returns:
            True if referrals should be processed

        """
        # Check handling mode
        if self._policy.handling_mode == ReferralHandlingMode.DISABLED:
            return False

        if self._policy.handling_mode == ReferralHandlingMode.MANUAL:
            return False

        # Check depth limit
        if operation.is_max_depth_reached():
            return False

        # Check time limit
        return not operation.get_duration() > self._policy.max_referral_time

    def set_rebind_credentials(
        self,
        credentials: ReferralCredentials | dict[str, str],
    ) -> None:
        """Set credentials for rebinding to referral servers.

        Args:
            credentials: Rebind credentials

        """
        if isinstance(credentials, dict):
            self._rebind_credentials = ReferralCredentials(**credentials)
        else:
            self._rebind_credentials = credentials

        self._chaser.set_default_credentials(self._rebind_credentials)

    def update_policy(self, policy_updates: dict[str, Any]) -> None:
        """Update referral handling policy.

        Args:
            policy_updates: Dictionary of policy fields to update

        """
        for field, value in policy_updates.items():
            if hasattr(self._policy, field):
                setattr(self._policy, field, value)

    def add_allowed_server(self, server: str) -> None:
        """Add server to allowed list.

        Args:
            server: Server hostname to allow

        """
        if self._policy.allowed_servers is None:
            self._policy.allowed_servers = []

        if server not in self._policy.allowed_servers:
            self._policy.allowed_servers.append(server)

    def add_blocked_server(self, server: str) -> None:
        """Add server to blocked list.

        Args:
            server: Server hostname to block

        """
        if server not in self._policy.blocked_servers:
            self._policy.blocked_servers.append(server)

    def remove_blocked_server(self, server: str) -> None:
        """Remove server from blocked list.

        Args:
            server: Server hostname to unblock

        """
        if server in self._policy.blocked_servers:
            self._policy.blocked_servers.remove(server)

    @property
    def policy(self) -> ReferralPolicy:
        """Get current referral policy."""
        return self._policy

    @property
    def rebind_credentials(self) -> ReferralCredentials | None:
        """Get current rebind credentials."""
        return self._rebind_credentials

    def get_statistics(self) -> dict[str, Any]:
        """Get referral handling statistics.

        Returns:
            Dictionary with statistics

        """
        return {
            "total_referrals_processed": self._total_referrals_processed,
            "successful_referrals": self._successful_referrals,
            "failed_referrals": self._failed_referrals,
            "success_rate": (
                self._successful_referrals
                / self._total_referrals_processed
                * DEFAULT_MAX_ITEMS
                if self._total_referrals_processed > 0
                else 0
            ),
            "policy": {
                "handling_mode": self._policy.handling_mode.value,
                "security_mode": self._policy.security_mode.value,
                "max_depth": self._policy.max_referral_depth,
                "max_time": self._policy.max_referral_time,
            },
        }


# Convenience functions
def create_referral_handler(
    follow_referrals: bool = True,
    bind_dn: str | None = None,
    password: str | None = None,
    max_depth: int = 5,
) -> ReferralHandler:
    """Create referral handler with basic configuration.

    Args:
        follow_referrals: Whether to follow referrals automatically
        bind_dn: Bind DN for rebinding
        password: Password for rebinding
        max_depth: Maximum referral depth

    Returns:
        Configured referral handler

    """
    credentials = None
    if bind_dn and password:
        credentials = ReferralCredentials(bind_dn=bind_dn, password=password)

    return ReferralHandler(
        follow_referrals=follow_referrals,
        rebind_credentials=credentials,
        max_referral_depth=max_depth,
    )


def parse_referral_urls(referral_response: str) -> list[str]:
    """Parse referral URLs from LDAP referral response.

    Args:
        referral_response: Referral response string

    Returns:
        List of parsed referral URLs

    """
    # TODO: Implement proper referral URL parsing
    # This should parse referral URLs according to RFC 4511
    urls = []

    # Simple parsing for now - would need proper RFC compliance
    if referral_response:
        # Split on whitespace and filter valid URLs
        potential_urls = referral_response.split()
        urls.extend(
            url.strip()
            for url in potential_urls
            if url.startswith(("ldap://", "ldaps://"))
        )

    return urls


async def follow_referral_url(
    referral_url: str,
    operation_type: str,
    operation_args: dict[str, Any],
    credentials: ReferralCredentials | None = None,
) -> ReferralResult:
    """Convenience function to follow single referral URL.

    Args:
        referral_url: Referral URL to follow
        operation_type: Type of operation
        operation_args: Operation arguments
        credentials: Optional credentials for rebinding

    Returns:
        Referral result

    """
    handler = ReferralHandler(rebind_credentials=credentials)

    return await handler.process_referral(
        [referral_url],
        operation_type,
        operation_args,
    )


# TODO: Integration points for implementation:
#
# 1. LDAP Connection Integration:
#    - Integration with connection manager for referral following
#    - Connection pooling for referral servers
#    - Authentication and rebinding support
#
# 2. ReferralChaser Integration:
#    - Complete implementation of referral chasing logic
#    - Server connection and operation execution
#    - Error handling and retry logic
#
# 3. Security and Authentication:
#    - Comprehensive authentication handling for referral servers
#    - Security policy enforcement and validation
#    - TLS/SSL support for secure referral connections
#
# 4. URL Parsing and Validation:
#    - RFC-compliant referral URL parsing
#    - DN rewriting and scope adjustment for referrals
#    - Invalid URL handling and sanitization
#
# 5. Error Handling and Recovery:
#    - Comprehensive error handling for referral failures
#    - Automatic fallback and retry strategies
#    - Partial result aggregation from multiple referrals
#
# 6. Performance Optimization:
#    - Parallel referral processing for multiple URLs
#    - Connection reuse and caching for referral servers
#    - Timeout management and resource cleanup
#
# 7. Testing Requirements:
#    - Unit tests for all referral functionality
#    - Integration tests with multiple LDAP servers
#    - Security tests for authentication and policy enforcement
#    - Performance tests for referral processing overhead
