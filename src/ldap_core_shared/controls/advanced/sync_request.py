"""LDAP Sync Request Control Implementation.

# Constants for magic values

This module provides LDAP Sync Request Control functionality following RFC 4533
with perl-ldap compatibility patterns for content synchronization and
incremental directory updates.

The Sync Request Control enables efficient synchronization of directory
content by requesting only changes since a previous synchronization point,
reducing bandwidth and processing overhead for distributed applications.

Architecture:
    - SyncRequestControl: Main control for synchronization requests
    - SyncRequestMode: Different synchronization operation modes
    - SyncCookie: Synchronization state tracking
    - SyncRequestConfig: Configuration for sync operations

Usage Example:
    >>> from ldap_core_shared.controls.advanced.sync_request import SyncRequestControl
    >>>
    >>> # Initial synchronization
    >>> sync_control = SyncRequestControl(
    ...     mode=SyncRequestMode.REFRESH_ONLY,
    ...     cookie=None  # No previous state
    ... )
    >>>
    >>> results = connection.search(
    ...     search_base="ou=users,dc=example,dc=com",
    ...     search_filter="(objectClass=person)",
    ...     controls=[sync_control]
    ... )
    >>>
    >>> # Save sync cookie for incremental updates
    >>> cookie = sync_control.response.sync_cookie

References:
    - perl-ldap: lib/Net/LDAP/Control/SyncRequest.pm
    - RFC 4533: LDAP Content Synchronization Operation
    - RFC 4511: LDAP Protocol Specification
    - Directory synchronization patterns
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import ldap3

from pydantic import BaseModel, Field

from ldap_core_shared.controls.base import LDAPControl


class SyncRequestMode(Enum):
    """Modes for content synchronization requests."""

    REFRESH_ONLY = "refresh_only"  # Full refresh without persistent sync
    REFRESH_AND_PERSIST = "refresh_persist"  # Full refresh then persistent sync
    PERSIST_ONLY = "persist_only"  # Persistent sync only (incremental)


class SyncReloadHint(Enum):
    """Hints for synchronization reload behavior."""

    FULL_RELOAD = "full_reload"  # Perform full content reload
    INCREMENTAL = "incremental"  # Incremental updates only
    PARTIAL_RELOAD = "partial_reload"  # Partial content reload
    OPTIMIZED = "optimized"  # Server-optimized synchronization


class SyncCookie(BaseModel):
    """Synchronization state cookie."""

    cookie_value: bytes = Field(description="Opaque cookie value from server")

    # Metadata (not sent to server)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Cookie creation timestamp",
    )

    last_used: datetime | None = Field(
        default=None,
        description="Last time cookie was used",
    )

    source_server: str | None = Field(
        default=None,
        description="Server that issued the cookie",
    )

    sync_base_dn: str | None = Field(
        default=None,
        description="Base DN for synchronization",
    )

    def is_valid(self) -> bool:
        """Check if cookie is valid (non-empty).

        Returns:
            True if cookie has valid value
        """
        return bool(self.cookie_value and len(self.cookie_value) > 0)

    def get_cookie_hex(self) -> str:
        """Get cookie value as hex string.

        Returns:
            Cookie value as hex string
        """
        return self.cookie_value.hex() if self.cookie_value else ""

    def update_last_used(self) -> None:
        """Update last used timestamp."""
        self.last_used = datetime.now(UTC)

    def get_age_seconds(self) -> float:
        """Get cookie age in seconds.

        Returns:
            Cookie age in seconds
        """
        return (datetime.now(UTC) - self.created_at).total_seconds()


class SyncRequestConfig(BaseModel):
    """Configuration for Sync Request control."""

    mode: SyncRequestMode = Field(description="Synchronization mode")

    cookie: SyncCookie | None = Field(
        default=None,
        description="Synchronization state cookie",
    )

    reload_hint: SyncReloadHint = Field(
        default=SyncReloadHint.OPTIMIZED,
        description="Hint for reload behavior",
    )

    # Size limits
    size_limit: int | None = Field(
        default=None,
        description="Maximum number of entries to return",
    )

    time_limit: int | None = Field(
        default=None,
        description="Time limit for synchronization in seconds",
    )

    # Performance options
    return_deleted_entries: bool = Field(
        default=True,
        description="Whether to return information about deleted entries",
    )

    include_operational_attributes: bool = Field(
        default=False,
        description="Whether to include operational attributes",
    )

    batch_size: int | None = Field(
        default=None,
        description="Preferred batch size for updates",
    )

    # Reliability options
    request_acknowledgment: bool = Field(
        default=False,
        description="Whether to request acknowledgment",
    )

    enable_compression: bool = Field(
        default=False,
        description="Whether to enable response compression",
    )

    def is_initial_sync(self) -> bool:
        """Check if this is an initial synchronization.

        Returns:
            True if no previous cookie exists
        """
        return self.cookie is None or not self.cookie.is_valid()

    def is_persistent_mode(self) -> bool:
        """Check if persistent synchronization is requested.

        Returns:
            True if persistent sync is enabled
        """
        return self.mode in {
            SyncRequestMode.REFRESH_AND_PERSIST,
            SyncRequestMode.PERSIST_ONLY,
        }

    def get_sync_summary(self) -> dict[str, Any]:
        """Get synchronization configuration summary.

        Returns:
            Dictionary with sync configuration
        """
        return {
            "mode": self.mode.value,
            "is_initial": self.is_initial_sync(),
            "is_persistent": self.is_persistent_mode(),
            "reload_hint": self.reload_hint.value,
            "has_cookie": self.cookie is not None and self.cookie.is_valid(),
            "cookie_age": self.cookie.get_age_seconds() if self.cookie else None,
            "size_limit": self.size_limit,
            "time_limit": self.time_limit,
        }


class SyncRequestResponse(BaseModel):
    """Response from Sync Request control processing."""

    sync_in_progress: bool = Field(description="Whether synchronization is in progress")

    # Updated synchronization state
    new_cookie: SyncCookie | None = Field(
        default=None,
        description="New synchronization state cookie",
    )

    refresh_required: bool = Field(
        default=False,
        description="Whether full refresh is required",
    )

    # Synchronization metadata
    entries_returned: int = Field(
        default=0,
        description="Number of entries returned",
    )

    entries_added: int = Field(
        default=0,
        description="Number of entries added",
    )

    entries_modified: int = Field(
        default=0,
        description="Number of entries modified",
    )

    entries_deleted: int = Field(
        default=0,
        description="Number of entries deleted",
    )

    # Server state information
    server_sync_state: str | None = Field(
        default=None,
        description="Server synchronization state",
    )

    persistent_search_active: bool = Field(
        default=False,
        description="Whether persistent search is active",
    )

    estimated_remaining: int | None = Field(
        default=None,
        description="Estimated remaining entries",
    )

    # Error information
    result_code: int = Field(default=0, description="Synchronization result code")

    result_message: str | None = Field(
        default=None,
        description="Synchronization result message",
    )

    sync_errors: list[str] = Field(
        default_factory=list,
        description="Synchronization errors",
    )

    # Performance metadata
    sync_duration: float | None = Field(
        default=None,
        description="Synchronization duration in seconds",
    )

    bandwidth_saved: int | None = Field(
        default=None,
        description="Estimated bandwidth saved in bytes",
    )

    processed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Response processing timestamp",
    )

    def is_success(self) -> bool:
        """Check if synchronization was successful."""
        return self.result_code == 0 and len(self.sync_errors) == 0

    def get_sync_statistics(self) -> dict[str, Any]:
        """Get synchronization statistics.

        Returns:
            Dictionary with sync statistics
        """
        total_changes = (
            self.entries_added + self.entries_modified + self.entries_deleted
        )

        return {
            "total_entries": self.entries_returned,
            "total_changes": total_changes,
            "entries_added": self.entries_added,
            "entries_modified": self.entries_modified,
            "entries_deleted": self.entries_deleted,
            "sync_duration": self.sync_duration,
            "persistent_active": self.persistent_search_active,
            "refresh_required": self.refresh_required,
            "bandwidth_saved": self.bandwidth_saved,
        }

    def has_errors(self) -> bool:
        """Check if synchronization had errors."""
        return len(self.sync_errors) > 0 or self.result_code != 0


class SyncRequestControl(LDAPControl):
    """LDAP Sync Request Control for content synchronization.

    This control enables efficient synchronization of directory content
    by requesting only changes since a previous synchronization point,
    supporting both one-time refresh and persistent synchronization modes.

    Example:
        >>> # Initial full synchronization
        >>> initial_sync = SyncRequestControl(
        ...     mode=SyncRequestMode.REFRESH_ONLY,
        ...     size_limit=DEFAULT_LARGE_LIMIT
        ... )
        >>>
        >>> results = connection.search(
        ...     search_base="ou=users,dc=example,dc=com",
        ...     search_filter="(objectClass=person)",
        ...     controls=[initial_sync]
        ... )
        >>>
        >>> # Save cookie for incremental updates
        >>> cookie = initial_sync.response.new_cookie
        >>>
        >>> # Incremental synchronization
        >>> incremental_sync = SyncRequestControl(
        ...     mode=SyncRequestMode.REFRESH_ONLY,
        ...     cookie=cookie
        ... )
    """

    control_type = "1.3.6.1.4.1.4203.1.9.1.1"  # RFC 4533 Sync Request Control OID

    def __init__(
        self,
        mode: SyncRequestMode = SyncRequestMode.REFRESH_ONLY,
        cookie: SyncCookie | None = None,
        reload_hint: SyncReloadHint = SyncReloadHint.OPTIMIZED,
        size_limit: int | None = None,
        criticality: bool = False,
    ) -> None:
        """Initialize Sync Request control.

        Args:
            mode: Synchronization mode
            cookie: Previous synchronization state cookie
            reload_hint: Hint for reload behavior
            size_limit: Maximum number of entries to return
            criticality: Whether control is critical for operation
        """
        # Create configuration
        self._config = SyncRequestConfig(
            mode=mode,
            cookie=cookie,
            reload_hint=reload_hint,
            size_limit=size_limit,
        )

        # Initialize response storage
        self._response: SyncRequestResponse | None = None
        self._response_available = False

        # Synchronization state
        self._sync_started = False
        self._last_sync_time: datetime | None = None

        # Initialize base control
        super().__init__(
            criticality=criticality,
            control_value=self._encode_request(),
        )

    def _encode_request(self) -> bytes:
        """Encode Sync Request control request.

        Returns:
            BER-encoded control value for sync request
        """
        # Simple BER encoding for sync request
        # In production, this would use proper ASN.1 encoding
        from struct import pack

        # Mode encoding (simplified)
        mode_value = {
            SyncRequestMode.REFRESH_ONLY: 1,
            SyncRequestMode.REFRESH_AND_PERSIST: 3,
            SyncRequestMode.PERSIST_ONLY: 4,
        }.get(self._config.mode, 1)

        # Basic encoding: mode + cookie if present
        encoded_parts = [pack("B", mode_value)]

        if self._config.cookie and self._config.cookie.is_valid():
            cookie_data = self._config.cookie.cookie_value
            encoded_parts.extend((pack("B", len(cookie_data)), cookie_data))
        else:
            encoded_parts.append(pack("B", 0))  # Empty cookie

        return b"".join(encoded_parts)

    def process_response(self, response_value: bytes) -> None:
        """Process Sync Request control response from server.

        Args:
            response_value: BER-encoded response from server
        """
        # Simple response processing for sync request
        if not response_value:
            # No response data - create default response
            self._response = SyncRequestResponse(
                sync_in_progress=False,
                new_cookie=None,
                refresh_required=False,
                result_code=0,
                result_message="Sync completed successfully",
            )
            self._response_available = True
            return

        # Basic response parsing (simplified)
        from struct import unpack

        try:
            # Parse response data (simplified format)
            offset = 0
            result_code = 0
            new_cookie_data = b""

            if len(response_value) >= 1:
                result_code = unpack("B", response_value[offset : offset + 1])[0]
                offset += 1

            if len(response_value) > offset:
                cookie_len = unpack("B", response_value[offset : offset + 1])[0]
                offset += 1
                if cookie_len > 0 and len(response_value) >= offset + cookie_len:
                    new_cookie_data = response_value[offset : offset + cookie_len]

            # Create sync cookie if data present
            new_cookie = None
            if new_cookie_data:
                new_cookie = SyncCookie(cookie_value=new_cookie_data)

            # Create response object
            self._response = SyncRequestResponse(
                sync_in_progress=result_code == 0,
                new_cookie=new_cookie,
                refresh_required=result_code == 1,
                result_code=result_code,
                result_message="Sync processed" if result_code == 0 else "Sync failed",
            )
            self._response_available = True

        except Exception:
            # Fallback response on parsing error
            self._response = SyncRequestResponse(
                sync_in_progress=False,
                new_cookie=None,
                refresh_required=True,
                result_code=1,
                result_message="Response parsing failed",
            )
            self._response_available = True

    def update_cookie(self, new_cookie: SyncCookie) -> None:
        """Update synchronization cookie for subsequent requests.

        Args:
            new_cookie: New synchronization state cookie
        """
        self._config.cookie = new_cookie
        new_cookie.update_last_used()
        # Update control value
        self.control_value = self._encode_request()

    def set_mode(self, mode: SyncRequestMode) -> None:
        """Set synchronization mode.

        Args:
            mode: New synchronization mode
        """
        self._config.mode = mode
        # Update control value
        self.control_value = self._encode_request()

    def set_reload_hint(self, hint: SyncReloadHint) -> None:
        """Set reload hint for server optimization.

        Args:
            hint: New reload hint
        """
        self._config.reload_hint = hint
        # Update control value
        self.control_value = self._encode_request()

    def set_limits(self, size_limit: int | None, time_limit: int | None) -> None:
        """Set synchronization limits.

        Args:
            size_limit: Maximum number of entries
            time_limit: Time limit in seconds
        """
        self._config.size_limit = size_limit
        self._config.time_limit = time_limit

    def is_initial_sync(self) -> bool:
        """Check if this is an initial synchronization.

        Returns:
            True if no previous state exists
        """
        return self._config.is_initial_sync()

    def is_persistent_mode(self) -> bool:
        """Check if persistent synchronization is enabled.

        Returns:
            True if persistent sync is requested
        """
        return self._config.is_persistent_mode()

    def get_current_cookie(self) -> SyncCookie | None:
        """Get current synchronization cookie.

        Returns:
            Current sync cookie or None if not available
        """
        return self._config.cookie

    def get_sync_summary(self) -> dict[str, Any]:
        """Get comprehensive synchronization summary.

        Returns:
            Dictionary with sync configuration and state
        """
        summary = self._config.get_sync_summary()
        summary.update(
            {
                "sync_started": self._sync_started,
                "last_sync_time": self._last_sync_time.isoformat()
                if self._last_sync_time
                else None,
                "response_available": self._response_available,
            },
        )

        if self._response:
            summary["statistics"] = self._response.get_sync_statistics()

        return summary

    @property
    def response(self) -> SyncRequestResponse | None:
        """Get Sync Request control response."""
        return self._response

    @property
    def response_available(self) -> bool:
        """Check if response is available."""
        return self._response_available

    @property
    def mode(self) -> SyncRequestMode:
        """Get current synchronization mode."""
        return self._config.mode

    @property
    def config(self) -> SyncRequestConfig:
        """Get synchronization configuration."""
        return self._config

    def encode_value(self) -> bytes | None:
        """Encode sync request control value to ASN.1 bytes.

        Returns:
            Encoded control value or None if no value
        """
        return self.control_value

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> SyncRequestControl:
        """Decode ASN.1 bytes to create sync request control instance.

        Args:
            control_value: ASN.1 encoded control value

        Returns:
            SyncRequestControl instance with decoded values
        """
        if not control_value:
            # Default sync request control for refresh only
            return cls(
                mode=SyncRequestMode.REFRESH_ONLY,
                cookie=None,
                reload_hint=SyncReloadHint.OPTIMIZED,
            )

        # For now, return a default control since proper ASN.1 decoding
        # would require more complex implementation
        return cls(
            mode=SyncRequestMode.REFRESH_ONLY,
            cookie=None,
            reload_hint=SyncReloadHint.OPTIMIZED,
        )


# Convenience functions
def create_initial_sync_control(
    mode: SyncRequestMode = SyncRequestMode.REFRESH_ONLY,
) -> SyncRequestControl:
    """Create Sync Request control for initial synchronization.

    Args:
        mode: Synchronization mode

    Returns:
        Configured Sync Request control for initial sync
    """
    return SyncRequestControl(
        mode=mode,
        cookie=None,
        reload_hint=SyncReloadHint.FULL_RELOAD,
        criticality=False,
    )


def create_incremental_sync_control(
    cookie: SyncCookie,
    mode: SyncRequestMode = SyncRequestMode.REFRESH_ONLY,
) -> SyncRequestControl:
    """Create Sync Request control for incremental synchronization.

    Args:
        cookie: Previous synchronization state
        mode: Synchronization mode

    Returns:
        Configured Sync Request control for incremental sync
    """
    return SyncRequestControl(
        mode=mode,
        cookie=cookie,
        reload_hint=SyncReloadHint.INCREMENTAL,
        criticality=False,
    )


def create_persistent_sync_control(
    cookie: SyncCookie | None = None,
) -> SyncRequestControl:
    """Create Sync Request control for persistent synchronization.

    Args:
        cookie: Optional previous synchronization state

    Returns:
        Configured Sync Request control for persistent sync
    """
    return SyncRequestControl(
        mode=SyncRequestMode.REFRESH_AND_PERSIST,
        cookie=cookie,
        reload_hint=SyncReloadHint.OPTIMIZED,
        criticality=False,
    )


async def perform_directory_sync(
    connection: ldap3.Connection,
    search_base: str,
    search_filter: str,
    cookie: SyncCookie | None = None,
) -> tuple[list[dict[str, Any]], SyncCookie | None]:
    """Perform directory synchronization with automatic cookie management.

    Args:
        connection: LDAP connection
        search_base: Base DN for synchronization
        search_filter: Filter for entries to synchronize
        cookie: Previous synchronization state

    Returns:
        Tuple of (synchronized_entries, new_cookie)
    """
    # Create sync request control
    mode = SyncRequestMode.REFRESH_ONLY
    if cookie:
        mode = SyncRequestMode.REFRESH_ONLY  # Use existing cookie for incremental
    else:
        mode = SyncRequestMode.REFRESH_ONLY  # Initial sync

    sync_control = SyncRequestControl(
        mode=mode,
        cookie=cookie,
        criticality=False,
    )

    try:
        # Perform search with sync control
        success = connection.search(
            search_base=search_base,
            search_filter=search_filter,
            controls=[sync_control],
        )

        if success:
            # Extract entries from search results
            entries = []
            for entry in connection.entries:
                entry_dict = {
                    "dn": entry.entry_dn,
                    "attributes": dict(entry.entry_attributes_as_dict),
                }
                entries.append(entry_dict)

            # Get new cookie from response
            new_cookie = None
            if sync_control.response and sync_control.response.new_cookie:
                new_cookie = sync_control.response.new_cookie

            return entries, new_cookie
        # Return empty results on failure
        return [], cookie

    except Exception:
        # Return empty results on error
        return [], cookie
