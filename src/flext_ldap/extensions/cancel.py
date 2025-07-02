"""LDAP Cancel Extended Operation Implementation.

This module implements the Cancel extended operation as defined in RFC 3909.
This extension allows clients to request cancellation of other outstanding
operations on the same LDAP connection.

The Cancel operation is critical for responsive LDAP applications, enabling
clients to abort long-running operations like searches or modifications when
they are no longer needed or when timeouts occur.

Architecture:
    - CancelExtension: Request extension for operation cancellation
    - CancelResult: Response containing cancellation status
    - CancelRequest: Structured cancellation parameters
    - OperationTracker: Utility for tracking cancellable operations

Usage Example:
    >>> from flext_ldap.extensions.cancel import CancelExtension
    >>>
    >>> # Cancel operation by message ID
    >>> cancel_op = CancelExtension(message_id=123)
    >>> result = connection.extended_operation(cancel_op)
    >>>
    >>> if result.is_success():
    ...     if result.operation_cancelled:
    ...         print("Operation cancelled successfully")
    ...     else:
    ...         print("Operation was not cancelled (may have completed)")
    ... else:
    ...     print(f"Cancel failed: {result.get_error_description()}")
    >>>
    >>> # Cancel with timeout handling
    >>> cancel_op = CancelExtension.for_operation(message_id=456, timeout_seconds=5)
    >>> result = connection.extended_operation(cancel_op)

References:
    - perl-ldap: lib/Net/LDAP/Extension/Cancel.pm
    - RFC 3909: Lightweight Directory Access Protocol (LDAP) Cancel Operation
    - OID: 1.3.6.1.1.8
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldapants import LDAP_MESSAGE_ID_MAX
from flext_ldapbase import (
    ExtensionDecodingError,
    ExtensionEncodingError,
    ExtensionOIDs,
    ExtensionResult,
    LDAPExtension,
)
from pydantic import Field, validator

if TYPE_CHECKING:
    from flext_ldapes import OID


class CancelError(Exception):
    """Exception raised for cancel operation errors."""


class CancelResult(ExtensionResult):
    """Result of Cancel extension operation.

    Contains the result of the cancellation request, including whether
    the target operation was actually cancelled or had already completed.

    Attributes:
        operation_cancelled: Whether the target operation was cancelled
        operation_completed: Whether the operation completed before cancellation
        target_message_id: Message ID of the operation that was targeted
        cancellation_reason: Reason for cancellation result

    Note:
        A successful cancel result doesn't guarantee the operation was cancelled.
        The operation may have completed normally before the cancel took effect.
    """

    operation_cancelled: bool = Field(
        default=False,
        description="Whether the target operation was cancelled",
    )

    operation_completed: bool = Field(
        default=False,
        description="Whether operation completed before cancellation",
    )

    target_message_id: int | None = Field(
        default=None,
        description="Message ID of the operation that was targeted",
    )

    cancellation_reason: str | None = Field(
        default=None,
        description="Reason for cancellation result",
    )

    def was_effective(self) -> bool:
        """Check if cancellation was effective (operation was actually cancelled)."""
        return self.operation_cancelled and not self.operation_completed

    def was_too_late(self) -> bool:
        """Check if cancellation was too late (operation already completed)."""
        return not self.operation_cancelled and self.operation_completed

    def get_cancellation_summary(self) -> str:
        """Get summary of cancellation result."""
        if self.is_failure():
            return f"Cancel failed: {self.get_error_description()}"

        if self.was_effective():
            return "Operation cancelled successfully"

        if self.was_too_late():
            return "Operation completed before cancellation"

        return "Cancellation processed (status unclear)"

    def __str__(self) -> str:
        """String representation of the result."""
        if self.is_failure():
            return f"Cancel failed: {self.get_error_description()}"

        if self.was_effective():
            return f"Cancel successful (msg {self.target_message_id})"

        if self.was_too_late():
            return f"Cancel too late (msg {self.target_message_id} completed)"

        return f"Cancel processed (msg {self.target_message_id})"


class CancelExtension(LDAPExtension):
    """Cancel Extended Operation (RFC 3909).

    This extension requests cancellation of another operation that is
    outstanding on the same LDAP connection. The operation to cancel
    is identified by its message ID.

    The Cancel operation provides a mechanism for clients to abort
    long-running operations when they are no longer needed, improving
    application responsiveness and resource utilization.

    Attributes:
        message_id: Message ID of the operation to cancel
        timeout_seconds: Optional timeout for the cancel operation itself

    Note:
        The message ID must correspond to an outstanding operation on
        the same connection. The server may or may not be able to
        cancel the operation depending on its current state.
    """

    request_name = ExtensionOIDs.CANCEL

    message_id: int = Field(description="Message ID of the operation to cancel")

    timeout_seconds: int | None = Field(
        default=None,
        description="Timeout for the cancel operation itself",
    )

    @validator("message_id")
    def validate_message_id(self, v: int) -> int:
        """Validate message ID."""
        if v < 1:
            msg = "Message ID must be positive"
            raise CancelError(msg)

        if v > LDAP_MESSAGE_ID_MAX:  # 2^31 - 1
            msg = "Message ID too large"
            raise CancelError(msg)

        return v

    @validator("timeout_seconds")
    def validate_timeout(self, v: int | None) -> int | None:
        """Validate timeout value."""
        if v is not None and v < 1:
            msg = "Timeout must be positive"
            raise CancelError(msg)

        return v

    def encode_request_value(self) -> bytes:
        """Encode cancel request value as ASN.1.

        The request value is just the message ID as an INTEGER:
        cancelID MessageID

        Returns:
            ASN.1 BER encoded request value

        Raises:
            ExtensionEncodingError: If encoding fails
        """
        try:
            # Encode message ID as INTEGER
            return self._encode_integer(self.message_id)

        except Exception as e:
            msg = f"Failed to encode cancel request: {e}"
            raise ExtensionEncodingError(msg) from e

    @classmethod
    def decode_response_value(
        cls,
        response_name: OID | None,
        response_value: bytes | None,
    ) -> CancelResult:
        """Decode cancel response value.

        Args:
            response_name: Should be None for cancel (no response name)
            response_value: Should be None for cancel (no response value)

        Returns:
            CancelResult with operation status

        Raises:
            ExtensionDecodingError: If decoding fails
        """
        try:
            # Cancel response has no value - result is in the result code
            # We'll assume success if we get here (result code handled by caller)
            return CancelResult(
                result_code=0,  # Will be overridden by caller
                operation_cancelled=True,  # Assume cancelled if successful
            )

        except Exception as e:
            msg = f"Failed to decode cancel response: {e}"
            raise ExtensionDecodingError(msg) from e

    @classmethod
    def for_operation(
        cls,
        message_id: int,
        timeout_seconds: int | None = None,
    ) -> CancelExtension:
        """Create cancel extension for specific operation.

        Args:
            message_id: Message ID of operation to cancel
            timeout_seconds: Optional timeout for cancel operation

        Returns:
            CancelExtension configured for the target operation
        """
        return cls(message_id=message_id, timeout_seconds=timeout_seconds)

    @classmethod
    def immediate(cls, message_id: int) -> CancelExtension:
        """Create cancel extension with no timeout.

        Args:
            message_id: Message ID of operation to cancel

        Returns:
            CancelExtension for immediate cancellation
        """
        return cls(message_id=message_id, timeout_seconds=None)

    @classmethod
    def with_timeout(cls, message_id: int, timeout_seconds: int) -> CancelExtension:
        """Create cancel extension with timeout.

        Args:
            message_id: Message ID of operation to cancel
            timeout_seconds: Timeout for cancel operation

        Returns:
            CancelExtension with timeout configured
        """
        return cls(message_id=message_id, timeout_seconds=timeout_seconds)

    def get_target_message_id(self) -> int:
        """Get the message ID of the target operation."""
        return self.message_id

    def has_timeout(self) -> bool:
        """Check if cancel operation has a timeout configured."""
        return self.timeout_seconds is not None

    def get_timeout_seconds(self) -> int | None:
        """Get timeout in seconds."""
        return self.timeout_seconds

    def __str__(self) -> str:
        """String representation of the extension."""
        timeout_str = f", timeout={self.timeout_seconds}s" if self.has_timeout() else ""
        return f"Cancel(msg_id={self.message_id}{timeout_str})"

    # Simple ASN.1 encoding helpers
    @staticmethod
    def _encode_integer(value: int) -> bytes:
        """Encode integer as BER INTEGER."""
        # Simple implementation for positive integers
        # Convert to minimal byte representation
        if value == 0:
            content = b"\x00"
        else:
            # Calculate number of bytes needed
            byte_length = (value.bit_length() + 7) // 8
            content = value.to_bytes(byte_length, "big")

            # Add leading zero if high bit is set (to ensure positive)
            if content[0] & 0x80:
                content = b"\x00" + content

        # Return with INTEGER tag and length
        length = len(content)
        return b"\x02" + length.to_bytes(1, "big") + content


# Convenience functions
def cancel_operation(message_id: int) -> CancelExtension:
    """Create cancel extension for operation.

    Args:
        message_id: Message ID of operation to cancel

    Returns:
        CancelExtension for the specified operation
    """
    return CancelExtension.for_operation(message_id)


def cancel_with_timeout(message_id: int, timeout_seconds: int) -> CancelExtension:
    """Create cancel extension with timeout.

    Args:
        message_id: Message ID of operation to cancel
        timeout_seconds: Timeout for cancel operation

    Returns:
        CancelExtension with timeout configured
    """
    return CancelExtension.with_timeout(message_id, timeout_seconds)


class OperationTracker:
    """Utility class for tracking cancellable operations.

    This class helps manage outstanding operations that can be cancelled,
    providing utilities for tracking message IDs and managing operation
    lifecycles.

    Example:
        >>> tracker = OperationTracker()
        >>> msg_id = tracker.start_operation("search", "dc=example,dc=com")
        >>> # ... later ...
        >>> cancel_ext = tracker.cancel_operation(msg_id)
        >>> tracker.complete_operation(msg_id)
    """

    def __init__(self) -> None:
        """Initialize operation tracker."""
        self._operations: dict[int, dict[str, Any]] = {}
        self._next_message_id = 1

    def start_operation(self, operation_type: str, operation_details: str = "") -> int:
        """Start tracking a new operation.

        Args:
            operation_type: Type of operation (search, modify, etc.)
            operation_details: Additional operation details

        Returns:
            Message ID assigned to the operation
        """
        message_id = self._next_message_id
        self._next_message_id += 1

        self._operations[message_id] = {
            "type": operation_type,
            "details": operation_details,
            "started": True,
            "completed": False,
            "cancelled": False,
        }

        return message_id

    def complete_operation(self, message_id: int) -> bool:
        """Mark operation as completed.

        Args:
            message_id: Message ID of completed operation

        Returns:
            True if operation was tracked and marked completed
        """
        if message_id in self._operations:
            self._operations[message_id]["completed"] = True
            return True
        return False

    def cancel_operation(self, message_id: int) -> CancelExtension | None:
        """Create cancel extension for tracked operation.

        Args:
            message_id: Message ID of operation to cancel

        Returns:
            CancelExtension or None if operation not tracked
        """
        if message_id not in self._operations:
            return None

        operation = self._operations[message_id]
        if operation["completed"] or operation["cancelled"]:
            return None

        operation["cancelled"] = True
        return CancelExtension.for_operation(message_id)

    def is_operation_active(self, message_id: int) -> bool:
        """Check if operation is active (started but not completed/cancelled).

        Args:
            message_id: Message ID to check

        Returns:
            True if operation is active
        """
        if message_id not in self._operations:
            return False

        operation = self._operations[message_id]
        return (
            operation["started"]
            and not operation["completed"]
            and not operation["cancelled"]
        )

    def get_active_operations(self) -> list[int]:
        """Get list of active operation message IDs.

        Returns:
            List of message IDs for active operations
        """
        return [
            msg_id
            for msg_id, op in self._operations.items()
            if self.is_operation_active(msg_id)
        ]

    def cleanup_completed(self) -> int:
        """Remove completed and cancelled operations from tracking.

        Returns:
            Number of operations removed
        """
        completed_ids = [
            msg_id
            for msg_id, op in self._operations.items()
            if op["completed"] or op["cancelled"]
        ]

        for msg_id in completed_ids:
            del self._operations[msg_id]

        return len(completed_ids)

    def get_operation_info(self, message_id: int) -> dict[str, Any] | None:
        """Get information about tracked operation.

        Args:
            message_id: Message ID to query

        Returns:
            Operation information dictionary or None
        """
        return self._operations.get(message_id)


# TODO: Integration points for implementation:
#
# 1. Connection Manager Integration:
#    - Add cancel_operation method to LDAPConnectionManager
#    - Track outstanding operations with message IDs
#    - Handle cancel responses and update operation status
#
# 2. Operation Lifecycle Management:
#    - Integrate OperationTracker with connection operations
#    - Automatically track search, modify, add, delete operations
#    - Provide callbacks for operation completion/cancellation
#
# 3. Client-Side Timeout Handling:
#    - Implement automatic cancellation for timed-out operations
#    - Provide configurable timeout policies per operation type
#    - Handle network timeout vs operation timeout scenarios
#
# 4. User Interface Integration:
#    - Provide cancel buttons/controls in UI applications
#    - Show operation progress with cancel options
#    - Handle user-initiated cancellation requests
#
# 5. Error Handling and Recovery:
#    - Handle cases where cancel fails or is not supported
#    - Provide fallback strategies (connection reset, etc.)
#    - Log cancellation attempts and results
#
# 6. Performance Optimization:
#    - Batch multiple cancel operations when possible
#    - Optimize message ID management for high-volume scenarios
#    - Monitor cancel operation performance impact
#
# 7. Testing Requirements:
#    - Unit tests for all cancel scenarios (success, too late, error)
#    - Integration tests with long-running operations
#    - Load tests for high-frequency cancel operations
#    - Edge case tests (invalid message IDs, concurrent operations)
#
# 8. Security Considerations:
#    - Ensure operations can only be cancelled by the same connection
#    - Validate message ID ownership and permissions
#    - Log security-relevant cancellation events
