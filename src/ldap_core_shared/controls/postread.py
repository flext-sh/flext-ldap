"""LDAP PostRead Control Implementation.

This module provides PostRead control functionality following perl-ldap
Net::LDAP::Control::PostRead patterns with enterprise-grade change
verification and state tracking capabilities.

The PostRead control enables atomic retrieval of entry attributes after
a modify, add, or delete operation, essential for verifying changes,
audit logging, and consistency checking in enterprise environments.

Architecture:
    - PostReadControl: Main control for requesting post-operation entry state
    - PostReadResponse: Response containing entry state after operation
    - PostReadRequest: Request configuration for post-read operations
    - ChangeVerificationHelper: Utilities for change verification

Usage Example:
    >>> from ldap_core_shared.controls.postread import PostReadControl
    >>>
    >>> # Verify changes after modify operation
    >>> postread = PostReadControl(attributes=["*"])
    >>> modify_result = connection.modify(dn, changes, controls=[postread])
    >>> # Verify the changes were applied correctly
    >>> if postread.response_available:
    ...     new_values = postread.get_attribute_values()
    ...     print(f"New state: {new_values}")

References:
    - perl-ldap: lib/Net/LDAP/Control/PostRead.pm
    - RFC 4527: LDAP Read Entry Controls
    - RFC 4511: LDAP Protocol Specification
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from ldap_core_shared.controls.base import LDAPControl


class PostReadRequest(BaseModel):
    """Request configuration for PostRead control."""

    attributes: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Attributes to retrieve after operation",
    )

    include_operational: bool = Field(
        default=False, description="Include operational attributes"
    )

    verification_mode: bool = Field(
        default=False, description="Enable change verification mode"
    )

    track_timestamps: bool = Field(
        default=True, description="Track modification timestamps"
    )

    def get_attribute_list(self) -> list[str]:
        """Get complete attribute list for PostRead control."""
        attrs = self.attributes.copy()

        if self.include_operational and "+" not in attrs:
            attrs.append("+")

        if self.track_timestamps:
            # Add timestamp tracking attributes
            timestamp_attrs = [
                "modifyTimestamp",
                "createTimestamp",
                "modifiersName",
                "creatorsName",
            ]
            for attr in timestamp_attrs:
                if attr not in attrs:
                    attrs.append(attr)

        return attrs


class PostReadResponse(BaseModel):
    """Response from PostRead control containing entry state after operation."""

    entry_dn: str = Field(description="Distinguished name of the entry")

    attributes: dict[str, list[str]] = Field(
        default_factory=dict, description="Entry attributes after operation"
    )

    retrieved_at: datetime = Field(
        default_factory=datetime.now, description="When attributes were retrieved"
    )

    operation_context: Optional[str] = Field(
        default=None, description="Context of the operation (add, modify, delete)"
    )

    # Change tracking metadata
    modification_timestamp: Optional[str] = Field(
        default=None, description="Modification timestamp from entry"
    )

    creation_timestamp: Optional[str] = Field(
        default=None, description="Creation timestamp from entry"
    )

    modifier_dn: Optional[str] = Field(default=None, description="DN of modifier")

    creator_dn: Optional[str] = Field(default=None, description="DN of creator")

    def has_attribute(self, name: str) -> bool:
        """Check if attribute is present in post-operation state."""
        return name.lower() in {k.lower() for k in self.attributes.keys()}

    def get_attribute_values(self, name: str) -> list[str]:
        """Get values for specific attribute."""
        for attr_name, values in self.attributes.items():
            if attr_name.lower() == name.lower():
                return values
        return []

    def get_single_value(self, name: str) -> Optional[str]:
        """Get single value for attribute."""
        values = self.get_attribute_values(name)
        return values[0] if values else None

    def get_all_attributes(self) -> dict[str, list[str]]:
        """Get all retrieved attributes."""
        return self.attributes.copy()

    def verify_change_applied(self, expected_value: Any, attribute: str) -> bool:
        """Verify that expected change was applied.

        Args:
            expected_value: Expected value after operation
            attribute: Attribute name to check

        Returns:
            True if expected value is present
        """
        current_values = self.get_attribute_values(attribute)

        if isinstance(expected_value, list):
            return set(current_values) == set(expected_value)
        return str(expected_value) in current_values

    def create_verification_record(self) -> dict[str, Any]:
        """Create verification record from post-read data."""
        return {
            "entry_dn": self.entry_dn,
            "post_operation_state": self.attributes,
            "retrieved_at": self.retrieved_at.isoformat(),
            "modification_timestamp": self.modification_timestamp,
            "creation_timestamp": self.creation_timestamp,
            "modifier_dn": self.modifier_dn,
            "creator_dn": self.creator_dn,
            "operation_context": self.operation_context,
        }


class PostReadControl(LDAPControl):
    """LDAP PostRead control for retrieving entry state after operations.

    This control enables atomic retrieval of entry attributes after
    an add, modify, or delete operation, essential for change verification
    and consistency checking in enterprise environments.

    Example:
        >>> # Verify changes after modify operation
        >>> postread = PostReadControl()
        >>> result = connection.modify(dn, changes, controls=[postread])
        >>> if postread.response_available:
        ...     new_state = postread.response.get_all_attributes()
        ...     # Verify changes were applied correctly
        ...     if postread.verify_attribute_change("mail", "new@example.com"):
        ...         print("Email update verified")
    """

    control_type = "1.3.6.1.1.13.2"  # RFC 4527 PostRead control OID

    def __init__(
        self,
        attributes: Optional[list[str]] = None,
        include_operational: bool = False,
        verification_mode: bool = False,
        track_timestamps: bool = True,
        criticality: bool = False,
    ) -> None:
        """Initialize PostRead control.

        Args:
            attributes: List of attributes to retrieve (default: all user attributes)
            include_operational: Include operational attributes
            verification_mode: Enable change verification mode
            track_timestamps: Track modification timestamps
            criticality: Whether control is critical for operation
        """
        # Create request configuration
        self._request = PostReadRequest(
            attributes=attributes or ["*"],
            include_operational=include_operational,
            verification_mode=verification_mode,
            track_timestamps=track_timestamps,
        )

        # Initialize response storage
        self._response: Optional[PostReadResponse] = None
        self._response_available = False

        # Store expected changes for verification
        self._expected_changes: dict[str, Any] = {}

        # Initialize base control
        super().__init__(
            control_type=self.control_type,
            criticality=criticality,
            control_value=self._encode_request(),
        )

    def _encode_request(self) -> bytes:
        """Encode PostRead control request.

        Returns:
            BER-encoded control value

        Raises:
            NotImplementedError: BER encoding not yet implemented
        """
        # TODO: Implement BER encoding of attribute list
        # This should encode the attribute list according to RFC 4527
        # SEQUENCE OF AttributeDescription
        msg = (
            "PostRead control BER encoding not yet implemented. "
            "Implement proper ASN.1 BER encoding of attribute list "
            "according to RFC 4527 specification."
        )
        raise NotImplementedError(msg)

    def process_response(self, response_value: bytes) -> None:
        """Process PostRead control response from server.

        Args:
            response_value: BER-encoded response from server

        Raises:
            NotImplementedError: Response processing not yet implemented
        """
        # TODO: Implement BER decoding of response
        # This should decode the SearchResultEntry according to RFC 4527
        msg = (
            "PostRead control response processing not yet implemented. "
            "Implement proper ASN.1 BER decoding of SearchResultEntry "
            "according to RFC 4527 specification."
        )
        raise NotImplementedError(msg)

    def set_expected_changes(self, changes: dict[str, Any]) -> None:
        """Set expected changes for verification.

        Args:
            changes: Dictionary of expected attribute changes
        """
        self._expected_changes = changes.copy()

    @property
    def response(self) -> Optional[PostReadResponse]:
        """Get PostRead control response."""
        return self._response

    @property
    def response_available(self) -> bool:
        """Check if response is available."""
        return self._response_available

    @property
    def requested_attributes(self) -> list[str]:
        """Get list of requested attributes."""
        return self._request.get_attribute_list()

    def get_new_values(self, attribute: str) -> list[str]:
        """Get new values for specific attribute.

        Args:
            attribute: Attribute name

        Returns:
            List of new values
        """
        if not self._response:
            return []
        return self._response.get_attribute_values(attribute)

    def get_new_single_value(self, attribute: str) -> Optional[str]:
        """Get single new value for attribute.

        Args:
            attribute: Attribute name

        Returns:
            New value or None
        """
        if not self._response:
            return None
        return self._response.get_single_value(attribute)

    def has_new_attribute(self, attribute: str) -> bool:
        """Check if attribute is present in post-operation entry.

        Args:
            attribute: Attribute name

        Returns:
            True if attribute is present
        """
        if not self._response:
            return False
        return self._response.has_attribute(attribute)

    def verify_attribute_change(self, attribute: str, expected_value: Any) -> bool:
        """Verify that attribute has expected value after operation.

        Args:
            attribute: Attribute name
            expected_value: Expected value

        Returns:
            True if attribute has expected value
        """
        if not self._response:
            return False
        return self._response.verify_change_applied(expected_value, attribute)

    def verify_all_changes(self) -> dict[str, bool]:
        """Verify all expected changes were applied.

        Returns:
            Dictionary mapping attributes to verification results
        """
        results = {}

        for attr, expected_value in self._expected_changes.items():
            results[attr] = self.verify_attribute_change(attr, expected_value)

        return results

    def get_verification_summary(self) -> dict[str, Any]:
        """Get comprehensive verification summary.

        Returns:
            Summary of change verification results
        """
        if not self._response:
            return {"error": "No response available for verification"}

        verification_results = self.verify_all_changes()
        all_verified = all(verification_results.values())

        return {
            "entry_dn": self._response.entry_dn,
            "all_changes_verified": all_verified,
            "verification_results": verification_results,
            "expected_changes_count": len(self._expected_changes),
            "verified_changes_count": sum(verification_results.values()),
            "timestamp": datetime.now().isoformat(),
        }


# Change verification utilities
class ChangeVerificationHelper:
    """Helper utilities for change verification with PostRead control."""

    def __init__(self) -> None:
        """Initialize change verification helper."""

    @staticmethod
    def create_verification_report(
        operation_type: str,
        entry_dn: str,
        requested_changes: dict[str, Any],
        postread_response: Optional[PostReadResponse],
        operation_result: bool,
    ) -> dict[str, Any]:
        """Create comprehensive verification report.

        Args:
            operation_type: Type of operation (add, modify, delete)
            entry_dn: Distinguished name of entry
            requested_changes: Changes that were requested
            postread_response: PostRead control response
            operation_result: Whether operation succeeded

        Returns:
            Complete verification report
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "operation_type": operation_type,
            "entry_dn": entry_dn,
            "operation_result": operation_result,
            "requested_changes": requested_changes,
        }

        if postread_response:
            report["post_operation_state"] = (
                postread_response.create_verification_record()
            )

            # Verify each requested change
            verification_results = {}
            for attr, expected_value in requested_changes.items():
                verification_results[attr] = postread_response.verify_change_applied(
                    expected_value, attr
                )

            report["verification_results"] = verification_results
            report["all_changes_verified"] = all(verification_results.values())
        else:
            report["verification_results"] = "No PostRead response available"
            report["all_changes_verified"] = False

        return report

    @staticmethod
    def compare_with_preread(
        preread_response: Any,  # PreReadResponse when available
        postread_response: PostReadResponse,
    ) -> dict[str, Any]:
        """Compare PreRead and PostRead responses to create change summary.

        Args:
            preread_response: State before operation
            postread_response: State after operation

        Returns:
            Change summary with before/after comparison
        """
        # TODO: Implement full comparison when PreRead control is available
        return {
            "before": "PreRead comparison not yet implemented",
            "after": postread_response.create_verification_record(),
            "detected_changes": [],
        }

    @staticmethod
    def detect_unexpected_changes(
        requested_changes: dict[str, Any],
        postread_response: PostReadResponse,
        preread_response: Optional[Any] = None,
    ) -> list[str]:
        """Detect any unexpected changes that occurred.

        Args:
            requested_changes: Changes that were requested
            postread_response: State after operation
            preread_response: State before operation (optional)

        Returns:
            List of unexpected changes detected
        """
        unexpected = []

        # TODO: Implement full change detection
        # This would compare pre-read and post-read states
        # to identify changes beyond what was requested

        return unexpected


# Convenience functions for common use cases
def create_postread_for_verification(
    include_operational: bool = True,
) -> PostReadControl:
    """Create PostRead control optimized for change verification.

    Args:
        include_operational: Include operational attributes

    Returns:
        Configured PostRead control
    """
    return PostReadControl(
        attributes=["*"],
        include_operational=include_operational,
        verification_mode=True,
        track_timestamps=True,
        criticality=False,
    )


def create_postread_for_attributes(attributes: list[str]) -> PostReadControl:
    """Create PostRead control for specific attributes.

    Args:
        attributes: List of specific attributes to retrieve

    Returns:
        Configured PostRead control
    """
    return PostReadControl(
        attributes=attributes,
        include_operational=False,
        verification_mode=True,
        track_timestamps=True,
        criticality=False,
    )


def create_postread_for_audit() -> PostReadControl:
    """Create PostRead control optimized for audit trails.

    Returns:
        Configured PostRead control with comprehensive tracking
    """
    return PostReadControl(
        attributes=["*", "+"],  # All user and operational attributes
        include_operational=True,
        verification_mode=True,
        track_timestamps=True,
        criticality=False,
    )


# Combined PreRead/PostRead operations
class AtomicReadOperations:
    """Combined PreRead and PostRead operations for complete change tracking."""

    def __init__(self) -> None:
        """Initialize atomic read operations."""

    @staticmethod
    def create_combined_controls(
        attributes: Optional[list[str]] = None,
        include_operational: bool = True,
    ) -> tuple[Any, PostReadControl]:  # Returns (PreReadControl, PostReadControl)
        """Create both PreRead and PostRead controls for complete tracking.

        Args:
            attributes: Attributes to track
            include_operational: Include operational attributes

        Returns:
            Tuple of (PreReadControl, PostReadControl)
        """
        # TODO: Import PreReadControl when circular import is resolved
        # preread = PreReadControl(
        #     attributes=attributes,
        #     include_operational=include_operational,
        #     audit_mode=True,
        # )

        postread = PostReadControl(
            attributes=attributes,
            include_operational=include_operational,
            verification_mode=True,
            track_timestamps=True,
        )

        return (None, postread)  # Placeholder until PreRead import is available

    @staticmethod
    def create_change_summary(
        preread_control: Any,  # PreReadControl
        postread_control: PostReadControl,
        requested_changes: dict[str, Any],
    ) -> dict[str, Any]:
        """Create comprehensive change summary from both controls.

        Args:
            preread_control: PreRead control with response
            postread_control: PostRead control with response
            requested_changes: Changes that were requested

        Returns:
            Complete change summary
        """
        summary = {
            "timestamp": datetime.now().isoformat(),
            "requested_changes": requested_changes,
        }

        # Add PreRead data if available
        if (
            preread_control
            and hasattr(preread_control, "response")
            and preread_control.response
        ):
            summary["before_state"] = preread_control.response.create_audit_record()

        # Add PostRead data if available
        if postread_control and postread_control.response:
            summary["after_state"] = (
                postread_control.response.create_verification_record()
            )

            # Verify changes
            verification_results = {}
            for attr, expected_value in requested_changes.items():
                verification_results[attr] = postread_control.verify_attribute_change(
                    attr, expected_value
                )

            summary["verification_results"] = verification_results
            summary["all_changes_verified"] = all(verification_results.values())

        return summary


# TODO: Integration points for implementation:
#
# 1. BER Encoding/Decoding:
#    - Implement proper ASN.1 BER encoding for attribute list
#    - Implement BER decoding for SearchResultEntry response
#    - Handle different attribute types and syntaxes
#
# 2. LDAP Connection Integration:
#    - Integrate with connection manager for control processing
#    - Handle control response parsing from different LDAP libraries
#    - Proper error handling for unsupported servers
#
# 3. Change Verification Engine:
#    - Advanced change detection algorithms
#    - Support for complex attribute value comparisons
#    - Handling of operational attribute changes
#
# 4. Performance Optimization:
#    - Efficient processing of large entries
#    - Memory management for high-volume operations
#    - Optimized attribute comparison algorithms
#
# 5. Integration with PreRead:
#    - Combined PreRead/PostRead operation workflows
#    - Complete before/after change tracking
#    - Atomic operation verification
#
# 6. Audit and Compliance:
#    - Integration with audit logging systems
#    - Compliance reporting for change tracking
#    - Data integrity verification
#
# 7. Testing Requirements:
#    - Unit tests for all control functionality
#    - Integration tests with different LDAP servers
#    - Performance tests for large entries
#    - Edge case tests for various change scenarios
