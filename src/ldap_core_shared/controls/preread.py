"""LDAP PreRead Control Implementation.

This module provides PreRead control functionality following perl-ldap
Net::LDAP::Control::PreRead patterns with enterprise-grade audit trail
and change tracking capabilities.

The PreRead control enables atomic retrieval of entry attributes before
a modify or delete operation, essential for audit logging, change tracking,
and rollback capabilities in enterprise environments.

Architecture:
    - PreReadControl: Main control for requesting pre-operation entry state
    - PreReadResponse: Response containing entry state before operation
    - PreReadRequest: Request configuration for pre-read operations
    - AuditTrailHelper: Utilities for audit trail integration

Usage Example:
    >>> from ldap_core_shared.controls.preread import PreReadControl
    >>>
    >>> # Request all attributes before modify operation
    >>> preread = PreReadControl(attributes=["*"])
    >>> modify_result = connection.modify(dn, changes, controls=[preread])
    >>> # Access original values for audit trail
    >>> if preread.response_available:
    ...     original_values = preread.get_attribute_values()
    ...     print(f"Original state: {original_values}")

References:
    - perl-ldap: lib/Net/LDAP/Control/PreRead.pm
    - RFC 4527: LDAP Read Entry Controls
    - RFC 4511: LDAP Protocol Specification
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from ldap_core_shared.controls.base import LDAPControl


class PreReadRequest(BaseModel):
    """Request configuration for PreRead control."""

    attributes: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Attributes to retrieve before operation",
    )

    include_operational: bool = Field(
        default=False, description="Include operational attributes"
    )

    audit_mode: bool = Field(
        default=False, description="Enable audit trail mode with enhanced metadata"
    )

    def get_attribute_list(self) -> list[str]:
        """Get complete attribute list for PreRead control."""
        attrs = self.attributes.copy()

        if self.include_operational and "+" not in attrs:
            attrs.append("+")

        if self.audit_mode:
            # Add critical audit attributes
            audit_attrs = [
                "modifyTimestamp",
                "modifiersName",
                "entryUUID",
                "contextCSN",
            ]
            for attr in audit_attrs:
                if attr not in attrs:
                    attrs.append(attr)

        return attrs


class PreReadResponse(BaseModel):
    """Response from PreRead control containing entry state."""

    entry_dn: str = Field(description="Distinguished name of the entry")

    attributes: dict[str, list[str]] = Field(
        default_factory=dict, description="Entry attributes before operation"
    )

    retrieved_at: datetime = Field(
        default_factory=datetime.now, description="When attributes were retrieved"
    )

    operation_context: Optional[str] = Field(
        default=None, description="Context of the operation (modify, delete, etc.)"
    )

    # Audit trail metadata
    modification_timestamp: Optional[str] = Field(
        default=None, description="Last modification timestamp from entry"
    )

    modifier_dn: Optional[str] = Field(default=None, description="DN of last modifier")

    entry_uuid: Optional[str] = Field(
        default=None, description="Entry UUID for tracking"
    )

    def has_attribute(self, name: str) -> bool:
        """Check if attribute was retrieved."""
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

    def create_audit_record(self) -> dict[str, Any]:
        """Create audit record from pre-read data."""
        return {
            "entry_dn": self.entry_dn,
            "pre_operation_state": self.attributes,
            "retrieved_at": self.retrieved_at.isoformat(),
            "last_modified": self.modification_timestamp,
            "last_modifier": self.modifier_dn,
            "entry_uuid": self.entry_uuid,
            "operation_context": self.operation_context,
        }


class PreReadControl(LDAPControl):
    """LDAP PreRead control for retrieving entry state before operations.

    This control enables atomic retrieval of entry attributes before
    a modify or delete operation, essential for audit trails and
    change tracking in enterprise environments.

    Example:
        >>> # Basic usage with all attributes
        >>> preread = PreReadControl()
        >>> result = connection.modify(dn, changes, controls=[preread])
        >>> if preread.response_available:
        ...     original_state = preread.response.get_all_attributes()
        ...     audit_log.record_change(dn, original_state, changes)
    """

    control_type = "1.3.6.1.1.13.1"  # RFC 4527 PreRead control OID

    def __init__(
        self,
        attributes: Optional[list[str]] = None,
        include_operational: bool = False,
        audit_mode: bool = False,
        criticality: bool = False,
    ) -> None:
        """Initialize PreRead control.

        Args:
            attributes: List of attributes to retrieve (default: all user attributes)
            include_operational: Include operational attributes
            audit_mode: Enable audit trail mode with enhanced metadata
            criticality: Whether control is critical for operation
        """
        # Create request configuration
        self._request = PreReadRequest(
            attributes=attributes or ["*"],
            include_operational=include_operational,
            audit_mode=audit_mode,
        )

        # Initialize response storage
        self._response: Optional[PreReadResponse] = None
        self._response_available = False

        # Initialize base control
        super().__init__(
            control_type=self.control_type,
            criticality=criticality,
            control_value=self._encode_request(),
        )

    def _encode_request(self) -> bytes:
        """Encode PreRead control request.

        Returns:
            BER-encoded control value

        Raises:
            NotImplementedError: BER encoding not yet implemented
        """
        # TODO: Implement BER encoding of attribute list
        # This should encode the attribute list according to RFC 4527
        # SEQUENCE OF AttributeDescription
        msg = (
            "PreRead control BER encoding not yet implemented. "
            "Implement proper ASN.1 BER encoding of attribute list "
            "according to RFC 4527 specification."
        )
        raise NotImplementedError(msg)

    def process_response(self, response_value: bytes) -> None:
        """Process PreRead control response from server.

        Args:
            response_value: BER-encoded response from server

        Raises:
            NotImplementedError: Response processing not yet implemented
        """
        # TODO: Implement BER decoding of response
        # This should decode the SearchResultEntry according to RFC 4527
        msg = (
            "PreRead control response processing not yet implemented. "
            "Implement proper ASN.1 BER decoding of SearchResultEntry "
            "according to RFC 4527 specification."
        )
        raise NotImplementedError(msg)

    @property
    def response(self) -> Optional[PreReadResponse]:
        """Get PreRead control response."""
        return self._response

    @property
    def response_available(self) -> bool:
        """Check if response is available."""
        return self._response_available

    @property
    def requested_attributes(self) -> list[str]:
        """Get list of requested attributes."""
        return self._request.get_attribute_list()

    def get_original_values(self, attribute: str) -> list[str]:
        """Get original values for specific attribute.

        Args:
            attribute: Attribute name

        Returns:
            List of original values
        """
        if not self._response:
            return []
        return self._response.get_attribute_values(attribute)

    def get_original_single_value(self, attribute: str) -> Optional[str]:
        """Get single original value for attribute.

        Args:
            attribute: Attribute name

        Returns:
            Original value or None
        """
        if not self._response:
            return None
        return self._response.get_single_value(attribute)

    def has_original_attribute(self, attribute: str) -> bool:
        """Check if attribute was present in original entry.

        Args:
            attribute: Attribute name

        Returns:
            True if attribute was present
        """
        if not self._response:
            return False
        return self._response.has_attribute(attribute)

    def create_change_diff(self, new_values: dict[str, Any]) -> dict[str, Any]:
        """Create diff between original and new values.

        Args:
            new_values: New attribute values

        Returns:
            Dictionary containing changes
        """
        if not self._response:
            return {"error": "No original values available"}

        diff = {
            "entry_dn": self._response.entry_dn,
            "changes": {},
            "timestamp": datetime.now().isoformat(),
        }

        original = self._response.get_all_attributes()

        # Check for modified attributes
        for attr, new_val in new_values.items():
            old_val = original.get(attr, [])

            if isinstance(new_val, list):
                if set(old_val) != set(new_val):
                    diff["changes"][attr] = {
                        "action": "modified",
                        "old_values": old_val,
                        "new_values": new_val,
                    }
            else:
                new_val_list = [new_val] if new_val is not None else []
                if old_val != new_val_list:
                    diff["changes"][attr] = {
                        "action": "modified",
                        "old_values": old_val,
                        "new_values": new_val_list,
                    }

        # Check for removed attributes
        for attr in original:
            if attr not in new_values:
                diff["changes"][attr] = {
                    "action": "removed",
                    "old_values": original[attr],
                    "new_values": [],
                }

        return diff


# Audit trail integration utilities
class AuditTrailHelper:
    """Helper utilities for audit trail integration with PreRead control."""

    def __init__(self) -> None:
        """Initialize audit trail helper."""

    @staticmethod
    def create_audit_entry(
        operation_type: str,
        entry_dn: str,
        preread_response: Optional[PreReadResponse],
        changes: Optional[dict[str, Any]] = None,
        operation_result: Optional[bool] = None,
    ) -> dict[str, Any]:
        """Create comprehensive audit entry.

        Args:
            operation_type: Type of operation (modify, delete, etc.)
            entry_dn: Distinguished name of modified entry
            preread_response: PreRead control response
            changes: Changes that were applied
            operation_result: Whether operation succeeded

        Returns:
            Complete audit entry
        """
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation_type": operation_type,
            "entry_dn": entry_dn,
            "operation_result": operation_result,
        }

        if preread_response:
            audit_entry["pre_operation_state"] = preread_response.create_audit_record()

        if changes:
            audit_entry["requested_changes"] = changes

        return audit_entry

    @staticmethod
    def compare_with_postread(
        preread_response: PreReadResponse,
        postread_response: Any,  # PostReadResponse when implemented
    ) -> dict[str, Any]:
        """Compare PreRead and PostRead responses to create change summary.

        Args:
            preread_response: State before operation
            postread_response: State after operation

        Returns:
            Change summary with before/after comparison
        """
        # TODO: Implement when PostRead control is available
        return {
            "before": preread_response.create_audit_record(),
            "after": "PostRead not yet implemented",
            "changes_detected": [],
        }


# Convenience functions for common use cases
def create_preread_for_audit(include_operational: bool = True) -> PreReadControl:
    """Create PreRead control optimized for audit trails.

    Args:
        include_operational: Include operational attributes

    Returns:
        Configured PreRead control
    """
    return PreReadControl(
        attributes=["*"],
        include_operational=include_operational,
        audit_mode=True,
        criticality=False,
    )


def create_preread_for_attributes(attributes: list[str]) -> PreReadControl:
    """Create PreRead control for specific attributes.

    Args:
        attributes: List of specific attributes to retrieve

    Returns:
        Configured PreRead control
    """
    return PreReadControl(
        attributes=attributes,
        include_operational=False,
        audit_mode=False,
        criticality=False,
    )


def create_preread_for_rollback() -> PreReadControl:
    """Create PreRead control optimized for rollback operations.

    Returns:
        Configured PreRead control with all attributes
    """
    return PreReadControl(
        attributes=["*", "+"],  # All user and operational attributes
        include_operational=True,
        audit_mode=True,
        criticality=True,  # Critical for rollback functionality
    )


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
# 3. Audit System Integration:
#    - Integration with enterprise audit logging systems
#    - Structured audit event formatting
#    - Async audit log processing for performance
#
# 4. Performance Optimization:
#    - Selective attribute retrieval based on operation type
#    - Efficient storage and processing of large entries
#    - Memory management for high-volume operations
#
# 5. Schema Integration:
#    - Validate requested attributes against schema
#    - Handle schema-aware attribute selection
#    - Optimize attribute lists based on schema information
#
# 6. Security and Compliance:
#    - Access control for PreRead operations
#    - Sensitive attribute filtering
#    - Compliance with data protection regulations
#
# 7. Testing Requirements:
#    - Unit tests for all control functionality
#    - Integration tests with different LDAP servers
#    - Performance tests for large entries
#    - Edge case tests for various attribute types
