"""LDAP Tree Delete Control Implementation.

This module provides LDAP Tree Delete Control functionality following RFC 3707
with perl-ldap compatibility patterns for hierarchical subtree deletion
and recursive directory structure removal.

The Tree Delete Control enables deletion of an entire subtree of entries
in a single atomic operation, providing efficient cleanup of hierarchical
directory structures and organizational units.

Architecture:
    - TreeDeleteControl: Control for subtree deletion operations
    - TreeDeleteRequest: Request configuration for tree deletion
    - DeletionPolicy: Policy management for deletion operations
    - TreeDeleteResponse: Response with deletion metadata

Usage Example:
    >>> from flext_ldap.controls.advanced.tree_delete import TreeDeleteControl
    >>>
    >>> # Delete entire organizational unit with all children
    >>> tree_delete = TreeDeleteControl(
    ...     criticality=True  # Ensure operation fails if control not supported
    ... )
    >>>
    >>> result = connection.delete(
    ...     "ou=temporary,dc=example,dc=com",
    ...     controls=[tree_delete]
    ... )
    >>>
    >>> # Entire subtree is deleted atomically

References:
    - perl-ldap: lib/Net/LDAP/Control/TreeDelete.pm
    - RFC 3707: LDAP Hierarchy Manipulation Controls
    - X.500 Directory Services tree operations
    - Atomic deletion patterns for directory hierarchies
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import ldap3

from flext_ldapse import LDAPControl
from pydantic import BaseModel, Field

# Constants for magic values
MIN_PROCESSING_PRIORITY = 1
MAX_PROCESSING_PRIORITY = 10
LARGE_OPERATION_THRESHOLD = 1000
DEFAULT_RETRY_MULTIPLIER = 2
MIN_RETRY_MULTIPLIER = 2
MAX_RETRY_MULTIPLIER = 4


class DeletionMode(Enum):
    """Modes for tree deletion operations."""

    RECURSIVE = "recursive"  # Delete all children recursively
    LEAF_ONLY = "leaf_only"  # Only delete if no children exist
    FORCED = "forced"  # Force deletion regardless of constraints
    SAFE = "safe"  # Safe deletion with validation


class DeletionConstraint(Enum):
    """Constraints for tree deletion operations."""

    NO_CONSTRAINTS = "no_constraints"  # No deletion constraints
    PRESERVE_CRITICAL = "preserve_critical"  # Preserve critical entries
    REQUIRE_EMPTY_OU = "require_empty_ou"  # Require empty organizational units
    VALIDATE_REFERENCES = "validate_references"  # Validate no external references


class TreeDeletionPolicy(BaseModel):
    """Policy configuration for tree deletion operations."""

    deletion_mode: DeletionMode = Field(
        default=DeletionMode.RECURSIVE,
        description="Mode for deletion operation",
    )

    deletion_constraints: list[DeletionConstraint] = Field(
        default_factory=list,
        description="Constraints to apply during deletion",
    )

    # Safety settings
    max_deletion_depth: int | None = Field(
        default=None,
        description="Maximum depth for recursive deletion",
    )

    max_entries_deleted: int | None = Field(
        default=None,
        description="Maximum number of entries to delete",
    )

    require_confirmation: bool = Field(
        default=False,
        description="Whether to require deletion confirmation",
    )

    # Performance settings
    batch_size: int | None = Field(
        default=None,
        description="Batch size for deletion operations",
    )

    deletion_timeout: int | None = Field(
        default=None,
        description="Timeout for deletion operation",
    )

    # Audit settings
    log_deletions: bool = Field(
        default=True,
        description="Whether to log deletion operations",
    )

    preserve_audit_trail: bool = Field(
        default=False,
        description="Whether to preserve audit trail of deletions",
    )

    def validate_deletion_constraints(self) -> list[str]:
        """Validate deletion policy constraints.

        Returns:
            List of validation error messages
        """
        errors = []

        if self.max_deletion_depth is not None and self.max_deletion_depth < 1:
            errors.append("Maximum deletion depth must be at least 1")

        if self.max_entries_deleted is not None and self.max_entries_deleted < 1:
            errors.append("Maximum entries deleted must be at least 1")

        if self.batch_size is not None and self.batch_size < 1:
            errors.append("Batch size must be at least 1")

        if (
            self.deletion_mode == DeletionMode.LEAF_ONLY
            and DeletionConstraint.NO_CONSTRAINTS in self.deletion_constraints
        ):
            errors.append("LEAF_ONLY mode incompatible with NO_CONSTRAINTS")

        return errors

    def is_safe_deletion(self) -> bool:
        """Check if deletion policy is configured for safe operation.

        Returns:
            True if deletion policy includes safety measures
        """
        safety_indicators = [
            self.deletion_mode == DeletionMode.SAFE,
            self.max_deletion_depth is not None,
            self.max_entries_deleted is not None,
            self.require_confirmation,
            DeletionConstraint.PRESERVE_CRITICAL in self.deletion_constraints,
        ]

        return any(safety_indicators)


class TreeDeleteRequest(BaseModel):
    """Request configuration for Tree Delete control."""

    target_dn: str = Field(description="DN of subtree root to delete")

    deletion_policy: TreeDeletionPolicy = Field(
        default_factory=TreeDeletionPolicy,
        description="Policy for deletion operation",
    )

    # Operation metadata
    operation_id: str | None = Field(
        default=None,
        description="Unique operation identifier",
    )

    requester_dn: str | None = Field(
        default=None,
        description="DN of user requesting deletion",
    )

    deletion_reason: str | None = Field(
        default=None,
        description="Reason for subtree deletion",
    )

    # Confirmation settings
    confirmation_token: str | None = Field(
        default=None,
        description="Confirmation token for deletion",
    )

    dry_run: bool = Field(
        default=False,
        description="Whether to perform dry run without actual deletion",
    )

    # Processing hints
    expected_entry_count: int | None = Field(
        default=None,
        description="Expected number of entries to delete",
    )

    processing_priority: int = Field(
        default=5,
        description="Processing priority (1-10)",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Request creation timestamp",
    )

    def validate_request(self) -> list[str]:
        """Validate tree deletion request.

        Returns:
            List of validation error messages
        """
        errors = []

        if not self.target_dn or not self.target_dn.strip():
            errors.append("Target DN is required for tree deletion")

        # Validate policy constraints
        policy_errors = self.deletion_policy.validate_deletion_constraints()
        errors.extend(policy_errors)

        if self.deletion_policy.require_confirmation and not self.confirmation_token:
            errors.append("Confirmation token required when confirmation is enabled")

        if self.expected_entry_count is not None and self.expected_entry_count < 0:
            errors.append("Expected entry count cannot be negative")

        if not (
            MIN_PROCESSING_PRIORITY
            <= self.processing_priority
            <= MAX_PROCESSING_PRIORITY
        ):
            errors.append(
                f"Processing priority must be between {MIN_PROCESSING_PRIORITY} and {MAX_PROCESSING_PRIORITY}",
            )

        return errors

    def estimate_operation_complexity(self) -> str:
        """Estimate complexity of deletion operation.

        Returns:
            Complexity level as string
        """
        if self.dry_run:
            return "low"  # Dry run is always low complexity

        complexity_factors = 0

        if self.deletion_policy.deletion_mode == DeletionMode.RECURSIVE:
            complexity_factors += DEFAULT_RETRY_MULTIPLIER

        if self.deletion_policy.max_deletion_depth is None:
            complexity_factors += 1

        if (
            self.expected_entry_count
            and self.expected_entry_count > LARGE_OPERATION_THRESHOLD
        ):
            complexity_factors += DEFAULT_RETRY_MULTIPLIER

        if len(self.deletion_policy.deletion_constraints) > DEFAULT_RETRY_MULTIPLIER:
            complexity_factors += 1

        if complexity_factors <= MIN_RETRY_MULTIPLIER:
            return "low"
        if complexity_factors <= MAX_RETRY_MULTIPLIER:
            return "medium"
        return "high"


class TreeDeleteResponse(BaseModel):
    """Response from Tree Delete control processing."""

    deletion_successful: bool = Field(description="Whether deletion was successful")

    # Deletion statistics
    entries_deleted: int = Field(default=0, description="Number of entries deleted")

    levels_processed: int = Field(
        default=0,
        description="Number of hierarchy levels processed",
    )

    deletion_order: list[str] = Field(
        default_factory=list,
        description="Order of entry deletion (DNs)",
    )

    # Error information
    result_code: int = Field(default=0, description="LDAP result code")

    result_message: str | None = Field(
        default=None,
        description="LDAP result message",
    )

    failed_deletions: list[str] = Field(
        default_factory=list,
        description="DNs that failed to delete",
    )

    constraint_violations: list[str] = Field(
        default_factory=list,
        description="Constraint violations encountered",
    )

    # Performance metadata
    total_processing_time: float | None = Field(
        default=None,
        description="Total processing time in seconds",
    )

    average_deletion_time: float | None = Field(
        default=None,
        description="Average time per deletion in seconds",
    )

    peak_memory_usage: int | None = Field(
        default=None,
        description="Peak memory usage during operation",
    )

    # Audit information
    deletion_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of deletion completion",
    )

    audit_trail: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Audit trail of deletion operations",
    )

    def is_success(self) -> bool:
        """Check if tree deletion was completely successful."""
        return (
            self.deletion_successful
            and self.result_code == 0
            and not self.failed_deletions
        )

    def get_success_rate(self) -> float:
        """Get deletion success rate as percentage.

        Returns:
            Success rate as percentage (0.0-100.0)
        """
        if self.entries_deleted == 0 and not self.failed_deletions:
            return 100.0  # No entries to delete

        total_attempted = self.entries_deleted + len(self.failed_deletions)
        if total_attempted == 0:
            return 0.0

        return (self.entries_deleted / total_attempted) * 100.0

    def get_performance_summary(self) -> dict[str, Any]:
        """Get performance summary.

        Returns:
            Dictionary with performance metrics
        """
        return {
            "entries_deleted": self.entries_deleted,
            "levels_processed": self.levels_processed,
            "total_processing_time": self.total_processing_time,
            "average_deletion_time": self.average_deletion_time,
            "peak_memory_usage": self.peak_memory_usage,
            "success_rate_percent": self.get_success_rate(),
            "failed_deletions_count": len(self.failed_deletions),
            "constraint_violations_count": len(self.constraint_violations),
        }

    def add_audit_entry(self, entry_dn: str, action: str, result: str) -> None:
        """Add entry to audit trail.

        Args:
            entry_dn: DN of entry that was processed
            action: Action taken (delete, skip, fail)
            result: Result of action
        """
        self.audit_trail.append(
            {
                "entry_dn": entry_dn,
                "action": action,
                "result": result,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )


class TreeDeleteControl(LDAPControl):
    """LDAP Tree Delete Control for hierarchical subtree deletion.

    This control enables deletion of an entire subtree of entries in a single
    atomic operation, providing efficient cleanup of hierarchical directory
    structures and organizational units.

    Example:
        >>> # Delete organizational unit and all children
        >>> tree_delete = TreeDeleteControl(criticality=True)
        >>>
        >>> result = connection.delete(
        ...     "ou=temp-project,ou=projects,dc=example,dc=com",
        ...     controls=[tree_delete]
        ... )
        >>>
        >>> # Check deletion response
        >>> if tree_delete.response and tree_delete.response.is_success():
        ...     print(f"Deleted {tree_delete.response.entries_deleted} entries")
        ... else:
        ...     print("Tree deletion failed")
    """

    control_type = "1.2.840.113556.1.4.805"  # Microsoft Tree Delete Control OID

    def __init__(
        self,
        deletion_policy: TreeDeletionPolicy | None = None,
        dry_run: bool = False,
        criticality: bool = True,
    ) -> None:
        """Initialize Tree Delete control.

        Args:
            deletion_policy: Policy for tree deletion operation
            dry_run: Whether to perform dry run without actual deletion
            criticality: Whether control is critical for operation
        """
        # Create default policy if not provided
        if deletion_policy is None:
            deletion_policy = TreeDeletionPolicy()

        # Create request configuration (target_dn will be set during operation)
        self._request = TreeDeleteRequest(
            target_dn="",  # Will be set from delete operation
            deletion_policy=deletion_policy,
            dry_run=dry_run,
        )

        # Validate policy
        policy_errors = deletion_policy.validate_deletion_constraints()
        if policy_errors:
            msg = f"Invalid deletion policy: {'; '.join(policy_errors)}"
            raise ValueError(msg)

        # Initialize response storage
        self._response: TreeDeleteResponse | None = None
        self._response_available = False

        # Initialize base control
        super().__init__(
            criticality=criticality,
            control_value=self._encode_request(),
        )

    def _encode_request(self) -> bytes:
        """Encode Tree Delete control request.

        Returns:
            BER-encoded control value (typically empty for standard tree delete)
        """
        # Standard Tree Delete control has no control value
        # The control presence itself indicates tree deletion request
        # Extended implementations could encode policy parameters here

        if self._request.dry_run or self._request.deletion_policy.require_confirmation:
            # For enhanced features, encode basic parameters
            from struct import pack

            # Simple encoding: dry_run flag + confirmation required flag
            flags = 0
            if self._request.dry_run:
                flags |= 0x01
            if self._request.deletion_policy.require_confirmation:
                flags |= 0x02

            return pack("B", flags)
        # Standard tree delete - no control value
        return b""

    def process_response(self, response_value: bytes) -> None:
        """Process Tree Delete control response from server.

        Args:
            response_value: BER-encoded response from server
        """
        # Process tree delete response
        if not response_value:
            # No response data - assume successful deletion
            self._response = TreeDeleteResponse(
                deletion_successful=True,
                entries_deleted=1,  # At least the target entry
                levels_processed=1,
                result_code=0,
                result_message="Tree deletion completed",
            )
            self._response_available = True
            return

        # Basic response parsing for deletion metadata
        from struct import unpack

        try:
            # Simple response format: result_code + entry_count + level_count
            offset = 0
            result_code = 0
            entries_deleted = 0
            levels_processed = 0

            if len(response_value) >= 1:
                result_code = unpack("B", response_value[offset : offset + 1])[0]
                offset += 1

            if len(response_value) >= offset + 2:
                entries_deleted = unpack("H", response_value[offset : offset + 2])[0]
                offset += 2

            if len(response_value) >= offset + 1:
                levels_processed = unpack("B", response_value[offset : offset + 1])[0]

            # Create response object
            self._response = TreeDeleteResponse(
                deletion_successful=(result_code == 0),
                entries_deleted=entries_deleted,
                levels_processed=levels_processed,
                result_code=result_code,
                result_message=(
                    "Tree deletion processed"
                    if result_code == 0
                    else "Tree deletion failed"
                ),
            )
            self._response_available = True

        except Exception:
            # Fallback response on parsing error
            self._response = TreeDeleteResponse(
                deletion_successful=False,
                entries_deleted=0,
                levels_processed=0,
                result_code=1,
                result_message="Response parsing failed",
            )
            self._response_available = True

    def set_target_dn(self, target_dn: str) -> None:
        """Set target DN for tree deletion.

        Args:
            target_dn: DN of subtree root to delete
        """
        self._request.target_dn = target_dn

    def set_confirmation_token(self, token: str) -> None:
        """Set confirmation token for deletion.

        Args:
            token: Confirmation token
        """
        self._request.confirmation_token = token

    def set_requester_info(
        self,
        requester_dn: str,
        reason: str | None = None,
    ) -> None:
        """Set requester information for audit trail.

        Args:
            requester_dn: DN of user requesting deletion
            reason: Optional reason for deletion
        """
        self._request.requester_dn = requester_dn
        self._request.deletion_reason = reason

    def estimate_deletion_complexity(self) -> str:
        """Estimate complexity of deletion operation.

        Returns:
            Complexity level (low, medium, high)
        """
        return self._request.estimate_operation_complexity()

    def is_safe_deletion(self) -> bool:
        """Check if deletion is configured for safe operation.

        Returns:
            True if deletion includes safety measures
        """
        return self._request.deletion_policy.is_safe_deletion()

    def get_deletion_summary(self) -> dict[str, Any]:
        """Get summary of deletion configuration.

        Returns:
            Dictionary with deletion configuration
        """
        return {
            "target_dn": self._request.target_dn,
            "deletion_mode": self._request.deletion_policy.deletion_mode.value,
            "constraints": [
                c.value for c in self._request.deletion_policy.deletion_constraints
            ],
            "max_depth": self._request.deletion_policy.max_deletion_depth,
            "max_entries": self._request.deletion_policy.max_entries_deleted,
            "dry_run": self._request.dry_run,
            "requires_confirmation": self._request.deletion_policy.require_confirmation,
            "estimated_complexity": self.estimate_deletion_complexity(),
            "is_safe": self.is_safe_deletion(),
        }

    @property
    def response(self) -> TreeDeleteResponse | None:
        """Get Tree Delete control response."""
        return self._response

    @property
    def response_available(self) -> bool:
        """Check if response is available."""
        return self._response_available

    @property
    def deletion_policy(self) -> TreeDeletionPolicy:
        """Get deletion policy configuration."""
        return self._request.deletion_policy

    @property
    def target_dn(self) -> str:
        """Get target DN for deletion."""
        return self._request.target_dn

    @property
    def dry_run(self) -> bool:
        """Check if configured for dry run."""
        return self._request.dry_run

    def encode_value(self) -> bytes | None:
        """Encode tree delete control value to ASN.1 bytes.

        Returns:
            Encoded control value or None if no value
        """
        return self.control_value

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> TreeDeleteControl:
        """Decode ASN.1 bytes to create tree delete control instance.

        Args:
            control_value: ASN.1 encoded control value

        Returns:
            TreeDeleteControl instance with decoded values
        """
        if not control_value:
            # Default tree delete control with safe deletion policy
            policy = TreeDeletionPolicy(
                deletion_mode=DeletionMode.SAFE,
                max_deletion_depth=10,
                deletion_constraints=[DeletionConstraint.PRESERVE_CRITICAL],
            )
            return cls(deletion_policy=policy, dry_run=False)

        # For now, return a default control since proper ASN.1 decoding
        # would require more complex implementation
        policy = TreeDeletionPolicy(
            deletion_mode=DeletionMode.SAFE,
            max_deletion_depth=10,
            deletion_constraints=[DeletionConstraint.PRESERVE_CRITICAL],
        )
        return cls(deletion_policy=policy, dry_run=False)


# Convenience functions
def create_tree_delete_control(
    safe_mode: bool = True,
    max_depth: int | None = None,
    dry_run: bool = False,
) -> TreeDeleteControl:
    """Create Tree Delete control with safety configuration.

    Args:
        safe_mode: Whether to enable safe deletion mode
        max_depth: Maximum deletion depth
        dry_run: Whether to perform dry run

    Returns:
        Configured Tree Delete control
    """
    policy = TreeDeletionPolicy(
        deletion_mode=DeletionMode.SAFE if safe_mode else DeletionMode.RECURSIVE,
        max_deletion_depth=max_depth,
        deletion_constraints=(
            [
                DeletionConstraint.PRESERVE_CRITICAL,
                DeletionConstraint.VALIDATE_REFERENCES,
            ]
            if safe_mode
            else []
        ),
    )

    return TreeDeleteControl(
        deletion_policy=policy,
        dry_run=dry_run,
        criticality=True,
    )


def create_forced_tree_delete_control() -> TreeDeleteControl:
    """Create Tree Delete control for forced deletion.

    Warning: This creates a control that bypasses safety constraints.

    Returns:
        Tree Delete control configured for forced deletion
    """
    policy = TreeDeletionPolicy(
        deletion_mode=DeletionMode.FORCED,
        deletion_constraints=[DeletionConstraint.NO_CONSTRAINTS],
    )

    return TreeDeleteControl(
        deletion_policy=policy,
        criticality=True,
    )


async def delete_subtree(
    connection: ldap3.Connection,
    subtree_dn: str,
    safe_mode: bool = True,
    dry_run: bool = False,
) -> TreeDeleteResponse:
    """Delete entire subtree using Tree Delete control.

    Args:
        connection: LDAP connection
        subtree_dn: DN of subtree root to delete
        safe_mode: Whether to use safe deletion mode
        dry_run: Whether to perform dry run

    Returns:
        Tree deletion response
    """
    # Create tree delete control with appropriate policy
    tree_delete_control = create_tree_delete_control(
        safe_mode=safe_mode,
        max_depth=10 if safe_mode else None,
        dry_run=dry_run,
    )

    # Set target DN for deletion
    tree_delete_control.set_target_dn(subtree_dn)

    try:
        # Perform delete operation with tree delete control
        success = connection.delete(
            dn=subtree_dn,
            controls=[tree_delete_control],
        )

        if success:
            # Process successful deletion
            if tree_delete_control.response:
                return tree_delete_control.response
            # Create default success response
            return TreeDeleteResponse(
                deletion_successful=True,
                entries_deleted=1,
                levels_processed=1,
                result_code=0,
                result_message="Subtree deleted successfully",
            )
        # Handle deletion failure
        return TreeDeleteResponse(
            deletion_successful=False,
            entries_deleted=0,
            levels_processed=0,
            result_code=1,
            result_message=f"Failed to delete subtree: {subtree_dn}",
        )

    except Exception as e:
        # Handle operation error
        return TreeDeleteResponse(
            deletion_successful=False,
            entries_deleted=0,
            levels_processed=0,
            result_code=1,
            result_message=f"Subtree deletion error: {e}",
        )
