"""LDAP ManageDsaIT Control Implementation.

This module provides LDAP ManageDsaIT Control functionality following RFC 3296
with perl-ldap compatibility patterns for directory structure management
and referral handling bypass.

The ManageDsaIT Control enables operations on referral objects and other
special entries as regular objects, bypassing automatic referral chasing
and providing direct access to directory structure elements.

Architecture:
    - ManageDsaITControl: Main control for DSA-IT management
    - ManageDsaITRequest: Request configuration for DSA-IT operations
    - ReferralBypassManager: Referral handling bypass coordination
    - SpecialEntryHandler: Special entry type management

Usage Example:
    >>> from flext_ldap.controls.advanced.manage_dsa_it import ManageDsaITControl
    >>>
    >>> # Access referral object directly
    >>> manage_control = ManageDsaITControl()
    >>>
    >>> # Search referral objects without following them
    >>> results = connection.search(
    ...     search_base="ou=referrals,dc=example,dc=com",
    ...     search_filter="(objectClass=referral)",
    ...     controls=[manage_control]
    ... )
    >>>
    >>> # Modify referral object directly
    >>> connection.modify(
    ...     "cn=branch,ou=referrals,dc=example,dc=com",
    ...     changes={"ref": "ldap://newserver.example.com/ou=branch,dc=example,dc=com"},
    ...     controls=[manage_control]
    ... )

References:
    - perl-ldap: lib/Net/LDAP/Control/ManageDsaIT.pm
    - RFC 3296: Named Subordinate References in LDAP
    - RFC 4511: LDAP Protocol Specification
    - Directory structure management patterns
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from flext_ldapse import LDAPControl
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    import ldap3


class DsaITOperationType(Enum):
    """Types of DSA-IT operations."""

    SEARCH = "search"  # Search with referral bypass
    MODIFY = "modify"  # Modify referral objects
    ADD = "add"  # Add referral objects
    DELETE = "delete"  # Delete referral objects
    COMPARE = "compare"  # Compare referral objects


class ReferralHandlingMode(Enum):
    """Modes for referral handling bypass."""

    BYPASS_ALL = "bypass_all"  # Bypass all referral processing
    TREAT_AS_OBJECTS = "treat_as_objects"  # Treat referrals as normal objects
    SELECTIVE = "selective"  # Selective referral handling
    PRESERVE_STRUCTURE = "preserve_structure"  # Preserve directory structure


class ManageDsaITRequest(BaseModel):
    """Request configuration for ManageDsaIT control."""

    operation_type: DsaITOperationType = Field(
        description="Type of DSA-IT operation",
    )

    referral_handling: ReferralHandlingMode = Field(
        default=ReferralHandlingMode.TREAT_AS_OBJECTS,
        description="Mode for referral handling",
    )

    # Operation settings
    preserve_object_classes: bool = Field(
        default=True,
        description="Whether to preserve special object classes",
    )

    validate_references: bool = Field(
        default=False,
        description="Whether to validate referral targets",
    )

    allow_structural_changes: bool = Field(
        default=False,
        description="Whether to allow structural modifications",
    )

    # Security settings
    require_special_privileges: bool = Field(
        default=True,
        description="Whether to require special access privileges",
    )

    audit_operations: bool = Field(
        default=True,
        description="Whether to audit DSA-IT operations",
    )

    # Performance settings
    bypass_cache: bool = Field(
        default=False,
        description="Whether to bypass directory caches",
    )

    force_local_processing: bool = Field(
        default=True,
        description="Whether to force local processing",
    )

    def is_read_only_operation(self) -> bool:
        """Check if operation is read-only.

        Returns:
            True if operation is read-only
        """
        return self.operation_type in {
            DsaITOperationType.SEARCH,
            DsaITOperationType.COMPARE,
        }

    def requires_special_handling(self) -> bool:
        """Check if operation requires special handling.

        Returns:
            True if special handling is required
        """
        return (
            self.allow_structural_changes
            or self.validate_references
            or not self.preserve_object_classes
        )


class ManageDsaITResponse(BaseModel):
    """Response from ManageDsaIT control processing."""

    operation_completed: bool = Field(
        description="Whether DSA-IT operation completed",
    )

    result_code: int = Field(default=0, description="Operation result code")

    result_message: str | None = Field(
        default=None,
        description="Operation result message",
    )

    # Operation metadata
    referrals_bypassed: int = Field(
        default=0,
        description="Number of referrals bypassed",
    )

    special_entries_processed: int = Field(
        default=0,
        description="Number of special entries processed",
    )

    structural_changes_made: int = Field(
        default=0,
        description="Number of structural changes made",
    )

    # Performance metadata
    processing_time: float | None = Field(
        default=None,
        description="Processing time in seconds",
    )

    local_processing_time: float | None = Field(
        default=None,
        description="Local processing time in seconds",
    )

    # Error information
    error_message: str | None = Field(
        default=None,
        description="Error message if operation failed",
    )

    privilege_error: str | None = Field(
        default=None,
        description="Privilege-related error",
    )

    validation_errors: list[str] = Field(
        default_factory=list,
        description="Reference validation errors",
    )

    processed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Response processing timestamp",
    )

    def is_success(self) -> bool:
        """Check if DSA-IT operation was successful."""
        return self.operation_completed and self.result_code == 0

    def has_privilege_error(self) -> bool:
        """Check if operation failed due to privilege issues."""
        return bool(self.privilege_error)

    def has_validation_errors(self) -> bool:
        """Check if operation had validation errors."""
        return len(self.validation_errors) > 0

    def get_performance_summary(self) -> dict[str, Any]:
        """Get performance summary.

        Returns:
            Dictionary with performance metrics
        """
        return {
            "total_processing_time": self.processing_time,
            "local_processing_time": self.local_processing_time,
            "referrals_bypassed": self.referrals_bypassed,
            "entries_processed": self.special_entries_processed,
            "structural_changes": self.structural_changes_made,
        }


class ManageDsaITControl(LDAPControl):
    """LDAP ManageDsaIT Control for directory structure management.

    This control enables operations on referral objects and other special
    entries as regular objects, bypassing automatic referral chasing and
    providing direct access to directory structure elements.

    Example:
        >>> # Direct operations on referral objects
        >>> manage_control = ManageDsaITControl()
        >>>
        >>> # Search for referral entries without following them
        >>> results = connection.search(
        ...     search_base="dc=example,dc=com",
        ...     search_filter="(objectClass=referral)",
        ...     search_scope="SUBTREE",
        ...     controls=[manage_control]
        ... )
        >>>
        >>> # Modify referral target
        >>> connection.modify(
        ...     "cn=sales,ou=departments,dc=example,dc=com",
        ...     changes={"ref": "ldap://sales-server.example.com/ou=sales,dc=company,dc=com"},
        ...     controls=[manage_control]
        ... )
    """

    control_type = "2.16.840.1.113730.3.4.2"  # ManageDsaIT control OID

    def __init__(
        self,
        operation_type: DsaITOperationType = DsaITOperationType.SEARCH,
        referral_handling: ReferralHandlingMode = ReferralHandlingMode.TREAT_AS_OBJECTS,
        require_special_privileges: bool = True,
        criticality: bool = False,
    ) -> None:
        """Initialize ManageDsaIT control.

        Args:
            operation_type: Type of DSA-IT operation
            referral_handling: Mode for referral handling
            require_special_privileges: Whether to require special privileges
            criticality: Whether control is critical for operation
        """
        # Initialize base control first (without value)
        super().__init__(
            criticality=criticality,
            control_value=b"",  # ManageDsaIT has no control value per RFC 3296
        )

        # Initialize response storage
        self._response: ManageDsaITResponse | None = None
        self._response_available = False

        # Operation tracking
        self._referrals_encountered = 0
        self._special_entries_found = 0

        # Create request configuration
        self._request = ManageDsaITRequest(
            operation_type=operation_type,
            referral_handling=referral_handling,
            require_special_privileges=require_special_privileges,
        )

    def _encode_request(self) -> bytes:
        """Encode ManageDsaIT control request.

        Returns:
            BER-encoded control value (empty for ManageDsaIT per RFC 3296)
        """
        # According to RFC 3296, the ManageDsaIT control has no control value
        # The control value should be absent (NULL) or empty
        # This is a simple control that just signals the server to treat
        # referral objects as regular objects without following them
        return b""

    def process_response(self, response_value: bytes) -> None:
        """Process ManageDsaIT control response from server.

        Args:
            response_value: BER-encoded response from server
        """
        import time

        from flext_ldapng import get_logger

        logger = get_logger("manage_dsa_it")
        processing_start = time.time()

        try:
            # ManageDsaIT control typically doesn't have a response value
            # per RFC 3296, but we can track operation metadata

            result_code = 0
            result_message = None
            error_message = None

            # If response_value is provided, it might contain server-specific metadata
            if response_value:
                # Some servers may provide operational metadata
                # For now, we'll log it and treat as successful
                logger.debug(
                    "ManageDsaIT response received: %s bytes",
                    len(response_value),
                )
                result_message = "Server provided response metadata"
            else:
                result_message = "ManageDsaIT control processed successfully"

            # Create response object
            processing_time = time.time() - processing_start

            self._response = ManageDsaITResponse(
                operation_completed=True,
                result_code=result_code,
                result_message=result_message,
                referrals_bypassed=self._referrals_encountered,
                special_entries_processed=self._special_entries_found,
                processing_time=processing_time,
                local_processing_time=processing_time,
                error_message=error_message,
            )

            self._response_available = True

            logger.info(
                "ManageDsaIT response processed: "
                "referrals_bypassed=%s, special_entries=%s, time=%.3fs",
                self._referrals_encountered,
                self._special_entries_found,
                processing_time,
            )

        except Exception as e:
            logger.exception("Error processing ManageDsaIT response: %s", e)

            # Create error response
            self._response = ManageDsaITResponse(
                operation_completed=False,
                result_code=1,
                result_message="Response processing failed",
                error_message=str(e),
                processing_time=time.time() - processing_start,
            )

            self._response_available = True

    def set_operation_type(self, operation_type: DsaITOperationType) -> None:
        """Set DSA-IT operation type.

        Args:
            operation_type: New operation type
        """
        self._request.operation_type = operation_type
        # ManageDsaIT control value doesn't change per RFC 3296

    def set_referral_handling(self, handling_mode: ReferralHandlingMode) -> None:
        """Set referral handling mode.

        Args:
            handling_mode: New referral handling mode
        """
        self._request.referral_handling = handling_mode
        # ManageDsaIT control value doesn't change per RFC 3296

    def enable_validation(self, validate_references: bool = True) -> None:
        """Enable or disable reference validation.

        Args:
            validate_references: Whether to validate referral targets
        """
        self._request.validate_references = validate_references

    def allow_structural_modifications(self, allow: bool = True) -> None:
        """Allow or disallow structural modifications.

        Args:
            allow: Whether to allow structural changes
        """
        self._request.allow_structural_changes = allow

    def get_operation_summary(self) -> dict[str, Any]:
        """Get summary of DSA-IT operation configuration.

        Returns:
            Dictionary with operation configuration
        """
        return {
            "operation_type": self._request.operation_type.value,
            "referral_handling": self._request.referral_handling.value,
            "preserve_object_classes": self._request.preserve_object_classes,
            "validate_references": self._request.validate_references,
            "allow_structural_changes": self._request.allow_structural_changes,
            "require_special_privileges": self._request.require_special_privileges,
        }

    @property
    def response(self) -> ManageDsaITResponse | None:
        """Get ManageDsaIT control response."""
        return self._response

    @property
    def response_available(self) -> bool:
        """Check if response is available."""
        return self._response_available

    @property
    def operation_type(self) -> DsaITOperationType:
        """Get current operation type."""
        return self._request.operation_type

    @property
    def referral_handling_mode(self) -> ReferralHandlingMode:
        """Get current referral handling mode."""
        return self._request.referral_handling

    def encode_value(self) -> bytes | None:
        """Encode control value to ASN.1 bytes.

        Returns:
            Encoded control value or None (ManageDsaIT has no value)
        """
        return None

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> ManageDsaITControl:
        """Decode ASN.1 bytes to create control instance.

        Args:
            control_value: ASN.1 encoded control value

        Returns:
            ManageDsaITControl instance
        """
        # ManageDsaIT control has no value, return default instance
        return cls()


# Convenience functions
def create_manage_dsa_it_control() -> ManageDsaITControl:
    """Create ManageDsaIT control with default settings.

    Returns:
        Configured ManageDsaIT control
    """
    return ManageDsaITControl(
        operation_type=DsaITOperationType.SEARCH,
        referral_handling=ReferralHandlingMode.TREAT_AS_OBJECTS,
        criticality=False,
    )


def create_referral_search_control() -> ManageDsaITControl:
    """Create ManageDsaIT control for referral object searches.

    Returns:
        ManageDsaIT control configured for referral searches
    """
    return ManageDsaITControl(
        operation_type=DsaITOperationType.SEARCH,
        referral_handling=ReferralHandlingMode.BYPASS_ALL,
        require_special_privileges=False,
        criticality=False,
    )


def create_referral_modify_control() -> ManageDsaITControl:
    """Create ManageDsaIT control for referral object modifications.

    Returns:
        ManageDsaIT control configured for referral modifications
    """
    control = ManageDsaITControl(
        operation_type=DsaITOperationType.MODIFY,
        referral_handling=ReferralHandlingMode.TREAT_AS_OBJECTS,
        require_special_privileges=True,
        criticality=True,
    )

    # Configure for structural changes
    control.allow_structural_modifications(True)
    control.enable_validation(True)

    return control


async def search_referral_objects(
    connection: ldap3.Connection,
    search_base: str,
    search_filter: str = "(objectClass=referral)",
) -> list[dict[str, Any]]:
    """Search for referral objects without following them.

    Args:
        connection: LDAP connection
        search_base: Base DN for search
        search_filter: Filter for referral objects

    Returns:
        List of referral objects

    Raises:
        Exception: If search operation fails
    """
    from flext_ldapng import get_logger

    logger = get_logger("manage_dsa_it")

    try:
        # Create ManageDsaIT control to bypass referral following
        manage_control = create_referral_search_control()

        logger.info(
            "Searching for referral objects: base='%s', filter='%s'",
            search_base,
            search_filter,
        )

        # Perform search with ManageDsaIT control
        connection.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope="SUBTREE",
            attributes=["*", "+"],  # Request all attributes including operational
            controls=[manage_control],
        )

        # Process search results
        results = []
        if connection.entries:
            for entry in connection.entries:
                # Convert entry to dictionary format
                entry_dict = {
                    "dn": str(entry.entry_dn),
                    "attributes": {},
                }

                # Extract all attributes
                for attr_name in entry.entry_attributes:
                    attr_values = entry[attr_name].values
                    if len(attr_values) == 1:
                        entry_dict["attributes"][attr_name] = attr_values[0]
                    else:
                        entry_dict["attributes"][attr_name] = attr_values

                # Special handling for referral attributes
                if "ref" in entry_dict["attributes"]:
                    entry_dict["referral_urls"] = entry_dict["attributes"]["ref"]
                    if not isinstance(entry_dict["referral_urls"], list):
                        entry_dict["referral_urls"] = [entry_dict["referral_urls"]]

                results.append(entry_dict)

        logger.info("Found %s referral objects", len(results))

        # Update control statistics
        if hasattr(manage_control, "_special_entries_found"):
            manage_control._special_entries_found = len(results)

        return results

    except Exception as e:
        logger.exception("Error searching referral objects: %s", e)
        msg = f"Referral search failed: {e}"
        raise Exception(msg) from e


async def modify_referral_target(
    connection: ldap3.Connection,
    referral_dn: str,
    new_target: str,
) -> bool:
    """Modify referral target URL.

    Args:
        connection: LDAP connection
        referral_dn: DN of referral object
        new_target: New referral target URL

    Returns:
        True if modification succeeded

    Raises:
        Exception: If modification operation fails
    """
    from urllib.parse import urlparse

    from flext_ldapng import get_logger

    logger = get_logger("manage_dsa_it")

    try:
        # Validate new target URL format
        if not new_target.startswith(("ldap://", "ldaps://")):
            msg = f"Invalid LDAP URL format: {new_target}"
            raise ValueError(msg)

        # Parse URL to validate structure
        try:
            parsed_url = urlparse(new_target)
            if not parsed_url.hostname:
                msg = f"Invalid LDAP URL - missing hostname: {new_target}"
                raise ValueError(msg)
        except Exception as e:
            msg = f"Invalid LDAP URL format: {new_target}"
            raise ValueError(msg) from e

        logger.info(
            "Modifying referral target: dn='%s', new_target='%s'",
            referral_dn,
            new_target,
        )

        # Create ManageDsaIT control for referral modification
        manage_control = create_referral_modify_control()

        # First, read current referral object to validate it exists
        connection.search(
            search_base=referral_dn,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["objectClass", "ref"],
            controls=[manage_control],
        )

        if not connection.entries:
            msg = f"Referral object not found: {referral_dn}"
            raise Exception(msg)

        entry = connection.entries[0]

        # Verify it's a referral object
        object_classes = [str(oc).lower() for oc in entry.objectClass.values]
        if "referral" not in object_classes:
            msg = (
                f"Object is not a referral: {referral_dn}, objectClass={object_classes}"
            )
            raise Exception(msg)

        # Get current referral targets
        current_refs = (
            entry.ref.values if hasattr(entry, "ref") and entry.ref.values else []
        )

        logger.debug("Current referral targets for %s: %s", referral_dn, current_refs)

        # Prepare modification - replace all referral targets with new one
        changes = {"ref": [("MODIFY_REPLACE", [new_target])]}

        # Perform modification with ManageDsaIT control
        result = connection.modify(
            dn=referral_dn,
            changes=changes,
            controls=[manage_control],
        )

        if result:
            logger.info(
                "Successfully modified referral target: %s -> %s",
                referral_dn,
                new_target,
            )

            # Update control statistics
            if hasattr(manage_control, "_special_entries_found"):
                manage_control._special_entries_found = 1

            return True
        error_msg = getattr(connection, "last_error", "Unknown error")
        logger.error(
            "Failed to modify referral target: %s, error: %s",
            referral_dn,
            error_msg,
        )
        msg = f"LDAP modify failed: {error_msg}"
        raise Exception(msg)

    except Exception as e:
        logger.exception("Error modifying referral target: {e}")
        msg = f"Referral modification failed: {e}"
        raise Exception(msg) from e


# TODO: Integration points for implementation:
#
# 1. BER Encoding/Decoding:
#    - Implement proper BER encoding (typically no value for ManageDsaIT)
#    - Handle response processing for operation metadata
#    - Proper control value handling according to RFC 3296
#
# 2. Referral Processing Integration:
#    - Integration with referral handling system for bypass
#    - Coordination with connection manager for local processing
#    - Special entry type detection and handling
#
# 3. Security and Privileges:
#    - Access control integration for special operations
#    - Privilege validation for structural modifications
#    - Audit logging for DSA-IT operations
#
# 4. Directory Structure Management:
#    - Integration with schema validation for structural changes
#    - Reference validation and target reachability checks
#    - Consistency checks for directory structure modifications
#
# 5. Performance Optimization:
#    - Efficient bypass of referral processing
#    - Local processing optimization
#    - Cache management for special entries
#
# 6. Error Handling and Recovery:
#    - Comprehensive error handling for privilege issues
#    - Validation error processing and reporting
#    - Recovery strategies for failed structural changes
#
# 7. Testing Requirements:
#    - Unit tests for all ManageDsaIT functionality
#    - Integration tests with referral objects and special entries
#    - Security tests for privilege enforcement
#    - Performance tests for referral bypass overhead
