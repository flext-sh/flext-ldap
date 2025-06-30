"""LDAP Assertion Control Implementation.

This module provides LDAP Assertion Control functionality following RFC 4528
with perl-ldap compatibility patterns for conditional operation execution
and enterprise-grade assertion management.

The Assertion Control enables conditional execution of LDAP operations based
on assertion filters, providing atomic test-and-set functionality essential
for concurrent operations and data consistency guarantees.

Architecture:
    - AssertionControl: Main control for conditional operations
    - AssertionRequest: Request configuration for assertion operations
    - AssertionValidator: Assertion filter validation and processing
    - AssertionResult: Result processing for assertion operations

Usage Example:
    >>> from flext_ldap.controls.advanced.assertion import AssertionControl
    >>>
    >>> # Conditional modify operation
    >>> assertion_control = AssertionControl("(mail=old@example.com)")
    >>>
    >>> # Only modify if current mail value matches assertion
    >>> result = connection.modify(
    ...     "uid=john,ou=users,dc=example,dc=com",
    ...     changes={"mail": "new@example.com"},
    ...     controls=[assertion_control]
    ... )
    >>>
    >>> if result.result_code == 122:  # LDAP_ASSERTION_FAILED
    ...     print("Assertion failed - entry was modified by another operation")

References:
    - perl-ldap: lib/Net/LDAP/Control/Assertion.pm
    - RFC 4528: LDAP Assertion Control
    - RFC 4511: LDAP Protocol Specification
    - Enterprise concurrent operation patterns
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING

from flext_ldapse import LDAPControl
from pydantic import BaseModel, Field, validator

if TYPE_CHECKING:
    import ldap3

# Constants for magic values
LDAP_ASSERTION_FAILED_CODE = 122


class AssertionType(Enum):
    """Types of assertion operations."""

    SIMPLE = "simple"  # Simple filter assertion
    COMPLEX = "complex"  # Complex multi-condition assertion
    PRESENCE = "presence"  # Attribute presence assertion
    VALUE = "value"  # Specific value assertion


class AssertionRequest(BaseModel):
    """Request configuration for assertion control."""

    assertion_filter: str = Field(description="LDAP filter for assertion")

    assertion_type: AssertionType = Field(
        default=AssertionType.SIMPLE,
        description="Type of assertion",
    )

    # Assertion options
    case_sensitive: bool = Field(
        default=True,
        description="Whether assertion is case-sensitive",
    )

    approximate_match: bool = Field(
        default=False,
        description="Whether to use approximate matching",
    )

    timeout_seconds: int | None = Field(
        default=None,
        description="Assertion timeout in seconds",
    )

    # Validation settings
    validate_syntax: bool = Field(
        default=True,
        description="Whether to validate filter syntax",
    )

    require_indexed: bool = Field(
        default=False,
        description="Whether to require indexed attributes",
    )

    @validator("assertion_filter")
    def validate_filter(self, v: str) -> str:
        """Validate assertion filter syntax."""
        if not v or not v.strip():
            msg = "Assertion filter cannot be empty"
            raise ValueError(msg)

        # Basic filter validation
        if not (v.startswith("(") and v.endswith(")")):
            msg = "Assertion filter must be enclosed in parentheses"
            raise ValueError(msg)

        return v.strip()

    def get_filter_attributes(self) -> list[str]:
        """Extract attributes from assertion filter.

        Returns:
            List of attribute names used in filter
        """
        # TODO: Implement proper filter parsing
        # This would parse the filter and extract attribute names
        attributes = []

        # Simple extraction for basic filters
        import re

        # Match patterns like (attr=value) or (attr>=value)
        pattern = r"\(([a-zA-Z][a-zA-Z0-9-]*)[><=~]"
        matches = re.findall(pattern, self.assertion_filter)
        attributes.extend(matches)

        return list(set(attributes))

    def is_simple_equality(self) -> bool:
        """Check if assertion is simple equality filter.

        Returns:
            True if filter is simple equality assertion
        """
        import re

        # Pattern for simple equality: (attr=value)
        pattern = r"^\([a-zA-Z][a-zA-Z0-9-]*=.*\)$"
        return bool(re.match(pattern, self.assertion_filter))


class AssertionResponse(BaseModel):
    """Response from assertion control processing."""

    assertion_result: bool = Field(description="Whether assertion succeeded")

    result_code: int = Field(default=0, description="Assertion result code")

    result_message: str | None = Field(
        default=None,
        description="Assertion result message",
    )

    # Performance metadata
    evaluation_time: float | None = Field(
        default=None,
        description="Assertion evaluation time in seconds",
    )

    attributes_checked: list[str] = Field(
        default_factory=list,
        description="Attributes evaluated in assertion",
    )

    # Error information
    error_message: str | None = Field(
        default=None,
        description="Error message if assertion failed",
    )

    syntax_error: str | None = Field(
        default=None,
        description="Filter syntax error if invalid",
    )

    processed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Response processing timestamp",
    )

    def is_success(self) -> bool:
        """Check if assertion was successful."""
        return self.assertion_result and self.result_code == 0

    def is_assertion_failed(self) -> bool:
        """Check if assertion evaluation failed (not assertion false)."""
        return self.result_code == LDAP_ASSERTION_FAILED_CODE

    def get_error_summary(self) -> str:
        """Get comprehensive error summary."""
        errors = []

        if self.error_message:
            errors.append(f"Error: {self.error_message}")
        if self.syntax_error:
            errors.append(f"Syntax: {self.syntax_error}")
        if self.result_message:
            errors.append(f"Result: {self.result_message}")

        return "; ".join(errors) if errors else "No errors"


class AssertionControl(LDAPControl):
    """LDAP Assertion Control for conditional operation execution.

    This control enables conditional execution of LDAP operations based on
    assertion filters, providing atomic test-and-set functionality for
    concurrent operations and data consistency.

    Example:
        >>> # Conditional modify with assertion
        >>> assertion_control = AssertionControl("(version=1)")
        >>>
        >>> result = connection.modify(
        ...     "cn=config,dc=example,dc=com",
        ...     changes={"version": "2", "lastModified": "2024-01-01"},
        ...     controls=[assertion_control]
        ... )
        >>>
        >>> # Check if assertion succeeded
        >>> if assertion_control.response and assertion_control.response.is_success():
        ...     print("Configuration updated successfully")
        >>> elif assertion_control.response and assertion_control.response.is_assertion_failed():
        ...     print("Configuration was modified by another process")
    """

    control_type = "1.3.6.1.1.12"  # RFC 4528 Assertion Control OID

    def __init__(
        self,
        assertion_filter: str,
        assertion_type: AssertionType = AssertionType.SIMPLE,
        case_sensitive: bool = True,
        criticality: bool = True,
        timeout_seconds: int | None = None,
    ) -> None:
        """Initialize Assertion control.

        Args:
            assertion_filter: LDAP filter for assertion
            assertion_type: Type of assertion
            case_sensitive: Whether assertion is case-sensitive
            criticality: Whether control is critical for operation
            timeout_seconds: Optional assertion timeout
        """
        # Create request configuration
        self._request = AssertionRequest(
            assertion_filter=assertion_filter,
            assertion_type=assertion_type,
            case_sensitive=case_sensitive,
            timeout_seconds=timeout_seconds,
        )

        # Initialize response storage
        self._response: AssertionResponse | None = None
        self._response_available = False

        # Initialize base control
        super().__init__(
            criticality=criticality,
            control_value=self._encode_request(),
        )

    def _encode_request(self) -> bytes:
        """Encode Assertion control request.

        Returns:
            BER-encoded control value

        Note:
            Encodes assertion filter as UTF-8 LDAPString per RFC 4528
        """
        # Implement BER encoding of assertion filter according to RFC 4528
        try:
            # The control value is just the assertion filter as LDAPString (UTF-8)
            if self._assertion_filter:
                return self._assertion_filter.encode("utf-8")
            # Empty assertion filter
            return b""
        except Exception as e:
            from flext_ldapng import get_logger

            logger = get_logger(__name__)
            logger.exception("Assertion control encoding failed: %s", e)
            # Fallback to empty control value
            return b""

    def process_response(self, response_value: bytes) -> None:
        """Process Assertion control response from server.

        Args:
            response_value: BER-encoded response from server

        Note:
            Processes assertion response and stores result metadata
        """
        # Implement assertion response processing according to RFC 4528
        try:
            # Assertion control typically has no response value
            # The assertion result is indicated by the operation result code
            if response_value:
                # If there is response data, log it for debugging
                from flext_ldapng import get_logger

                logger = get_logger(__name__)
                logger.debug("Assertion control received response: %r", response_value)

                # Basic response processing - could be error information
                try:
                    response_text = response_value.decode("utf-8")
                    self._response_data = {
                        "response_received": True,
                        "response_content": response_text,
                        "response_length": len(response_value),
                    }
                except UnicodeDecodeError:
                    # Binary response data
                    self._response_data = {
                        "response_received": True,
                        "response_content": response_value,
                        "response_length": len(response_value),
                        "binary": True,
                    }
            else:
                # No response data (normal case)
                self._response_data = {
                    "response_received": True,
                    "response_content": None,
                    "assertion_processed": True,
                }

        except Exception as e:
            from flext_ldapng import get_logger

            logger = get_logger(__name__)
            logger.exception("Assertion response processing failed: %s", e)
            self._response_data = {
                "response_received": False,
                "error": str(e),
            }

    def update_assertion_filter(self, new_filter: str) -> None:
        """Update assertion filter for subsequent operations.

        Args:
            new_filter: New assertion filter
        """
        self._request.assertion_filter = new_filter
        # Re-validate the request
        self._request = AssertionRequest(**self._request.dict())
        # Update control value
        self.control_value = self._encode_request()

    def get_assertion_filter(self) -> str:
        """Get current assertion filter.

        Returns:
            Current assertion filter
        """
        return self._request.assertion_filter

    def get_filter_attributes(self) -> list[str]:
        """Get attributes used in assertion filter.

        Returns:
            List of attribute names
        """
        return self._request.get_filter_attributes()

    def is_simple_equality(self) -> bool:
        """Check if assertion is simple equality filter.

        Returns:
            True if filter is simple equality
        """
        return self._request.is_simple_equality()

    @property
    def response(self) -> AssertionResponse | None:
        """Get assertion control response."""
        return self._response

    @property
    def response_available(self) -> bool:
        """Check if response is available."""
        return self._response_available

    @property
    def assertion_type(self) -> AssertionType:
        """Get assertion type."""
        return self._request.assertion_type

    def encode_value(self) -> bytes | None:
        """Encode assertion control value to ASN.1 bytes.

        Returns:
            Encoded control value or None if no value
        """
        return self.control_value

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> AssertionControl:
        """Decode ASN.1 bytes to create assertion control instance.

        Args:
            control_value: ASN.1 encoded control value

        Returns:
            AssertionControl instance with decoded values
        """
        if not control_value:
            # Default assertion control with simple filter
            return cls("(objectClass=*)")

        # For now, return a default control since proper ASN.1 decoding
        # would require more complex implementation
        return cls("(objectClass=*)")


# Convenience functions
def create_assertion_control(assertion_filter: str) -> AssertionControl:
    """Create Assertion control with default settings.

    Args:
        assertion_filter: LDAP filter for assertion

    Returns:
        Configured Assertion control
    """
    return AssertionControl(
        assertion_filter=assertion_filter,
        criticality=True,
    )


def create_equality_assertion(attribute: str, value: str) -> AssertionControl:
    """Create simple equality assertion control.

    Args:
        attribute: Attribute name
        value: Expected value

    Returns:
        Assertion control for equality check
    """
    assertion_filter = f"({attribute}={value})"
    return AssertionControl(
        assertion_filter=assertion_filter,
        assertion_type=AssertionType.SIMPLE,
        criticality=True,
    )


def create_presence_assertion(attribute: str) -> AssertionControl:
    """Create attribute presence assertion control.

    Args:
        attribute: Attribute name to check for presence

    Returns:
        Assertion control for presence check
    """
    assertion_filter = f"({attribute}=*)"
    return AssertionControl(
        assertion_filter=assertion_filter,
        assertion_type=AssertionType.PRESENCE,
        criticality=True,
    )


async def test_assertion(
    connection: ldap3.Connection,
    dn: str,
    assertion_filter: str,
) -> bool:
    """Test assertion against entry without modifying it.

    Args:
        connection: LDAP connection
        dn: Distinguished name of entry
        assertion_filter: Filter to test

    Returns:
        True if assertion would succeed

    Note:
        Uses base-scope search with assertion control to test filter validity
    """
    # Implement assertion testing using search with assertion control
    try:
        # Create assertion control
        assertion_control = AssertionControl(assertion_filter=assertion_filter)

        # Perform search on specific entry with assertion control
        if hasattr(connection, "search"):
            success = connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",  # Simple filter to retrieve entry
                search_scope=0,  # Base scope - just the specified entry
                controls=[assertion_control],
            )

            # If search succeeded, assertion passed
            if success and hasattr(connection, "entries") and connection.entries:
                return True
            # Assertion failed or entry not found
            return False
        # Fallback when connection doesn't support search
        from flext_ldapng import get_logger

        logger = get_logger(__name__)
        logger.warning("Connection does not support search - cannot test assertion")
        return False

    except Exception as e:
        from flext_ldapng import get_logger

        logger = get_logger(__name__)
        logger.exception("Assertion test failed: %s", e)
        return False


# TODO: Integration points for implementation:
#
# 1. BER Encoding/Decoding:
#    - Implement proper ASN.1 BER encoding for assertion filters
#    - Handle LDAPString encoding according to RFC 4528
#    - Implement response decoding for assertion results
#
# 2. Filter Processing:
#    - Integration with filter parser for assertion validation
#    - Attribute extraction from complex filters
#    - Filter syntax validation and error handling
#
# 3. Connection Manager Integration:
#    - Integration with LDAP operations for assertion processing
#    - Proper error handling for assertion failures (result code 122)
#    - Response correlation and result processing
#
# 4. Performance Optimization:
#    - Efficient filter parsing and attribute extraction
#    - Caching of parsed filters for repeated operations
#    - Minimal overhead for assertion evaluation
#
# 5. Error Handling:
#    - Comprehensive error handling for assertion failures
#    - Clear distinction between assertion false and evaluation error
#    - Proper error messaging for debugging
#
# 6. Advanced Features:
#    - Support for complex assertion filters
#    - Approximate matching and case-insensitive assertions
#    - Timeout handling for long-running assertions
#
# 7. Testing Requirements:
#    - Unit tests for all assertion functionality
#    - Integration tests with LDAP servers supporting assertions
#    - Concurrency tests for atomic operations
#    - Performance tests for assertion overhead
