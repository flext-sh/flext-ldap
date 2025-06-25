"""LDAP Server Side Sort Control Implementation.

This module implements the Server Side Sorting control as defined in RFC 2891.
This control allows clients to request that LDAP search results be sorted on
the server side, which is much more efficient than client-side sorting for
large result sets.

The server side sort control significantly improves performance and reduces
network traffic for operations that require sorted results, especially when
combined with paged results.

Architecture:
    - ServerSideSortControl: Request control for server-side sorting
    - SortKey: Individual sort key specification
    - SortOrder: Enumeration for sort order (ascending/descending)
    - SortResponse: Server response with sort status

Usage Example:
    >>> from ldap_core_shared.controls.sort import ServerSideSortControl, SortKey
    >>>
    >>> # Single attribute sort
    >>> sort_control = ServerSideSortControl([SortKey(attribute="cn")])
    >>>
    >>> # Multi-attribute sort with custom order
    >>> sort_control = ServerSideSortControl(
    ...     [
    ...         SortKey(attribute="department", order="ascending"),
    ...         SortKey(attribute="cn", order="descending"),
    ...     ]
    ... )
    >>>
    >>> # Search with server-side sorting
    >>> results = connection.search(
    ...     base_dn="ou=people,dc=example,dc=com",
    ...     filter_expr="(objectClass=person)",
    ...     controls=[sort_control],
    ... )

References:
    - perl-ldap: lib/Net/LDAP/Control/Sort.pm
    - RFC 2891: LDAP Control Extension for Server Side Sorting of Search Results
    - Request OID: 1.2.840.113556.1.4.473
    - Response OID: 1.2.840.113556.1.4.474
"""

from __future__ import annotations

from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, Field, validator

from ldap_core_shared.controls.base import (
    ControlDecodingError,
    ControlEncodingError,
    ControlOIDs,
    LDAPControl,
)


class SortOrder(Enum):
    """Sort order enumeration."""

    ASCENDING = "ascending"
    DESCENDING = "descending"

    def __str__(self) -> str:
        """String representation."""
        return self.value


class SortResult(Enum):
    """Server side sort result codes."""

    SUCCESS = 0
    OPERATIONS_ERROR = 1
    TIME_LIMIT_EXCEEDED = 3
    SIZE_LIMIT_EXCEEDED = 4
    COMPARE_FALSE = 5
    COMPARE_TRUE = 6
    AUTH_METHOD_NOT_SUPPORTED = 7
    STRONG_AUTH_REQUIRED = 8
    REFERRAL = 10
    ADMIN_LIMIT_EXCEEDED = 11
    UNAVAILABLE_CRITICAL_EXTENSION = 12
    CONFIDENTIALITY_REQUIRED = 13
    SASL_BIND_IN_PROGRESS = 14
    NO_SUCH_ATTRIBUTE = 16
    UNDEFINED_ATTRIBUTE_TYPE = 17
    INAPPROPRIATE_MATCHING = 18
    CONSTRAINT_VIOLATION = 19
    ATTRIBUTE_OR_VALUE_EXISTS = 20
    INVALID_ATTRIBUTE_SYNTAX = 21
    NO_SUCH_OBJECT = 32
    ALIAS_PROBLEM = 33
    INVALID_DN_SYNTAX = 34
    IS_LEAF = 35
    ALIAS_DEREFERENCING_PROBLEM = 36
    INAPPROPRIATE_AUTHENTICATION = 48
    INVALID_CREDENTIALS = 49
    INSUFFICIENT_ACCESS_RIGHTS = 50
    BUSY = 51
    UNAVAILABLE = 52
    UNWILLING_TO_PERFORM = 53
    LOOP_DETECT = 54
    SORT_CONTROL_MISSING = 60
    OFFSET_RANGE_ERROR = 61
    OTHER = 80


class SortKey(BaseModel):
    """Individual sort key specification.

    A sort key defines how to sort on a specific attribute, including
    the attribute name, sort order, and optional matching rule.

    Attributes:
        attribute: The LDAP attribute name to sort by
        order: Sort order (ascending or descending)
        matching_rule: Optional OID of matching rule for sorting
        reverse_order: Whether to reverse the sort order

    Note:
        The matching_rule specifies how attribute values should be compared.
        Common matching rules include caseIgnoreOrderingMatch for strings
        and integerOrderingMatch for integers.
    """

    attribute: str = Field(description="LDAP attribute name to sort by", min_length=1)

    order: SortOrder = Field(
        default=SortOrder.ASCENDING, description="Sort order for this attribute"
    )

    matching_rule: Optional[str] = Field(
        default=None, description="OID of matching rule for comparison"
    )

    reverse_order: bool = Field(
        default=False, description="Whether to reverse the natural sort order"
    )

    @validator("attribute")
    def validate_attribute_name(cls, v: str) -> str:
        """Validate attribute name format."""
        if not v or not v.strip():
            msg = "Attribute name cannot be empty"
            raise ValueError(msg)

        # Basic validation for LDAP attribute name format
        v = v.strip()
        if not v.replace("-", "").replace("_", "").replace(".", "").isalnum():
            msg = "Invalid attribute name format"
            raise ValueError(msg)

        return v

    @validator("order", pre=True)
    def validate_sort_order(cls, v: Union[str, SortOrder]) -> SortOrder:
        """Validate and convert sort order."""
        if isinstance(v, str):
            v = v.lower()
            if v in ("asc", "ascending", "up"):
                return SortOrder.ASCENDING
            if v in ("desc", "descending", "down"):
                return SortOrder.DESCENDING
            msg = f"Invalid sort order: {v}"
            raise ValueError(msg)
        return v

    def is_ascending(self) -> bool:
        """Check if sort order is ascending."""
        return (self.order == SortOrder.ASCENDING) != self.reverse_order

    def is_descending(self) -> bool:
        """Check if sort order is descending."""
        return not self.is_ascending()

    def get_effective_order(self) -> SortOrder:
        """Get the effective sort order considering reverse flag."""
        if self.reverse_order:
            return (
                SortOrder.DESCENDING
                if self.order == SortOrder.ASCENDING
                else SortOrder.ASCENDING
            )
        return self.order

    def __str__(self) -> str:
        """String representation of sort key."""
        order_str = "↓" if self.is_descending() else "↑"
        rule_str = f" ({self.matching_rule})" if self.matching_rule else ""
        return f"{self.attribute}{order_str}{rule_str}"


class ServerSideSortControl(LDAPControl):
    """Server Side Sort Control (RFC 2891).

    This control requests that the server sort the search results according
    to the specified sort keys. Multiple sort keys create a multi-level sort
    where later keys are used to break ties in earlier keys.

    The control is sent with search requests and the server responds with
    a sort response control indicating success or failure.

    Attributes:
        sort_keys: List of sort key specifications

    Note:
        The sort keys are applied in order - the first key is the primary sort,
        the second key breaks ties in the first, etc.
    """

    control_type = ControlOIDs.SERVER_SIDE_SORT

    sort_keys: list[SortKey] = Field(
        description="List of sort key specifications", min_items=1
    )

    @validator("sort_keys")
    def validate_sort_keys(cls, v: list[SortKey]) -> list[SortKey]:
        """Validate sort keys list."""
        if not v:
            msg = "At least one sort key is required"
            raise ValueError(msg)

        # Check for duplicate attributes
        attributes = [key.attribute.lower() for key in v]
        if len(attributes) != len(set(attributes)):
            msg = "Duplicate sort attributes not allowed"
            raise ValueError(msg)

        return v

    def encode_value(self) -> bytes:
        """Encode server side sort control value as ASN.1.

        The control value is a SEQUENCE OF SortKeyList where each SortKey is:
        SortKey ::= SEQUENCE {
            attributeType   AttributeDescription,
            orderingRule    [0] MatchingRuleId OPTIONAL,
            reverseOrder    [1] BOOLEAN DEFAULT FALSE }

        Returns:
            ASN.1 BER encoded control value

        Raises:
            ControlEncodingError: If encoding fails
        """
        try:
            sort_key_sequences = []

            for sort_key in self.sort_keys:
                # Encode attribute type as OCTET STRING
                attr_encoded = self._encode_octet_string(
                    sort_key.attribute.encode("utf-8")
                )

                key_content = attr_encoded

                # Add ordering rule if specified
                if sort_key.matching_rule:
                    rule_encoded = self._encode_octet_string(
                        sort_key.matching_rule.encode("utf-8")
                    )
                    rule_tagged = self._encode_context_tag(0, rule_encoded)
                    key_content += rule_tagged

                # Add reverse order if True
                reverse_needed = (
                    sort_key.reverse_order or sort_key.order == SortOrder.DESCENDING
                )
                if reverse_needed:
                    reverse_encoded = self._encode_boolean(True)
                    reverse_tagged = self._encode_context_tag(1, reverse_encoded)
                    key_content += reverse_tagged

                # Wrap in SEQUENCE
                sort_key_seq = self._encode_sequence(key_content)
                sort_key_sequences.append(sort_key_seq)

            # Combine all sort key sequences
            all_keys = b"".join(sort_key_sequences)

            # Wrap in SEQUENCE OF
            return self._encode_sequence(all_keys)

        except Exception as e:
            msg = f"Failed to encode server side sort control: {e}"
            raise ControlEncodingError(msg) from e

    @classmethod
    def decode_value(cls, control_value: Optional[bytes]) -> ServerSideSortControl:
        """Decode server side sort control value.

        Args:
            control_value: ASN.1 encoded control value

        Returns:
            ServerSideSortControl instance

        Raises:
            ControlDecodingError: If decoding fails
        """
        if not control_value:
            msg = "Server side sort control requires a value"
            raise ControlDecodingError(msg)

        try:
            # Decode SEQUENCE OF SortKey
            content = cls._decode_sequence(control_value)

            sort_keys = []
            pos = 0

            while pos < len(content):
                # Decode individual SortKey SEQUENCE
                if content[pos] != 0x30:  # SEQUENCE tag
                    msg = "Expected SEQUENCE for sort key"
                    raise ValueError(msg)

                seq_length = content[pos + 1]
                seq_content = content[pos + 2 : pos + 2 + seq_length]

                # Decode attribute type (OCTET STRING)
                attr_name, remaining = cls._decode_octet_string(seq_content)
                attribute = attr_name.decode("utf-8")

                # Default values
                matching_rule = None
                reverse_order = False

                # Decode optional fields
                field_pos = 0
                while field_pos < len(remaining):
                    tag = remaining[field_pos]

                    if tag == 0x80:  # Context tag [0] - ordering rule
                        rule_content, field_pos = cls._decode_context_tag(
                            remaining, field_pos
                        )
                        matching_rule = rule_content.decode("utf-8")

                    elif tag == 0x81:  # Context tag [1] - reverse order
                        reverse_content, field_pos = cls._decode_context_tag(
                            remaining, field_pos
                        )
                        reverse_order = cls._decode_boolean(reverse_content)

                    else:
                        field_pos += 1  # Skip unknown tags

                # Create sort key
                order = SortOrder.DESCENDING if reverse_order else SortOrder.ASCENDING
                sort_key = SortKey(
                    attribute=attribute,
                    order=order,
                    matching_rule=matching_rule,
                    reverse_order=reverse_order,
                )
                sort_keys.append(sort_key)

                # Move to next sort key
                pos += 2 + seq_length

            return cls(sort_keys=sort_keys)

        except Exception as e:
            msg = f"Failed to decode server side sort control: {e}"
            raise ControlDecodingError(msg) from e

    @classmethod
    def single_sort(
        cls,
        attribute: str,
        order: Union[str, SortOrder] = SortOrder.ASCENDING,
        matching_rule: Optional[str] = None,
    ) -> ServerSideSortControl:
        """Create control for sorting by a single attribute.

        Args:
            attribute: Attribute name to sort by
            order: Sort order (ascending or descending)
            matching_rule: Optional matching rule OID

        Returns:
            ServerSideSortControl for single attribute
        """
        sort_key = SortKey(
            attribute=attribute, order=order, matching_rule=matching_rule
        )
        return cls(sort_keys=[sort_key])

    @classmethod
    def multi_sort(
        cls, *sort_specs: Union[str, tuple, SortKey]
    ) -> ServerSideSortControl:
        """Create control for multi-attribute sorting.

        Args:
            *sort_specs: Sort specifications as:
                - str: attribute name (ascending order)
                - tuple: (attribute, order) or (attribute, order, matching_rule)
                - SortKey: complete sort key object

        Returns:
            ServerSideSortControl for multi-attribute sorting

        Example:
            >>> control = ServerSideSortControl.multi_sort(
            ...     "department",  # ascending
            ...     ("salary", "descending"),  # descending
            ...     SortKey(attribute="cn", order="ascending"),
            ... )
        """
        sort_keys = []

        for spec in sort_specs:
            if isinstance(spec, str):
                # Simple attribute name
                sort_keys.append(SortKey(attribute=spec))

            elif isinstance(spec, tuple):
                # Tuple specification
                if len(spec) == 2:
                    attr, order = spec
                    sort_keys.append(SortKey(attribute=attr, order=order))
                elif len(spec) == 3:
                    attr, order, rule = spec
                    sort_keys.append(
                        SortKey(attribute=attr, order=order, matching_rule=rule)
                    )
                else:
                    msg = f"Invalid sort specification tuple: {spec}"
                    raise ValueError(msg)

            elif isinstance(spec, SortKey):
                # Complete sort key object
                sort_keys.append(spec)

            else:
                msg = f"Invalid sort specification: {spec}"
                raise ValueError(msg)

        return cls(sort_keys=sort_keys)

    def get_primary_sort_attribute(self) -> str:
        """Get the primary (first) sort attribute."""
        return self.sort_keys[0].attribute

    def get_sort_attributes(self) -> list[str]:
        """Get list of all sort attributes in order."""
        return [key.attribute for key in self.sort_keys]

    def has_attribute(self, attribute: str) -> bool:
        """Check if sorting by specified attribute."""
        return attribute.lower() in [key.attribute.lower() for key in self.sort_keys]

    def __str__(self) -> str:
        """String representation of sort control."""
        key_strs = [str(key) for key in self.sort_keys]
        return f"ServerSideSort([{', '.join(key_strs)}])"

    # Simple ASN.1 encoding helpers
    @staticmethod
    def _encode_octet_string(value: bytes) -> bytes:
        """Encode bytes as BER OCTET STRING."""
        length = len(value)
        return b"\x04" + length.to_bytes(1, "big") + value

    @staticmethod
    def _encode_boolean(value: bool) -> bytes:
        """Encode boolean as BER BOOLEAN."""
        content = b"\xff" if value else b"\x00"
        return b"\x01\x01" + content

    @staticmethod
    def _encode_sequence(content: bytes) -> bytes:
        """Encode content as BER SEQUENCE."""
        length = len(content)
        return b"\x30" + length.to_bytes(1, "big") + content

    @staticmethod
    def _encode_context_tag(tag_num: int, content: bytes) -> bytes:
        """Encode content with context-specific tag."""
        tag = 0x80 | tag_num  # Context-specific, primitive
        length = len(content)
        return bytes([tag]) + length.to_bytes(1, "big") + content

    @classmethod
    def _decode_sequence(cls, data: bytes) -> bytes:
        """Decode BER SEQUENCE and return content."""
        if not data or data[0] != 0x30:
            msg = "Not a SEQUENCE"
            raise ValueError(msg)
        length = data[1]
        return data[2 : 2 + length]

    @classmethod
    def _decode_octet_string(cls, data: bytes) -> tuple[bytes, bytes]:
        """Decode BER OCTET STRING and return value and remaining data."""
        if not data or data[0] != 0x04:
            msg = "Not an OCTET STRING"
            raise ValueError(msg)
        length = data[1]
        content = data[2 : 2 + length]
        return content, data[2 + length :]

    @classmethod
    def _decode_boolean(cls, data: bytes) -> bool:
        """Decode BER BOOLEAN and return value."""
        if not data or data[0] != 0x01:
            msg = "Not a BOOLEAN"
            raise ValueError(msg)
        if data[1] != 0x01:
            msg = "Invalid BOOLEAN length"
            raise ValueError(msg)
        return data[2] != 0x00

    @classmethod
    def _decode_context_tag(cls, data: bytes, pos: int) -> tuple[bytes, int]:
        """Decode context-specific tag and return content and new position."""
        data[pos]
        length = data[pos + 1]
        content = data[pos + 2 : pos + 2 + length]
        return content, pos + 2 + length


class ServerSideSortResponse(LDAPControl):
    """Server Side Sort Response Control.

    This control is returned by the server in response to a sort request,
    indicating whether the sort was successful and providing error information
    if the sort failed.

    Attributes:
        sort_result: Result code indicating sort success or failure
        attribute_type_error: Attribute that caused error (if any)

    Note:
        A successful sort has sort_result = SortResult.SUCCESS.
        Any other value indicates an error in processing the sort request.
    """

    control_type = ControlOIDs.SERVER_SIDE_SORT_RESPONSE

    sort_result: SortResult = Field(description="Result code for sort operation")

    attribute_type_error: Optional[str] = Field(
        default=None, description="Attribute that caused sort error"
    )

    def encode_value(self) -> bytes:
        """Encode sort response control value.

        Returns:
            ASN.1 encoded response value

        Raises:
            ControlEncodingError: If encoding fails
        """
        try:
            # Encode result as ENUMERATED
            result_encoded = self._encode_enumerated(self.sort_result.value)

            content = result_encoded

            # Add attribute error if present
            if self.attribute_type_error:
                attr_encoded = self._encode_octet_string(
                    self.attribute_type_error.encode("utf-8")
                )
                content += attr_encoded

            return self._encode_sequence(content)

        except Exception as e:
            msg = f"Failed to encode sort response control: {e}"
            raise ControlEncodingError(msg) from e

    @classmethod
    def decode_value(cls, control_value: Optional[bytes]) -> ServerSideSortResponse:
        """Decode sort response control value.

        Args:
            control_value: ASN.1 encoded control value

        Returns:
            ServerSideSortResponse instance

        Raises:
            ControlDecodingError: If decoding fails
        """
        if not control_value:
            msg = "Sort response control requires a value"
            raise ControlDecodingError(msg)

        try:
            # Decode SEQUENCE
            content = cls._decode_sequence(control_value)

            # Decode result (ENUMERATED)
            result_value, remaining = cls._decode_enumerated(content)
            sort_result = SortResult(result_value)

            # Decode optional attribute error
            attribute_error = None
            if remaining:
                attr_bytes, _ = cls._decode_octet_string(remaining)
                attribute_error = attr_bytes.decode("utf-8")

            return cls(sort_result=sort_result, attribute_type_error=attribute_error)

        except Exception as e:
            msg = f"Failed to decode sort response control: {e}"
            raise ControlDecodingError(msg) from e

    def is_successful(self) -> bool:
        """Check if sort was successful."""
        return self.sort_result == SortResult.SUCCESS

    def get_error_message(self) -> Optional[str]:
        """Get human-readable error message."""
        if self.is_successful():
            return None

        base_msg = f"Sort failed: {self.sort_result.name}"
        if self.attribute_type_error:
            base_msg += f" (attribute: {self.attribute_type_error})"

        return base_msg

    # ASN.1 helpers for response
    @staticmethod
    def _encode_enumerated(value: int) -> bytes:
        """Encode integer as BER ENUMERATED."""
        if value == 0:
            content = b"\x00"
        else:
            content = value.to_bytes((value.bit_length() + 7) // 8, "big")
            if content[0] & 0x80:
                content = b"\x00" + content

        length = len(content)
        return b"\x0a" + length.to_bytes(1, "big") + content

    @staticmethod
    def _encode_sequence(content: bytes) -> bytes:
        """Encode content as BER SEQUENCE."""
        length = len(content)
        return b"\x30" + length.to_bytes(1, "big") + content

    @staticmethod
    def _encode_octet_string(value: bytes) -> bytes:
        """Encode bytes as BER OCTET STRING."""
        length = len(value)
        return b"\x04" + length.to_bytes(1, "big") + value

    @classmethod
    def _decode_sequence(cls, data: bytes) -> bytes:
        """Decode BER SEQUENCE and return content."""
        if not data or data[0] != 0x30:
            msg = "Not a SEQUENCE"
            raise ValueError(msg)
        length = data[1]
        return data[2 : 2 + length]

    @classmethod
    def _decode_enumerated(cls, data: bytes) -> tuple[int, bytes]:
        """Decode BER ENUMERATED and return value and remaining data."""
        if not data or data[0] != 0x0A:
            msg = "Not an ENUMERATED"
            raise ValueError(msg)
        length = data[1]
        content = data[2 : 2 + length]
        value = int.from_bytes(content, "big")
        return value, data[2 + length :]

    @classmethod
    def _decode_octet_string(cls, data: bytes) -> tuple[bytes, bytes]:
        """Decode BER OCTET STRING and return value and remaining data."""
        if not data or data[0] != 0x04:
            msg = "Not an OCTET STRING"
            raise ValueError(msg)
        length = data[1]
        content = data[2 : 2 + length]
        return content, data[2 + length :]


# Convenience functions
def sort_by(attribute: str, order: str = "ascending") -> ServerSideSortControl:
    """Create simple sort control for single attribute.

    Args:
        attribute: Attribute to sort by
        order: Sort order ("ascending" or "descending")

    Returns:
        ServerSideSortControl for single attribute
    """
    return ServerSideSortControl.single_sort(attribute, order)


def sort_ascending(*attributes: str) -> ServerSideSortControl:
    """Create sort control for multiple attributes in ascending order.

    Args:
        *attributes: Attribute names to sort by

    Returns:
        ServerSideSortControl for ascending multi-attribute sort
    """
    return ServerSideSortControl.multi_sort(*attributes)


def sort_descending(*attributes: str) -> ServerSideSortControl:
    """Create sort control for multiple attributes in descending order.

    Args:
        *attributes: Attribute names to sort by

    Returns:
        ServerSideSortControl for descending multi-attribute sort
    """
    specs = [(attr, "descending") for attr in attributes]
    return ServerSideSortControl.multi_sort(*specs)


# TODO: Integration points for implementation:
#
# 1. Search Engine Integration:
#    - Integrate with ldap_core_shared.core.search_engine
#    - Add sort control support to search operations
#    - Handle sort response parsing automatically
#
# 2. Performance Optimization:
#    - Combine with paged results for large sorted datasets
#    - Cache sort order preferences per application
#    - Monitor sort performance and provide fallbacks
#
# 3. Connection Manager Integration:
#    - Add sort support to all search methods
#    - Provide automatic fallback to client-side sorting
#    - Handle server capabilities detection
#
# 4. Error Handling:
#    - Graceful degradation when server doesn't support sorting
#    - Clear error messages for sort failures
#    - Retry logic for temporary sort failures
#
# 5. Configuration:
#    - Allow disabling server-side sort for specific servers
#    - Configure default sort orders per attribute type
#    - Set limits on maximum sort keys per request
#
# 6. Testing Requirements:
#    - Unit tests for all sort key combinations
#    - Integration tests with different LDAP servers
#    - Performance tests comparing server vs client sorting
#    - Edge case testing (empty results, large sorts)
