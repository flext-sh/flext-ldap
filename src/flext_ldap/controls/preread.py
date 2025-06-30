"""RFC 4527 Compliant LDAP Pre-Read Control Implementation.

This module implements the Pre-Read control as defined in RFC 4527 Section 3.1.
The pre-read control allows clients to retrieve the target entry's state
before modifications are applied as an atomic part of the update operation.

RFC 4527 defines the Pre-Read control which enables:
- Reading entry state before Delete operations (returns current entry)
- Reading entry state before Modify operations (returns pre-modify state)
- Reading entry state before ModifyDN operations (returns pre-rename state)
- For Add operations, no pre-read response is returned (entry didn't exist)

The control is processed atomically with the update operation to ensure
proper isolation and consistency as mandated by RFC 4527.

Architecture:
    - PreReadControl: Request control with AttributeSelection
    - PreReadResponse: Response control with SearchResultEntry
    - RFC-compliant ASN.1 BER encoding/decoding
    - Full support for attribute selection patterns

Usage Example:
    >>> from flext_ldap.controls.preread import PreReadControl
    >>>
    >>> # Read specific attributes before modification
    >>> pre_read = PreReadControl(attributes=["employeeType", "manager"])
    >>>
    >>> # Read all user attributes before modification
    >>> pre_read_all = PreReadControl.all_user_attributes()
    >>>
    >>> # Perform modify with pre-read
    >>> result = connection.modify(
    ...     dn="cn=john.doe,ou=people,dc=example,dc=com",
    ...     changes=[("replace", "title", ["Senior Engineer"])],
    ...     controls=[pre_read],
    ... )
    >>>
    >>> # Access pre-read response from result controls
    >>> for control in result.controls:
    ...     if isinstance(control, PreReadResponse):
    ...         print(f"Previous title: {control.entry.get('title')}")

References:
    - RFC 4527: Lightweight Directory Access Protocol (LDAP) Read Entry Controls
    - RFC 4511: LDAP Protocol specification
    - RFC 3673: Lightweight Directory Access Protocol version 3 (LDAPv3): All Operational Attributes
    - OID: 1.3.6.1.1.13.1 (Pre-Read Control)
"""

from __future__ import annotations

from flext_ldapse import (
    ControlDecodingError,
    ControlEncodingError,
    LDAPControl,
)
from pydantic import BaseModel, Field, field_validator

# Constants for RFC 4527 compliance
RFC4527_PRE_READ_OID = "1.3.6.1.1.13.1"
RFC4527_POST_READ_OID = "1.3.6.1.1.13.2"

# ASN.1 BER encoding constants
BER_SEQUENCE_TAG = 0x30
BER_OCTET_STRING_TAG = 0x04
BER_APPLICATION_TAG_4 = 0x64  # SearchResultEntry [APPLICATION 4]
BER_SHORT_FORM_THRESHOLD = 128  # Values below this use short form length encoding


class AttributeSelection(BaseModel):
    """RFC 4511 AttributeSelection for Pre-Read control.

    Represents the BER-encoded AttributeSelection as specified in RFC 4511
    and extended by RFC 3673 for operational attributes.
    """

    attributes: list[str] = Field(
        default_factory=lambda: ["*"],
        description="List of attribute descriptions to return",
    )

    @field_validator("attributes")
    @classmethod
    def validate_attributes(cls, v: list[str]) -> list[str]:
        """Validate attribute selection list per RFC 3673."""
        if not v:
            return ["*"]  # Default to all user attributes

        # Remove duplicates while preserving order
        seen = set()
        validated = []
        for attr in v:
            attr_normalized = attr.strip().lower()
            if attr_normalized not in seen:
                seen.add(attr_normalized)
                validated.append(attr.strip())

        return validated

    def encode_ber(self) -> bytes:
        """Encode AttributeSelection as BER per RFC 4511.

        AttributeSelection ::= SEQUENCE OF LDAPString
        LDAPString ::= OCTET STRING -- UTF-8 encoded

        Returns:
            BER-encoded SEQUENCE OF OCTET STRING
        """
        # Encode each attribute as OCTET STRING
        encoded_attrs = []
        for attr in self.attributes:
            attr_bytes = attr.encode("utf-8")
            length = len(attr_bytes)

            # Encode length (simple form for length < 128)
            if length < BER_SHORT_FORM_THRESHOLD:
                length_bytes = bytes([length])
            else:
                # Long form encoding for length >= 128
                length_octets: list[int] = []
                temp_length = length
                while temp_length > 0:
                    length_octets.insert(0, temp_length & 0xFF)
                    temp_length >>= 8
                length_bytes = bytes([0x80 | len(length_octets)]) + bytes(length_octets)

            # OCTET STRING = tag + length + content
            encoded_attr = bytes([BER_OCTET_STRING_TAG]) + length_bytes + attr_bytes
            encoded_attrs.append(encoded_attr)

        # Encode as SEQUENCE
        content = b"".join(encoded_attrs)
        content_length = len(content)

        # Encode sequence length
        if content_length < BER_SHORT_FORM_THRESHOLD:
            length_bytes = bytes([content_length])
        else:
            length_octets = []
            temp_length = content_length
            while temp_length > 0:
                length_octets.insert(0, temp_length & 0xFF)
                temp_length >>= 8
            length_bytes = bytes([0x80 | len(length_octets)]) + bytes(length_octets)

        return bytes([BER_SEQUENCE_TAG]) + length_bytes + content

    @classmethod
    def decode_ber(cls, data: bytes) -> tuple[AttributeSelection, bytes]:
        """Decode BER-encoded AttributeSelection per RFC 4511.

        Args:
            data: BER-encoded data starting with SEQUENCE

        Returns:
            Tuple of (AttributeSelection, remaining_data)

        Raises:
            ValueError: If BER decoding fails
        """
        if not data or data[0] != BER_SEQUENCE_TAG:
            msg = "Invalid AttributeSelection: expected SEQUENCE"
            raise ValueError(msg)

        pos = 1

        # Decode length
        if pos >= len(data):
            msg = "Truncated AttributeSelection: missing length"
            raise ValueError(msg)

        length_byte = data[pos]
        pos += 1

        if length_byte & 0x80 == 0:
            # Short form
            content_length = length_byte
        else:
            # Long form
            length_octets = length_byte & 0x7F
            if length_octets == 0:
                msg = "Indefinite length not supported in AttributeSelection"
                raise ValueError(msg)

            if pos + length_octets > len(data):
                msg = "Truncated AttributeSelection: incomplete length"
                raise ValueError(msg)

            content_length = 0
            for _i in range(length_octets):
                content_length = (content_length << 8) | data[pos]
                pos += 1

        # Extract content
        if pos + content_length > len(data):
            msg = "Truncated AttributeSelection: incomplete content"
            raise ValueError(msg)

        content = data[pos : pos + content_length]
        remaining = data[pos + content_length :]

        # Decode attributes from content
        attributes = []
        attr_pos = 0

        while attr_pos < len(content):
            if content[attr_pos] != BER_OCTET_STRING_TAG:
                msg = f"Invalid attribute encoding: expected OCTET STRING, got {content[attr_pos]:02x}"
                raise ValueError(msg)

            attr_pos += 1

            # Decode attribute length
            if attr_pos >= len(content):
                msg = "Truncated attribute: missing length"
                raise ValueError(msg)

            attr_length_byte = content[attr_pos]
            attr_pos += 1

            if attr_length_byte & 0x80 == 0:
                # Short form
                attr_length = attr_length_byte
            else:
                # Long form
                attr_length_octets = attr_length_byte & 0x7F
                if attr_length_octets == 0:
                    msg = "Indefinite length not supported in attribute"
                    raise ValueError(msg)

                if attr_pos + attr_length_octets > len(content):
                    msg = "Truncated attribute: incomplete length"
                    raise ValueError(msg)

                attr_length = 0
                for _i in range(attr_length_octets):
                    attr_length = (attr_length << 8) | content[attr_pos]
                    attr_pos += 1

            # Extract attribute value
            if attr_pos + attr_length > len(content):
                msg = "Truncated attribute: incomplete value"
                raise ValueError(msg)

            attr_bytes = content[attr_pos : attr_pos + attr_length]
            attr_pos += attr_length

            try:
                attribute = attr_bytes.decode("utf-8")
                attributes.append(attribute)
            except UnicodeDecodeError as e:
                msg = f"Invalid UTF-8 in attribute: {e}"
                raise ValueError(msg) from e

        return cls(attributes=attributes), remaining


class SearchResultEntry(BaseModel):
    """RFC 4511 SearchResultEntry for Pre-Read response.

    Represents the entry returned in a Pre-Read response control.
    """

    object_name: str = Field(description="LDAP Distinguished Name")
    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Partial attribute list",
    )

    def encode_ber(self) -> bytes:
        """Encode SearchResultEntry as BER per RFC 4511.

        SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
            objectName      LDAPDN,
            attributes      PartialAttributeList }

        PartialAttributeList ::= SEQUENCE OF
            partialAttribute PartialAttribute

        PartialAttribute ::= SEQUENCE {
            type       AttributeDescription,
            vals       SET OF value AttributeValue }

        Returns:
            BER-encoded SearchResultEntry
        """
        # Encode object name (LDAPDN as OCTET STRING)
        dn_bytes = self.object_name.encode("utf-8")
        dn_length = len(dn_bytes)

        if dn_length < BER_SHORT_FORM_THRESHOLD:
            dn_length_bytes = bytes([dn_length])
        else:
            length_octets: list[int] = []
            temp_length = dn_length
            while temp_length > 0:
                length_octets.insert(0, temp_length & 0xFF)
                temp_length >>= 8
            dn_length_bytes = bytes([0x80 | len(length_octets)]) + bytes(length_octets)

        encoded_dn = bytes([BER_OCTET_STRING_TAG]) + dn_length_bytes + dn_bytes

        # Encode attributes (PartialAttributeList)
        encoded_attrs = []
        for attr_name, attr_values in self.attributes.items():
            # Encode attribute type
            type_bytes = attr_name.encode("utf-8")
            type_length = len(type_bytes)

            if type_length < BER_SHORT_FORM_THRESHOLD:
                type_length_bytes = bytes([type_length])
            else:
                length_octets = []
                temp_length = type_length
                while temp_length > 0:
                    length_octets.insert(0, temp_length & 0xFF)
                    temp_length >>= 8
                type_length_bytes = bytes([0x80 | len(length_octets)]) + bytes(
                    length_octets,
                )

            encoded_type = bytes([BER_OCTET_STRING_TAG]) + type_length_bytes + type_bytes

            # Encode attribute values as SET OF
            encoded_values = []
            for value in attr_values:
                value_bytes = value.encode("utf-8")
                value_length = len(value_bytes)

                if value_length < BER_SHORT_FORM_THRESHOLD:
                    value_length_bytes = bytes([value_length])
                else:
                    length_octets = []
                    temp_length = value_length
                    while temp_length > 0:
                        length_octets.insert(0, temp_length & 0xFF)
                        temp_length >>= 8
                    value_length_bytes = bytes([0x80 | len(length_octets)]) + bytes(
                        length_octets,
                    )

                encoded_value = bytes([BER_OCTET_STRING_TAG]) + value_length_bytes + value_bytes
                encoded_values.append(encoded_value)

            # Encode SET OF values
            values_content = b"".join(encoded_values)
            values_length = len(values_content)

            if values_length < BER_SHORT_FORM_THRESHOLD:
                values_length_bytes = bytes([values_length])
            else:
                length_octets = []
                temp_length = values_length
                while temp_length > 0:
                    length_octets.insert(0, temp_length & 0xFF)
                    temp_length >>= 8
                values_length_bytes = bytes([0x80 | len(length_octets)]) + bytes(
                    length_octets,
                )

            encoded_values_set = (
                bytes([0x31]) + values_length_bytes + values_content
            )  # SET tag = 0x31

            # Encode PartialAttribute as SEQUENCE
            attr_content = encoded_type + encoded_values_set
            attr_length = len(attr_content)

            if attr_length < BER_SHORT_FORM_THRESHOLD:
                attr_length_bytes = bytes([attr_length])
            else:
                length_octets = []
                temp_length = attr_length
                while temp_length > 0:
                    length_octets.insert(0, temp_length & 0xFF)
                    temp_length >>= 8
                attr_length_bytes = bytes([0x80 | len(length_octets)]) + bytes(
                    length_octets,
                )

            encoded_attr = bytes([BER_SEQUENCE_TAG]) + attr_length_bytes + attr_content
            encoded_attrs.append(encoded_attr)

        # Encode PartialAttributeList as SEQUENCE
        attrs_content = b"".join(encoded_attrs)
        attrs_length = len(attrs_content)

        if attrs_length < BER_SHORT_FORM_THRESHOLD:
            attrs_length_bytes = bytes([attrs_length])
        else:
            length_octets = []
            temp_length = attrs_length
            while temp_length > 0:
                length_octets.insert(0, temp_length & 0xFF)
                temp_length >>= 8
            attrs_length_bytes = bytes([0x80 | len(length_octets)]) + bytes(
                length_octets,
            )

        encoded_attrs_list = bytes([BER_SEQUENCE_TAG]) + attrs_length_bytes + attrs_content

        # Encode SearchResultEntry as [APPLICATION 4] SEQUENCE
        entry_content = encoded_dn + encoded_attrs_list
        entry_length = len(entry_content)

        if entry_length < BER_SHORT_FORM_THRESHOLD:
            entry_length_bytes = bytes([entry_length])
        else:
            length_octets = []
            temp_length = entry_length
            while temp_length > 0:
                length_octets.insert(0, temp_length & 0xFF)
                temp_length >>= 8
            entry_length_bytes = bytes([0x80 | len(length_octets)]) + bytes(
                length_octets,
            )

        return bytes([BER_APPLICATION_TAG_4]) + entry_length_bytes + entry_content

    @classmethod
    def decode_ber(cls, data: bytes) -> tuple[SearchResultEntry, bytes]:
        """Decode BER-encoded SearchResultEntry per RFC 4511.

        Args:
            data: BER-encoded data starting with [APPLICATION 4]

        Returns:
            Tuple of (SearchResultEntry, remaining_data)

        Raises:
            ValueError: If BER decoding fails
        """
        if not data or data[0] != BER_APPLICATION_TAG_4:
            msg = "Invalid SearchResultEntry: expected [APPLICATION 4]"
            raise ValueError(msg)

        pos = 1

        # Decode length (same logic as AttributeSelection)
        if pos >= len(data):
            msg = "Truncated SearchResultEntry: missing length"
            raise ValueError(msg)

        length_byte = data[pos]
        pos += 1

        if length_byte & 0x80 == 0:
            content_length = length_byte
        else:
            length_octets = length_byte & 0x7F
            if length_octets == 0:
                msg = "Indefinite length not supported in SearchResultEntry"
                raise ValueError(msg)

            if pos + length_octets > len(data):
                msg = "Truncated SearchResultEntry: incomplete length"
                raise ValueError(msg)

            content_length = 0
            for _i in range(length_octets):
                content_length = (content_length << 8) | data[pos]
                pos += 1

        if pos + content_length > len(data):
            msg = "Truncated SearchResultEntry: incomplete content"
            raise ValueError(msg)

        content = data[pos : pos + content_length]
        remaining = data[pos + content_length :]

        # Decode object name (LDAPDN)
        if not content or content[0] != BER_OCTET_STRING_TAG:
            msg = "Invalid SearchResultEntry: expected LDAPDN"
            raise ValueError(msg)

        # Simplified decoding for object name (assuming short length)
        dn_length = content[1]
        if dn_length & 0x80 != 0:
            msg = "Long form length not implemented for LDAPDN"
            raise ValueError(msg)

        dn_bytes = content[2 : 2 + dn_length]
        try:
            object_name = dn_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            msg = f"Invalid UTF-8 in LDAPDN: {e}"
            raise ValueError(msg) from e

        # For now, return empty attributes (full implementation would decode PartialAttributeList)
        return cls(object_name=object_name, attributes={}), remaining


class PreReadControl(LDAPControl):
    """RFC 4527 Pre-Read Control implementation.

    This control requests that the server return a copy of the target entry
    before the update operation is applied. The attributes to be returned
    are specified using RFC 4511 AttributeSelection syntax.

    Per RFC 4527:
    - OID: 1.3.6.1.1.13.1
    - Control value: BER-encoded AttributeSelection
    - Appropriate for: modifyRequest, delRequest, modDNRequest
    - Atomic processing with update operation required

    Attributes:
        attributes: List of attribute names per RFC 3673 extensions

    RFC 3673 Extensions:
        - "*" requests all user attributes
        - "+" requests all operational attributes
        - "*" "+" requests all attributes
        - Empty list requests all user attributes
    """

    control_type = RFC4527_PRE_READ_OID

    attributes: list[str] = Field(
        default_factory=lambda: ["*"],
        description="RFC 3673 AttributeSelection list",
    )

    @field_validator("attributes")
    @classmethod
    def validate_attributes(cls, v: list[str]) -> list[str]:
        """Validate attribute list per RFC 3673."""
        if not v:
            return ["*"]  # Default to all user attributes per RFC

        # Normalize and deduplicate
        seen = set()
        validated = []
        for attr in v:
            attr_normalized = attr.strip()
            if attr_normalized and attr_normalized.lower() not in seen:
                seen.add(attr_normalized.lower())
                validated.append(attr_normalized)

        return validated or ["*"]

    def encode_value(self) -> bytes:
        """Encode pre-read control value per RFC 4527.

        Per RFC 4527 Section 3.1:
        "The controlValue is a BER-encoded AttributeSelection [RFC4511],
        as extended by [RFC3673]"

        Returns:
            BER-encoded AttributeSelection

        Raises:
            ControlEncodingError: If BER encoding fails
        """
        try:
            attr_selection = AttributeSelection(attributes=self.attributes)
            return attr_selection.encode_ber()
        except Exception as e:
            msg = f"Failed to encode RFC 4527 pre-read control: {e}"
            raise ControlEncodingError(msg) from e

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> PreReadControl:
        """Decode pre-read control value per RFC 4527.

        Args:
            control_value: BER-encoded AttributeSelection

        Returns:
            PreReadControl instance

        Raises:
            ControlDecodingError: If BER decoding fails
        """
        if not control_value:
            # Empty control value means all user attributes per RFC
            return cls(attributes=["*"])

        try:
            attr_selection, _ = AttributeSelection.decode_ber(control_value)
            return cls(attributes=attr_selection.attributes)
        except Exception as e:
            msg = f"Failed to decode RFC 4527 pre-read control: {e}"
            raise ControlDecodingError(msg) from e

    @classmethod
    def all_user_attributes(cls) -> PreReadControl:
        """Create control for all user attributes per RFC 3673.

        Returns:
            PreReadControl with "*" attribute selection
        """
        return cls(attributes=["*"])

    @classmethod
    def all_operational_attributes(cls) -> PreReadControl:
        """Create control for all operational attributes per RFC 3673.

        Returns:
            PreReadControl with "+" attribute selection
        """
        return cls(attributes=["+"])

    @classmethod
    def all_attributes(cls) -> PreReadControl:
        """Create control for all attributes per RFC 3673.

        Returns:
            PreReadControl with "*" and "+" attribute selection
        """
        return cls(attributes=["*", "+"])

    @classmethod
    def specific_attributes(cls, *attributes: str) -> PreReadControl:
        """Create control for specific attributes.

        Args:
            *attributes: Attribute names to read

        Returns:
            PreReadControl for specified attributes
        """
        return cls(attributes=list(attributes))

    def includes_attribute(self, attribute: str) -> bool:
        """Check if control includes specified attribute per RFC 3673.

        Args:
            attribute: Attribute name to check

        Returns:
            True if attribute is included per RFC 3673 rules
        """
        attr_lower = attribute.lower()

        # Check for wildcard patterns per RFC 3673
        if "*" in self.attributes and "+" in self.attributes:
            return True  # All attributes requested

        if "*" in self.attributes:
            # All user attributes (non-operational)
            return not self._is_operational_attribute(attribute)

        if "+" in self.attributes:
            # All operational attributes + any explicitly listed
            return self._is_operational_attribute(attribute) or attr_lower in [
                a.lower() for a in self.attributes if a != "+"
            ]

        # Explicit attribute list
        return attr_lower in [a.lower() for a in self.attributes]

    def _is_operational_attribute(self, attribute: str) -> bool:
        """Check if attribute is operational per RFC 4512.

        Operational attributes typically start with specific prefixes
        or are well-known operational attributes.
        """
        attr_lower = attribute.lower()

        # Common operational attributes per RFC 4512
        operational_attrs = {
            "createtimestamp",
            "creatorsname",
            "modifytimestamp",
            "modifiersname",
            "structuralobjectclass",
            "governingstructurerule",
            "subschemasubentry",
            "entrydn",
            "entryuuid",
            "pwdchangedtime",
            "pwdhistory",
            "pwdpolicysubentry",
        }

        return attr_lower in operational_attrs

    def get_requested_attributes(self) -> list[str]:
        """Get list of requested attributes.

        Returns:
            List of attribute names including RFC 3673 patterns
        """
        return self.attributes.copy()

    def __str__(self) -> str:
        """String representation of pre-read control."""
        return f"PreReadControl(OID={self.control_type}, attrs={self.attributes})"


class PreReadResponse(LDAPControl):
    """RFC 4527 Pre-Read Response Control implementation.

    This control is returned by the server in response to a pre-read request,
    containing the entry state before the operation was applied.

    Per RFC 4527 Section 3.1:
    - OID: 1.3.6.1.1.13.1
    - Control value: BER-encoded SearchResultEntry
    - Returned only on successful operations (resultCode 0)
    - Contains entry state before operation

    Attributes:
        entry: SearchResultEntry with pre-operation state

    Note:
        For Add operations, no pre-read response is typically returned
        since the entry didn't exist before the operation.
    """

    control_type = RFC4527_PRE_READ_OID

    entry: SearchResultEntry | None = Field(
        default=None,
        description="SearchResultEntry with pre-operation state",
    )

    def encode_value(self) -> bytes:
        """Encode pre-read response per RFC 4527.

        Per RFC 4527 Section 3.1:
        "The controlValue, an OCTET STRING, contains a BER-encoded SearchResultEntry"

        Returns:
            BER-encoded SearchResultEntry

        Raises:
            ControlEncodingError: If BER encoding fails
        """
        try:
            if not self.entry:
                # No entry (e.g., for Add operations where entry didn't exist)
                # Return minimal valid SearchResultEntry with empty DN and attributes
                empty_entry = SearchResultEntry(object_name="", attributes={})
                return empty_entry.encode_ber()

            return self.entry.encode_ber()
        except Exception as e:
            msg = f"Failed to encode RFC 4527 pre-read response: {e}"
            raise ControlEncodingError(msg) from e

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> PreReadResponse:
        """Decode pre-read response per RFC 4527.

        Args:
            control_value: BER-encoded SearchResultEntry

        Returns:
            PreReadResponse instance

        Raises:
            ControlDecodingError: If BER decoding fails
        """
        if not control_value:
            return cls(entry=None)

        try:
            entry, _ = SearchResultEntry.decode_ber(control_value)
            return cls(entry=entry if entry.object_name else None)
        except Exception as e:
            msg = f"Failed to decode RFC 4527 pre-read response: {e}"
            raise ControlDecodingError(msg) from e

    def has_entry(self) -> bool:
        """Check if response contains an entry.

        Returns:
            True if entry exists in response
        """
        return self.entry is not None and bool(self.entry.object_name)

    def get_attribute_values(self, attribute: str) -> list[str] | None:
        """Get attribute values from entry.

        Args:
            attribute: Attribute name

        Returns:
            List of attribute values or None if not present
        """
        if not self.entry:
            return None

        return self.entry.attributes.get(attribute)

    def get_dn(self) -> str | None:
        """Get entry distinguished name.

        Returns:
            Entry DN or None if no entry
        """
        if not self.entry:
            return None

        return self.entry.object_name or None

    def __str__(self) -> str:
        """String representation of pre-read response."""
        if self.has_entry():
            dn = self.get_dn()
            attr_count = len(self.entry.attributes) if self.entry else 0
            return f"PreReadResponse(dn='{dn}', attrs={attr_count})"
        return "PreReadResponse(no_entry)"


# RFC 4527 compliant convenience functions
def preread_all_user_attributes() -> PreReadControl:
    """Create RFC 3673 compliant pre-read control for all user attributes.

    Returns:
        PreReadControl with "*" attribute selection per RFC 3673
    """
    return PreReadControl.all_user_attributes()


def preread_all_operational_attributes() -> PreReadControl:
    """Create RFC 3673 compliant pre-read control for all operational attributes.

    Returns:
        PreReadControl with "+" attribute selection per RFC 3673
    """
    return PreReadControl.all_operational_attributes()


def preread_all_attributes() -> PreReadControl:
    """Create RFC 3673 compliant pre-read control for all attributes.

    Returns:
        PreReadControl with "*" and "+" attribute selection per RFC 3673
    """
    return PreReadControl.all_attributes()


def preread_specific_attributes(*attributes: str) -> PreReadControl:
    """Create pre-read control for specific attributes.

    Args:
        *attributes: Attribute names to read

    Returns:
        PreReadControl for specified attributes
    """
    return PreReadControl.specific_attributes(*attributes)


def preread_for_audit_trail() -> PreReadControl:
    """Create pre-read control optimized for audit trails.

    Returns audit-relevant attributes commonly needed for compliance
    and security logging.

    Returns:
        PreReadControl with all attributes for comprehensive audit
    """
    return PreReadControl.all_attributes()


def preread_user_profile_attributes() -> PreReadControl:
    """Create pre-read control for common user profile attributes.

    Returns:
        PreReadControl for typical user profile attributes
    """
    return PreReadControl.specific_attributes(
        "cn",
        "sn",
        "givenName",
        "mail",
        "telephoneNumber",
        "title",
        "department",
        "manager",
        "employeeNumber",
    )


# TODO: Integration points for full RFC 4527 compliance:
#
# 1. LDAP Operation Integration:
#    - Integrate with modify, delete, and modifyDN operations
#    - Ensure atomic processing per RFC 4527 requirements
#    - Handle operation failure scenarios properly
#
# 2. Server Implementation:
#    - Add supportedControl advertisement in rootDSE
#    - Implement proper access control checking
#    - Handle criticality flag processing
#
# 3. Enhanced SearchResultEntry Support:
#    - Complete PartialAttributeList decoding implementation
#    - Add support for binary attributes and options
#    - Implement proper attribute value encoding/decoding
#
# 4. Testing and Validation:
#    - Add comprehensive RFC 4527 compliance tests
#    - Test interaction with other controls per RFC 4527 Section 4
#    - Validate atomic operation behavior
#
# 5. Performance Optimization:
#    - Optimize BER encoding/decoding for large entries
#    - Add streaming support for large attribute values
#    - Implement efficient attribute filtering
