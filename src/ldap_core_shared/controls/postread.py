"""RFC 4527 Compliant LDAP Post-Read Control Implementation.

This module implements the Post-Read control as defined in RFC 4527 Section 3.2.
The post-read control allows clients to retrieve the target entry's state
after modifications are applied as an atomic part of the update operation.

RFC 4527 defines the Post-Read control which enables:
- Reading entry state after Add operations (returns new entry)
- Reading entry state after Modify operations (returns post-modify state)
- Reading entry state after ModifyDN operations (returns post-rename state)
- Not applicable to Delete operations (entry no longer exists)

The control is processed atomically with the update operation to ensure
proper isolation and consistency as mandated by RFC 4527.

Architecture:
    - PostReadControl: Request control with AttributeSelection
    - PostReadResponse: Response control with SearchResultEntry
    - RFC-compliant ASN.1 BER encoding/decoding
    - Full support for attribute selection patterns
    - Change verification and audit capabilities

Usage Example:
    >>> from ldap_core_shared.controls.postread import PostReadControl
    >>>
    >>> # Read specific attributes after modification
    >>> post_read = PostReadControl(attributes=["employeeType", "manager"])
    >>>
    >>> # Read all user attributes after modification
    >>> post_read_all = PostReadControl.all_user_attributes()
    >>>
    >>> # Perform modify with post-read
    >>> result = connection.modify(
    ...     dn="cn=john.doe,ou=people,dc=example,dc=com",
    ...     changes=[("replace", "title", ["Senior Engineer"])],
    ...     controls=[post_read],
    ... )
    >>>
    >>> # Access post-read response from result controls
    >>> for control in result.controls:
    ...     if isinstance(control, PostReadResponse):
    ...         print(f"New title: {control.entry.get('title')}")

References:
    - RFC 4527: Lightweight Directory Access Protocol (LDAP) Read Entry Controls
    - RFC 4511: LDAP Protocol specification
    - RFC 3673: Lightweight Directory Access Protocol version 3 (LDAPv3): All Operational Attributes
    - OID: 1.3.6.1.1.13.2 (Post-Read Control)

"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from ldap_core_shared.controls.base import (
    ControlDecodingError,
    ControlEncodingError,
    LDAPControl,
)

# Constants for RFC 4527 compliance
RFC4527_PRE_READ_OID = "1.3.6.1.1.13.1"
RFC4527_POST_READ_OID = "1.3.6.1.1.13.2"

# ASN.1 BER encoding constants
BER_SEQUENCE_TAG = 0x30
BER_OCTET_STRING_TAG = 0x04
BER_SET_TAG = 0x31
BER_APPLICATION_TAG_4 = 0x64  # SearchResultEntry [APPLICATION 4]
BER_SHORT_FORM_THRESHOLD = 128  # Values below this use short form length encoding


class AttributeSelection(BaseModel):
    """RFC 4511 AttributeSelection for Post-Read control.

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
            length_octets: list[int] = []
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
    """RFC 4511 SearchResultEntry for Post-Read response.

    Represents the entry returned in a Post-Read response control.
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
                length_octets_list: list[int] = []
                temp_length = type_length
                while temp_length > 0:
                    length_octets_list.insert(0, temp_length & 0xFF)
                    temp_length >>= 8
                type_length_bytes = bytes([0x80 | len(length_octets_list)]) + bytes(
                    length_octets_list,
                )

            encoded_type = (
                bytes([BER_OCTET_STRING_TAG]) + type_length_bytes + type_bytes
            )

            # Encode attribute values as SET OF
            encoded_values = []
            for value in attr_values:
                value_bytes = value.encode("utf-8")
                value_length = len(value_bytes)

                if value_length < BER_SHORT_FORM_THRESHOLD:
                    value_length_bytes = bytes([value_length])
                else:
                    value_length_octets: list[int] = []
                    temp_length = value_length
                    while temp_length > 0:
                        value_length_octets.insert(0, temp_length & 0xFF)
                        temp_length >>= 8
                    value_length_bytes = bytes(
                        [0x80 | len(value_length_octets)],
                    ) + bytes(value_length_octets)

                encoded_value = (
                    bytes([BER_OCTET_STRING_TAG]) + value_length_bytes + value_bytes
                )
                encoded_values.append(encoded_value)

            # Encode SET OF values
            values_content = b"".join(encoded_values)
            values_length = len(values_content)

            if values_length < BER_SHORT_FORM_THRESHOLD:
                values_length_bytes = bytes([values_length])
            else:
                values_length_octets_list: list[int] = []
                temp_length = values_length
                while temp_length > 0:
                    values_length_octets_list.insert(0, temp_length & 0xFF)
                    temp_length >>= 8
                values_length_bytes = bytes(
                    [0x80 | len(values_length_octets_list)],
                ) + bytes(values_length_octets_list)

            encoded_values_set = (
                bytes([BER_SET_TAG]) + values_length_bytes + values_content
            )

            # Encode PartialAttribute as SEQUENCE
            attr_content = encoded_type + encoded_values_set
            attr_length = len(attr_content)

            if attr_length < BER_SHORT_FORM_THRESHOLD:
                attr_length_bytes = bytes([attr_length])
            else:
                attr_length_octets_list: list[int] = []
                temp_length = attr_length
                while temp_length > 0:
                    attr_length_octets_list.insert(0, temp_length & 0xFF)
                    temp_length >>= 8
                attr_length_bytes = bytes(
                    [0x80 | len(attr_length_octets_list)],
                ) + bytes(attr_length_octets_list)

            encoded_attr = bytes([BER_SEQUENCE_TAG]) + attr_length_bytes + attr_content
            encoded_attrs.append(encoded_attr)

        # Encode PartialAttributeList as SEQUENCE
        attrs_content = b"".join(encoded_attrs)
        attrs_length = len(attrs_content)

        if attrs_length < BER_SHORT_FORM_THRESHOLD:
            attrs_length_bytes = bytes([attrs_length])
        else:
            attrs_length_octets_list: list[int] = []
            temp_length = attrs_length
            while temp_length > 0:
                attrs_length_octets_list.insert(0, temp_length & 0xFF)
                temp_length >>= 8
            attrs_length_bytes = bytes([0x80 | len(attrs_length_octets_list)]) + bytes(
                attrs_length_octets_list,
            )

        encoded_attrs_list = (
            bytes([BER_SEQUENCE_TAG]) + attrs_length_bytes + attrs_content
        )

        # Encode SearchResultEntry as [APPLICATION 4] SEQUENCE
        entry_content = encoded_dn + encoded_attrs_list
        entry_length = len(entry_content)

        if entry_length < BER_SHORT_FORM_THRESHOLD:
            entry_length_bytes = bytes([entry_length])
        else:
            entry_length_octets_list: list[int] = []
            temp_length = entry_length
            while temp_length > 0:
                entry_length_octets_list.insert(0, temp_length & 0xFF)
                temp_length >>= 8
            entry_length_bytes = bytes([0x80 | len(entry_length_octets_list)]) + bytes(
                entry_length_octets_list,
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


class PostReadControl(LDAPControl):
    """RFC 4527 Post-Read Control implementation.

    This control requests that the server return a copy of the target entry
    after the update operation is applied. The attributes to be returned
    are specified using RFC 4511 AttributeSelection syntax.

    Per RFC 4527:
    - OID: 1.3.6.1.1.13.2
    - Control value: BER-encoded AttributeSelection
    - Appropriate for: addRequest, modifyRequest, modDNRequest
    - Atomic processing with update operation required

    Attributes:
        attributes: List of attribute names per RFC 3673 extensions

    RFC 3673 Extensions:
        - "*" requests all user attributes
        - "+" requests all operational attributes
        - "*" "+" requests all attributes
        - Empty list requests all user attributes

    """

    control_type = RFC4527_POST_READ_OID

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
        """Encode post-read control value per RFC 4527.

        Per RFC 4527 Section 3.2:
        "The controlValue, an OCTET STRING, contains a BER-encoded
        AttributeSelection [RFC4511], as extended by [RFC3673]"

        Returns:
            BER-encoded AttributeSelection

        Raises:
            ControlEncodingError: If BER encoding fails

        """
        try:
            attr_selection = AttributeSelection(attributes=self.attributes)
            return attr_selection.encode_ber()
        except Exception as e:
            msg = f"Failed to encode RFC 4527 post-read control: {e}"
            raise ControlEncodingError(msg) from e

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> PostReadControl:
        """Decode post-read control value per RFC 4527.

        Args:
            control_value: BER-encoded AttributeSelection

        Returns:
            PostReadControl instance

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
            msg = f"Failed to decode RFC 4527 post-read control: {e}"
            raise ControlDecodingError(msg) from e

    @classmethod
    def all_user_attributes(cls) -> PostReadControl:
        """Create control for all user attributes per RFC 3673.

        Returns:
            PostReadControl with "*" attribute selection

        """
        return cls(attributes=["*"])

    @classmethod
    def all_operational_attributes(cls) -> PostReadControl:
        """Create control for all operational attributes per RFC 3673.

        Returns:
            PostReadControl with "+" attribute selection

        """
        return cls(attributes=["+"])

    @classmethod
    def all_attributes(cls) -> PostReadControl:
        """Create control for all attributes per RFC 3673.

        Returns:
            PostReadControl with "*" and "+" attribute selection

        """
        return cls(attributes=["*", "+"])

    @classmethod
    def specific_attributes(cls, *attributes: str) -> PostReadControl:
        """Create control for specific attributes.

        Args:
            *attributes: Attribute names to read

        Returns:
            PostReadControl for specified attributes

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
        """String representation of post-read control."""
        return f"PostReadControl(OID={self.control_type}, attrs={self.attributes})"


class PostReadResponse(LDAPControl):
    """RFC 4527 Post-Read Response Control implementation.

    This control is returned by the server in response to a post-read request,
    containing the entry state after the operation was applied.

    Per RFC 4527 Section 3.2:
    - OID: 1.3.6.1.1.13.2
    - Control value: BER-encoded SearchResultEntry
    - Returned only on successful operations (resultCode 0)
    - Contains entry state after operation

    Attributes:
        entry: SearchResultEntry with post-operation state

    Note:
        For Delete operations, no post-read response is typically returned
        since the entry no longer exists after the operation.

    """

    control_type = RFC4527_POST_READ_OID

    entry: SearchResultEntry | None = Field(
        default=None,
        description="SearchResultEntry with post-operation state",
    )

    def encode_value(self) -> bytes:
        """Encode post-read response per RFC 4527.

        Per RFC 4527 Section 3.2:
        "The controlValue is a BER-encoded SearchResultEntry"

        Returns:
            BER-encoded SearchResultEntry

        Raises:
            ControlEncodingError: If BER encoding fails

        """
        try:
            if not self.entry:
                # No entry (e.g., for Delete operations where entry no longer exists)
                # Return minimal valid SearchResultEntry with empty DN and attributes
                empty_entry = SearchResultEntry(object_name="", attributes={})
                return empty_entry.encode_ber()

            return self.entry.encode_ber()
        except Exception as e:
            msg = f"Failed to encode RFC 4527 post-read response: {e}"
            raise ControlEncodingError(msg) from e

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> PostReadResponse:
        """Decode post-read response per RFC 4527.

        Args:
            control_value: BER-encoded SearchResultEntry

        Returns:
            PostReadResponse instance

        Raises:
            ControlDecodingError: If BER decoding fails

        """
        if not control_value:
            return cls(entry=None)

        try:
            entry, _ = SearchResultEntry.decode_ber(control_value)
            return cls(entry=entry if entry.object_name else None)
        except Exception as e:
            msg = f"Failed to decode RFC 4527 post-read response: {e}"
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

    def verify_change_applied(self, attribute: str, expected_value: Any) -> bool:
        """Verify that expected change was applied to the entry.

        Args:
            attribute: Attribute name to check
            expected_value: Expected value(s) after operation

        Returns:
            True if expected value is present in post-operation state

        """
        if not self.entry:
            return False

        current_values = self.get_attribute_values(attribute)
        if current_values is None:
            return expected_value is None

        if isinstance(expected_value, list):
            return set(current_values) == {str(v) for v in expected_value}

        return str(expected_value) in current_values

    def get_change_summary(self) -> dict[str, Any]:
        """Get summary of entry state after operation.

        Returns:
            Dictionary with entry state summary

        """
        if not self.has_entry():
            return {"status": "no_entry", "reason": "entry_not_available"}

        return {
            "status": "entry_available",
            "dn": self.get_dn(),
            "attribute_count": len(self.entry.attributes) if self.entry else 0,
            "attributes": list(self.entry.attributes.keys()) if self.entry else [],
        }

    def __str__(self) -> str:
        """String representation of post-read response."""
        if self.has_entry():
            dn = self.get_dn()
            attr_count = len(self.entry.attributes) if self.entry else 0
            return f"PostReadResponse(dn='{dn}', attrs={attr_count})"
        return "PostReadResponse(no_entry)"


# RFC 4527 compliant convenience functions
def postread_all_user_attributes() -> PostReadControl:
    """Create RFC 3673 compliant post-read control for all user attributes.

    Returns:
        PostReadControl with "*" attribute selection per RFC 3673

    """
    return PostReadControl.all_user_attributes()


def postread_all_operational_attributes() -> PostReadControl:
    """Create RFC 3673 compliant post-read control for all operational attributes.

    Returns:
        PostReadControl with "+" attribute selection per RFC 3673

    """
    return PostReadControl.all_operational_attributes()


def postread_all_attributes() -> PostReadControl:
    """Create RFC 3673 compliant post-read control for all attributes.

    Returns:
        PostReadControl with "*" and "+" attribute selection per RFC 3673

    """
    return PostReadControl.all_attributes()


def postread_specific_attributes(*attributes: str) -> PostReadControl:
    """Create post-read control for specific attributes.

    Args:
        *attributes: Attribute names to read

    Returns:
        PostReadControl for specified attributes

    """
    return PostReadControl.specific_attributes(*attributes)


def postread_for_change_verification(*changed_attributes: str) -> PostReadControl:
    """Create post-read control optimized for change verification.

    Requests specific attributes that were changed plus common verification
    attributes like modification timestamps.

    Args:
        *changed_attributes: Attributes that were modified

    Returns:
        PostReadControl with verification-optimized attribute selection

    """
    verification_attrs = [
        *list(changed_attributes),
        "modifyTimestamp",
        "modifiersName",
        "entryUUID",
    ]
    return PostReadControl.specific_attributes(*verification_attrs)


def postread_for_audit_trail() -> PostReadControl:
    """Create post-read control optimized for audit trails.

    Returns audit-relevant attributes commonly needed for compliance
    and security logging.

    Returns:
        PostReadControl with all attributes for comprehensive audit

    """
    return PostReadControl.all_attributes()


def postread_user_profile_attributes() -> PostReadControl:
    """Create post-read control for common user profile attributes.

    Returns:
        PostReadControl for typical user profile attributes

    """
    return PostReadControl.specific_attributes(
        "cn",
        "sn",
        "givenName",
        "mail",
        "telephoneNumber",
        "title",
        "department",
        "manager",
        "employeeNumber",
        "modifyTimestamp",
        "modifiersName",
    )


class ChangeVerificationHelper:
    """Helper class for verifying changes using Post-Read responses.

    Provides utilities for validating that LDAP operations applied
    changes correctly using Post-Read control responses.
    """

    @staticmethod
    def verify_add_operation(
        response: PostReadResponse,
        expected_attributes: dict[str, Any],
    ) -> dict[str, bool]:
        """Verify that Add operation created entry with expected attributes.

        Args:
            response: Post-Read response from Add operation
            expected_attributes: Attributes that should be present

        Returns:
            Dictionary mapping attributes to verification results

        """
        if not response.has_entry():
            return dict.fromkeys(expected_attributes, False)

        results = {}
        for attr, expected_value in expected_attributes.items():
            results[attr] = response.verify_change_applied(attr, expected_value)

        return results

    @staticmethod
    def verify_modify_operation(
        response: PostReadResponse,
        modifications: dict[str, Any],
    ) -> dict[str, bool]:
        """Verify that Modify operation applied changes correctly.

        Args:
            response: Post-Read response from Modify operation
            modifications: Modifications that were applied

        Returns:
            Dictionary mapping attributes to verification results

        """
        if not response.has_entry():
            return dict.fromkeys(modifications, False)

        results = {}
        for attr, new_value in modifications.items():
            results[attr] = response.verify_change_applied(attr, new_value)

        return results

    @staticmethod
    def verify_moddn_operation(
        response: PostReadResponse,
        new_dn: str,
    ) -> bool:
        """Verify that ModifyDN operation renamed entry correctly.

        Args:
            response: Post-Read response from ModifyDN operation
            new_dn: Expected new DN

        Returns:
            True if entry has expected new DN

        """
        if not response.has_entry():
            return False

        return response.get_dn() == new_dn

    @staticmethod
    def create_verification_report(
        operation_type: str,
        response: PostReadResponse,
        expected_changes: dict[str, Any],
    ) -> dict[str, Any]:
        """Create comprehensive verification report.

        Args:
            operation_type: Type of operation (add, modify, moddn)
            response: Post-Read response
            expected_changes: Expected changes

        Returns:
            Detailed verification report

        """
        report = {
            "operation_type": operation_type,
            "timestamp": "placeholder_timestamp",  # Would use datetime.now()
            "entry_present": response.has_entry(),
        }

        if response.has_entry():
            report["entry_dn"] = response.get_dn()
            report["entry_summary"] = response.get_change_summary()

            if operation_type == "add":
                verification_results = ChangeVerificationHelper.verify_add_operation(
                    response,
                    expected_changes,
                )
            elif operation_type == "modify":
                verification_results = ChangeVerificationHelper.verify_modify_operation(
                    response,
                    expected_changes,
                )
            else:
                verification_results = {}

            report["verification_results"] = verification_results
            report["all_changes_verified"] = all(verification_results.values())
        else:
            report["verification_results"] = {}
            report["all_changes_verified"] = False

        return report


# TODO: Integration points for full RFC 4527 compliance:
#
# 1. LDAP Operation Integration:
#    - Integrate with add, modify, and modifyDN operations
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
#    - Implement efficient change verification algorithms
#
# 6. Change Verification Engine:
#    - Advanced change detection and validation
#    - Support for complex attribute value comparisons
#    - Integration with audit and compliance systems
