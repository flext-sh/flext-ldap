from __future__ import annotations

from flext_ldap.utils.constants import LDAP_DEFAULT_PORT, LDAPS_DEFAULT_PORT

"""LDAP Helpers - Useful utilities and helper functions for LDAP projects."""


import base64
import logging
import re
from datetime import datetime
from typing import Any
from urllib.parse import quote

# Constants for magic values

logger = logging.getLogger(__name__)


class DNHelper:
    """Helper functions for Distinguished Name (DN) manipulation - Enterprise Delegation Facade.

    TRUE FACADE PATTERN: 100% DELEGATION TO ENTERPRISE DN INFRASTRUCTURE
    ====================================================================

    This class delegates entirely to the enterprise-grade DN utilities in
    utilities.dn without any reimplementation.

    DELEGATION TARGET: utilities.dn.DistinguishedName - Enterprise DN processing
    with RFC 4514 compliance, comprehensive validation, advanced manipulation.
    """

    @staticmethod
    def parse_dn(dn: str) -> list[dict[str, str]]:
        """Parse DN into list of RDN components - delegates to enterprise DN system.

        Args:
            dn: Distinguished Name to parse

        Returns:
            List of RDN dictionaries with 'attribute' and 'value' keys

        """
        if not dn:
            return []

        # Delegate to enterprise DN parsing
        from flext_ldapn import DistinguishedName

        try:
            enterprise_dn = DistinguishedName(dn)
            return [
                {
                    "attribute": comp.attribute_type,
                    "value": comp.attribute_value,
                }
                for comp in enterprise_dn.components
            ]
        except Exception:
            return []

    @staticmethod
    def build_dn(rdns: list[dict[str, str]]) -> str:
        """Build DN from list of RDN components.

        Args:
            rdns: List of RDN dictionaries

        Returns:
            Formatted Distinguished Name

        """
        dn_parts = [
            f"{rdn['attribute']}={rdn['value']}"
            for rdn in rdns
            if "attribute" in rdn and "value" in rdn
        ]

        return ",".join(dn_parts)

    @staticmethod
    def get_parent_dn(dn: str) -> str:
        """Get parent DN by removing the first RDN component - delegates to enterprise DN system.

        Args:
            dn: Child DN

        Returns:
            Parent DN or empty string if no parent

        """
        if not dn:
            return ""

        # Delegate to enterprise DN system
        from flext_ldapn import get_dn_parent

        parent = get_dn_parent(dn)
        return parent or ""

    @staticmethod
    def get_rdn(dn: str) -> str:
        """Get the RDN (leftmost component) from DN - delegates to enterprise DN system.

        Args:
            dn: Distinguished Name

        Returns:
            RDN component

        """
        if not dn:
            return ""

        # Delegate to enterprise DN system
        from flext_ldapn import get_dn_rdn

        rdn = get_dn_rdn(dn)
        return rdn or ""

    @staticmethod
    def escape_dn_value(value: str) -> str:
        """Escape special characters in DN value - delegates to enterprise DN system.

        Args:
            value: Value to escape

        Returns:
            Escaped value

        """
        # Delegate to enterprise DN escaping
        from flext_ldapn import escape_dn_value

        return escape_dn_value(value)

    @staticmethod
    def normalize_dn(dn: str) -> str:
        """Normalize DN format for comparison - delegates to enterprise DN system.

        Args:
            dn: DN to normalize

        Returns:
            Normalized DN

        """
        if not dn:
            return ""

        # Delegate to enterprise DN normalization
        from flext_ldapn import normalize_dn

        return normalize_dn(dn)


class FilterHelper:
    """Helper functions for building LDAP search filters."""

    @staticmethod
    def build_and_filter(filters: list[str]) -> str:
        """Build AND filter from list of conditions.

        Args:
            filters: List of filter conditions

        Returns:
            AND filter string

        """
        if not filters:
            return ""
        if len(filters) == 1:
            return filters[0]

        return f"(&{''.join(filters)})"

    @staticmethod
    def build_or_filter(filters: list[str]) -> str:
        """Build OR filter from list of conditions.

        Args:
            filters: List of filter conditions

        Returns:
            OR filter string

        """
        if not filters:
            return ""
        if len(filters) == 1:
            return filters[0]

        return f"(|{''.join(filters)})"

    @staticmethod
    def build_not_filter(filter_expr: str) -> str:
        """Build NOT filter.

        Args:
            filter_expr: Filter expression to negate

        Returns:
            NOT filter string

        """
        return f"(!{filter_expr})"

    @staticmethod
    def build_presence_filter(attribute: str) -> str:
        """Build presence filter (attribute exists).

        Args:
            attribute: Attribute name

        Returns:
            Presence filter string

        """
        return f"({attribute}=*)"

    @staticmethod
    def build_equality_filter(attribute: str, value: str) -> str:
        """Build equality filter.

        Args:
            attribute: Attribute name
            value: Attribute value

        Returns:
            Equality filter string

        """
        escaped_value = FilterHelper.escape_filter_value(value)
        return f"({attribute}={escaped_value})"

    @staticmethod
    def build_substring_filter(
        attribute: str,
        initial: str = "",
        any_parts: list[str] | None = None,
        final: str = "",
    ) -> str:
        """Build substring filter.

        Args:
            attribute: Attribute name
            initial: Initial substring
            any_parts: Middle substrings
            final: Final substring

        Returns:
            Substring filter string

        """
        any_parts = any_parts or []

        parts = []
        if initial:
            parts.append(FilterHelper.escape_filter_value(initial))

        parts.extend(f"*{FilterHelper.escape_filter_value(part)}" for part in any_parts)

        if final:
            if parts:
                parts.append(f"*{FilterHelper.escape_filter_value(final)}")
            else:
                parts.append(f"*{FilterHelper.escape_filter_value(final)}")
        elif parts and not parts[-1].endswith("*"):
            parts.append("*")

        value = "".join(parts)
        return f"({attribute}={value})"

    @staticmethod
    def build_greater_or_equal_filter(attribute: str, value: str) -> str:
        """Build greater-than-or-equal filter.

        Args:
            attribute: Attribute name
            value: Comparison value

        Returns:
            Greater-than-or-equal filter string

        """
        escaped_value = FilterHelper.escape_filter_value(value)
        return f"({attribute}>={escaped_value})"

    @staticmethod
    def build_less_or_equal_filter(attribute: str, value: str) -> str:
        """Build less-than-or-equal filter.

        Args:
            attribute: Attribute name
            value: Comparison value

        Returns:
            Less-than-or-equal filter string

        """
        escaped_value = FilterHelper.escape_filter_value(value)
        return f"({attribute}<={escaped_value})"

    @staticmethod
    def escape_filter_value(value: str) -> str:
        """Escape special characters in filter value according to RFC 2254.

        Args:
            value: Value to escape

        Returns:
            Escaped value

        """
        # Characters that need escaping: ( ) \ * and NUL
        escape_map = {
            "(": "\\28",
            ")": "\\29",
            "\\": "\\5c",
            "*": "\\2a",
            "\x00": "\\00",
        }

        for char, replacement in escape_map.items():
            value = value.replace(char, replacement)

        return value


class AttributeHelper:
    """Helper functions for attribute value processing."""

    @staticmethod
    def is_binary_attribute(attribute_name: str) -> bool:
        """Check if attribute is typically binary.

        Args:
            attribute_name: Name of attribute

        Returns:
            True if attribute is typically binary

        """
        binary_attributes = {
            "userCertificate",
            "caCertificate",
            "certificateRevocationList",
            "crossCertificatePair",
            "objectGUID",
            "objectSid",
            "jpegPhoto",
            "audio",
            "userPassword",
            "unicodePwd",
            "ntPwdHistory",
            "lmPwdHistory",
            "supplementalCredentials",
            "thumbnailPhoto",
            "thumbnailLogo",
            "logonHours",
        }

        return attribute_name.lower() in {attr.lower() for attr in binary_attributes}

    @staticmethod
    def encode_binary_value(value: bytes) -> str:
        """Encode binary value as base64 string.

        Args:
            value: Binary value to encode

        Returns:
            Base64 encoded string

        """
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def decode_binary_value(encoded_value: str) -> bytes:
        """Decode base64 string to binary value.

        Args:
            encoded_value: Base64 encoded string

        Returns:
            Decoded binary value

        """
        return base64.b64decode(encoded_value)

    @staticmethod
    def format_timestamp(timestamp: datetime) -> str:
        """Format datetime as LDAP timestamp string.

        Args:
            timestamp: Datetime object

        Returns:
            LDAP timestamp string (YYYYMMDDHHMMSSZ)

        """
        return timestamp.strftime("%Y%m%d%H%M%SZ")

    @staticmethod
    def parse_timestamp(timestamp_str: str) -> datetime:
        """Parse LDAP timestamp string to datetime.

        Args:
            timestamp_str: LDAP timestamp string

        Returns:
            Datetime object

        """
        # Handle various LDAP timestamp formats
        formats = [
            "%Y%m%d%H%M%SZ",  # YYYYMMDDHHMMSSZ
            "%Y%m%d%H%M%S.%fZ",  # YYYYMMDDHHMMSS.fZ
            "%Y%m%d%H%M%S",  # YYYYMMDDHHMMSS
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue

        msg = f"Unable to parse timestamp: {timestamp_str}"
        raise ValueError(msg)

    @staticmethod
    def normalize_attribute_name(attribute_name: str) -> str:
        """Normalize attribute name for comparison.

        Args:
            attribute_name: Attribute name to normalize

        Returns:
            Normalized attribute name (lowercase)

        """
        return attribute_name.lower().strip()


class LDAPUrlHelper:
    """Helper functions for LDAP URL manipulation."""

    @staticmethod
    def build_ldap_url(
        host: str,
        port: int = LDAP_DEFAULT_PORT,
        base_dn: str = "",
        scope: str = "sub",
        filter_expr: str = "",
        attributes: list[str] | None = None,
        use_ssl: bool = False,
    ) -> str:
        """Build LDAP URL according to RFC 2255.

        Args:
            host: LDAP server hostname
            port: LDAP server port
            base_dn: Base DN for search
            scope: Search scope (base, one, sub)
            filter_expr: Search filter
            attributes: List of attributes to return
            use_ssl: Use LDAPS (SSL/TLS)

        Returns:
            LDAP URL string

        """
        scheme = "ldaps" if use_ssl else "ldap"

        # Basic URL format: ldap://host:port/dn?attributes?scope?filter
        url = f"{scheme}://{host}:{port}/"

        if base_dn:
            url += quote(base_dn, safe=",=")

        # Add query components
        query_parts = []

        # Attributes
        if attributes:
            query_parts.append(",".join(attributes))
        else:
            query_parts.append("")

        # Scope
        query_parts.append(scope)

        # Filter
        if filter_expr:
            query_parts.append(quote(filter_expr, safe="()&|!=<>*"))
        else:
            query_parts.append("")

        if any(query_parts):
            url += "?" + "?".join(query_parts)

        return url

    @staticmethod
    def parse_ldap_url(url: str) -> dict[str, Any]:
        """Parse LDAP URL into components.

        Args:
            url: LDAP URL to parse

        Returns:
            Dictionary with URL components

        """
        from urllib.parse import unquote, urlparse

        parsed = urlparse(url)

        result: dict[str, str | int | bool | list[str]] = {
            "scheme": parsed.scheme,
            "host": parsed.hostname or "",
            "port": parsed.port
            or (LDAPS_DEFAULT_PORT if parsed.scheme == "ldaps" else LDAP_DEFAULT_PORT),
            "base_dn": unquote(parsed.path.lstrip("/") if parsed.path else ""),
            "attributes": [],
            "scope": "sub",
            "filter": "",
        }

        if parsed.query:
            query_parts = parsed.query.split("?")

            # Attributes
            if len(query_parts) > 0 and query_parts[0]:
                result["attributes"] = query_parts[0].split(",")

            # Scope
            if len(query_parts) > 1 and query_parts[1]:
                result["scope"] = query_parts[1]

            # Filter
            if len(query_parts) > 2 and query_parts[2]:
                result["filter"] = unquote(query_parts[2])

        return result


class ValidationHelper:
    """Helper functions for LDAP data validation."""

    @staticmethod
    def is_valid_dn(dn: str) -> bool:
        """Validate DN format.

        Args:
            dn: DN to validate

        Returns:
            True if DN format is valid

        """
        if not dn:
            return False

        try:
            rdns = DNHelper.parse_dn(dn)
            return len(rdns) > 0 and all(
                rdn.get("attribute") and rdn.get("value") for rdn in rdns
            )
        except Exception:
            return False

    @staticmethod
    def is_valid_attribute_name(name: str) -> bool:
        """Validate attribute name format.

        Args:
            name: Attribute name to validate

        Returns:
            True if attribute name is valid

        """
        if not name:
            return False

        # RFC 2252: attribute names must start with letter, contain letters, digits, hyphens
        return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9-]*$", name))

    @staticmethod
    def is_valid_object_class_name(name: str) -> bool:
        """Validate object class name format.

        Args:
            name: Object class name to validate

        Returns:
            True if object class name is valid

        """
        return ValidationHelper.is_valid_attribute_name(name)

    @staticmethod
    def is_valid_oid(oid: str) -> bool:
        """Validate OID format.

        Args:
            oid: OID to validate

        Returns:
            True if OID format is valid

        """
        if not oid:
            return False

        return bool(re.match(r"^[0-9]+(\.[0-9]+)*$", oid))


class ConversionHelper:
    """Helper functions for data type conversions."""

    @staticmethod
    def string_to_boolean(value: str) -> bool:
        """Convert string to boolean using LDAP conventions.

        Args:
            value: String value to convert

        Returns:
            Boolean value

        """
        true_values = {"true", "yes", "1", "on", "enabled"}
        return value.lower().strip() in true_values

    @staticmethod
    def boolean_to_string(value: bool) -> str:
        """Convert boolean to string using LDAP conventions.

        Args:
            value: Boolean value to convert

        Returns:
            String representation

        """
        return "TRUE" if value else "FALSE"

    @staticmethod
    def sid_to_string(sid_bytes: bytes) -> str:
        """Convert Windows SID bytes to string representation.

        Args:
            sid_bytes: Binary SID data

        Returns:
            String SID (S-1-5-...)

        """
        import struct

        if len(sid_bytes) < 8:
            msg = "Invalid SID length"
            raise ValueError(msg)

        # Parse SID structure
        revision = sid_bytes[0]
        sub_authority_count = sid_bytes[1]
        identifier_authority = struct.unpack(">Q", b"\x00\x00" + sid_bytes[2:8])[0]

        sid_string = f"S-{revision}-{identifier_authority}"

        for i in range(sub_authority_count):
            offset = 8 + (i * 4)
            if offset + 4 <= len(sid_bytes):
                sub_authority = struct.unpack("<L", sid_bytes[offset : offset + 4])[0]
                sid_string += f"-{sub_authority}"

        return sid_string

    @staticmethod
    def guid_to_string(guid_bytes: bytes) -> str:
        """Convert GUID bytes to string representation.

        Args:
            guid_bytes: Binary GUID data

        Returns:
            String GUID ({xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx})

        """
        import struct

        if len(guid_bytes) != 16:
            msg = "GUID must be 16 bytes"
            raise ValueError(msg)

        # GUID structure: 4 bytes + 2 bytes + 2 bytes + 8 bytes
        parts = struct.unpack("<LHH8s", guid_bytes)
        guid_string = f"{{{parts[0]:08x}-{parts[1]:04x}-{parts[2]:04x}-{parts[3][:2].hex()}-{parts[3][2:].hex()}}}"

        return guid_string.upper()
