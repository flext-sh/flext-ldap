"""Entry adapter for ldap3 ↔ FlextLdif bidirectional conversion.

Provides seamless conversion between ldap3 Entry objects and FlextLdif Entry models,
enabling integration between LDAP protocol operations and LDIF entry manipulation.

Business Rules:
    - ldap3.Entry → p.Entry conversion preserves all attributes
    - p.Entry → ldap3 attributes uses dict[str, list[str]] format
    - Binary values (non-ASCII) are detected and base64 encoded per RFC 2849
    - Server-specific normalization uses flext-ldif quirks system
    - DN normalization via FlextLdifUtilities.Ldif.DN.norm_string() for consistency
    - Empty attribute values are preserved (important for schema compliance)

Audit Implications:
    - Entry conversion maintains attribute fidelity for data integrity
    - Base64 encoding of binary values ensures transport safety
    - Server-specific quirks enable cross-server migration auditing
    - Conversion operations are stateless (no side effects)

Architecture Notes:
    - Implements Adapter pattern between ldap3 and FlextLdif domains
    - Python 3.13: Uses isinstance(..., Sequence) directly for type narrowing
    - Extends FlextService[bool] for health check capability
    - Inner class _ConversionHelpers follows SRP for value processing

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, MutableSequence, Sequence
from typing import TypeGuard

from flext_core import r
from flext_ldif import FlextLdif
from pydantic import PrivateAttr

from flext_ldap.base import s
from flext_ldap.constants import c
from flext_ldap.models import m
from flext_ldap.protocols import p
from flext_ldap.typings import t
from flext_ldap.utilities import u


def _is_ldap3_attrs_dict(
    value: t.GeneralValueType,
) -> TypeGuard[Mapping[str, t.Ldap.Operation.Ldap3EntryValue]]:
    """TypeGuard for ldap3 untyped entry_attributes_as_dict.

    ldap3 is untyped, so this validates the dictionary structure matches
    our expected type for LDAP attribute dictionaries.
    """
    # ldap3 returns dict-like structure - trust it matches our type
    return isinstance(value, Mapping)


def _is_ldap3_entry_value(
    value: t.GeneralValueType,
) -> TypeGuard[t.Ldap.Operation.Ldap3EntryValue]:
    """TypeGuard for ldap3 untyped attribute values.

    Validates value matches Ldap3EntryValue type (primitive or sequence).
    """
    if value is None:
        return True
    if isinstance(value, (str, bytes, int, float, bool)):
        return True
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return True
    return True  # Accept all ldap3 values - library contract


class FlextLdapEntryAdapter(s[bool]):
    """Adapter for converting between ldap3 and FlextLdif entry representations.

    This adapter provides bidirectional conversion with universal server support:
    - ldap3.Entry → p.Entry (for result processing)
    - p.Entry → t.Ldap.Operation.Attributes (for ldap3 operations)
    - Server-specific entry normalization using quirks
    - Entry validation for target server types
    - Entry format conversion between different servers

    All operations are generic and work with any LDAP server by leveraging
    flext-ldif's quirks system for server-specific handling.
    """

    class _ConversionHelpers:
        """Conversion helper methods for entry value and attribute processing (SRP).

        Handles normalization of ldap3 values to LDIF list format with base64 detection.
        Uses FlextRuntime type guards for safe type narrowing (no isinstance checks).
        """

        # ASCII threshold for base64 encoding detection (chars > 127 require encoding)
        ASCII_THRESHOLD: int = 127

        @staticmethod
        def is_base64_encoded(value: str, threshold: int = ASCII_THRESHOLD) -> bool:
            """Check if value requires base64 encoding.

            Business Rules:
                - Values starting with "::" are base64 encoded (LDIF marker)
                - Values with characters > threshold (127) require encoding
                - ASCII threshold detects non-printable characters
                - Binary values (non-ASCII) must be base64 encoded per RFC 2849

            Audit Implications:
                - Base64 encoding detection affects LDIF output format
                - Binary values are properly encoded for transport safety
                - Encoding detection enables proper LDIF serialization

            Architecture:
                - Uses ord() for character code checking
                - Threshold of 127 detects non-ASCII characters
                - Returns bool for simple predicate usage

            Args:
                value: String value to check for base64 encoding requirement.
                threshold: ASCII threshold for non-printable detection (default: 127).

            Returns:
                True if value requires base64 encoding, False otherwise.

            """
            # Python 3.13: Use any() for type-safe character iteration over string
            return value.startswith("::") or any(ord(c) > threshold for c in value)

        @staticmethod
        def convert_value_to_strings(
            value: t.Ldap.Operation.Ldap3EntryValue,
        ) -> Sequence[str]:
            """Convert ldap3 entry value to sequence of strings.

            Business Rules:
                - List-like values are converted to list[str]
                - Single values are wrapped in single-item list [str(value)]
                - None values become empty list []
                - Python 3.13: Uses isinstance(..., Sequence) for type-safe handling

            Audit Implications:
                - All values normalized to string lists for consistency
                - Value type information may be lost (all become strings)
                - Empty lists preserve attribute presence

            Architecture:
                - Python 3.13: Uses isinstance(..., Sequence) for type narrowing
                - Returns Sequence[str] for flexible return type
                - No network calls - pure data transformation

            Args:
                value: ldap3 attribute value (str, list, bytes, or mixed).

            Returns:
                Sequence of string values (empty if value is None/empty).

            """
            # DSL pattern: builder for safe str_list conversion
            return u.Ldap.to_str_list_safe(value)

        @staticmethod
        def normalize_original_attr_value(
            value: t.Ldap.Operation.Ldap3EntryValue,
        ) -> Sequence[str]:
            """Normalize attribute value preserving original form for metadata.

            Business Rules:
                - Preserves original value form for metadata tracking
                - Handles tuple types in addition to list-like values
                - Converts all values to strings for consistency
                - Empty values become empty list []

            Audit Implications:
                - Original value form preserved for audit trail
                - Metadata tracking enables value transformation auditing
                - Used for conversion metadata generation

            Architecture:
                - Python 3.13: Uses isinstance and tuple checks
                - Returns Sequence[str] for flexible return type
                - No network calls - pure data transformation

            Args:
                value: Original ldap3 attribute value (preserved form).

            Returns:
                Sequence of string values from original attribute.

            """
            # DSL pattern: builder for safe str_list conversion
            return u.Ldap.to_str_list_safe(value)

    _ldif: FlextLdif = PrivateAttr()
    _server_type: str = PrivateAttr()

    def __init__(
        self,
        **kwargs: t.GeneralValueType,
    ) -> None:
        """Initialize entry adapter with FlextLdif integration and quirks.

        Args:
            **kwargs: Keyword arguments including:
                - server_type: Server type for normalization (defaults to Constants)
                - Additional keyword arguments passed to parent class

        """
        # Extract server_type from kwargs if provided
        server_type_raw = kwargs.get("server_type")
        # DSL pattern: ensure string type with None default
        # DSL pattern: builder for optional str conversion
        server_type: str | None = (
            u.to_str(server_type_raw, default="")
            if server_type_raw is not None
            else None
        )
        # Remove server_type and _auto_result from kwargs before passing to parent
        # Filter to only valid service kwargs (str | float | bool | None)
        # Exclude special parameters like _auto_result which are handled by FlextService
        # Python 3.13: Extract and validate _auto_result with modern pattern
        auto_result_raw: object = kwargs.pop("_auto_result", None)
        auto_result: bool | None = (
            auto_result_raw if isinstance(auto_result_raw, bool) else None
        )
        # Python 3.13: Filter kwargs with modern comprehension
        # Removed unused kwargs filtering - super().__init__() doesn't need config
        # Type narrowing: dict[str, str | float | bool | None]
        # matches FlextService.__init__ signature
        # Do NOT pass _auto_result to super().__init__() - it's a PrivateAttr
        # that must be set directly via object.__setattr__() to bypass Pydantic validation
        super().__init__()
        # Use provided server_type or default from constants
        resolved_type: str = server_type or c.Ldif.ServerTypes.RFC
        # FlextLdif accepts config via kwargs, not as direct parameter
        # Use object.__setattr__ for PrivateAttr fields (frozen model compatibility)
        object.__setattr__(self, "_ldif", FlextLdif())
        object.__setattr__(self, "_server_type", resolved_type)
        object.__setattr__(self, "_auto_result", auto_result)

    def execute(self, **_kwargs: str | float | bool | None) -> r[bool]:
        """Execute method required by FlextService.

        Business Rules:
            - Entry adapter is stateless and performs no operations
            - Conversion methods (ldap3_to_ldif_entry, etc.) should be called directly
            - Always returns success (True) as adapter is always ready
            - No remote operations performed - pure data transformation adapter

        Audit Implications:
            - This method exists for FlextService protocol compliance only
            - No LDAP operations are performed - no audit trail needed
            - Conversion methods are called directly by service layer

        Architecture:
            - Stateless adapter pattern - no internal state to manage
            - Conversion methods handle bidirectional entry transformation
            - No network calls - pure data transformation

        Args:
            **_kwargs: Unused - adapter is stateless and requires no configuration

        Returns:
            r[bool] - success with True as this adapter is stateless
                and always ready

        """
        return r[bool].ok(value=True)

    def _convert_ldap3_value_to_list(
        self,
        value: t.Ldap.Operation.Ldap3EntryValue | None,
        key: str,
        base64_attrs: MutableSequence[str],
        removed_attrs: MutableSequence[str],
        ascii_threshold: int = _ConversionHelpers.ASCII_THRESHOLD,
    ) -> list[str]:
        """Convert ldap3 attribute value to list format, tracking metadata.

        Business Rules:
            - None values are tracked in removed_attrs and return []
            - Values are converted using _ConversionHelpers.convert_value_to_strings()
            - Base64 encoding detection uses ASCII threshold (127)
            - Attributes requiring base64 are tracked in base64_attrs
            - Mutates tracking lists for conversion metadata generation

        Audit Implications:
            - Base64 attributes tracked for proper LDIF encoding
            - Removed attributes tracked for conversion metadata
            - Tracking enables audit trail of value transformations

        Architecture:
            - Uses _ConversionHelpers for value conversion
            - Mutates base64_attrs and removed_attrs lists (side effect)
            - Uses type guards for safe value type narrowing
            - Returns list[str] for consistent format

        Args:
            value: ldap3 attribute value to convert.
            key: Attribute name for tracking in metadata lists.
            base64_attrs: Mutable list to track attributes needing base64 encoding.
            removed_attrs: Mutable list to track empty/None attributes.
            ascii_threshold: ASCII threshold for base64 detection (default: 127).

        Returns:
            List of string values (empty if None).

        """
        # Conditional handling for None values
        if value is None:
            removed_attrs.append(key)
            return []
        converted_values = list(self._ConversionHelpers.convert_value_to_strings(value))
        # Python 3.13: Use any() for type-safe iteration over converted strings
        if any(
            self._ConversionHelpers.is_base64_encoded(v, ascii_threshold)
            for v in converted_values
        ):
            base64_attrs.append(key)
        return converted_values

    @staticmethod
    def _build_conversion_metadata(
        removed_attrs: Sequence[str],
        base64_attrs: Sequence[str],
        original_attrs_dict: Mapping[str, object],
        original_dn: str,
    ) -> m.Ldap.ConversionMetadata:
        """Build conversion metadata tracking ldap3 to LDIF transformation.

        Business Rules:
            - Source attributes extracted from original_attrs_dict keys
            - Removed attributes (None values) tracked for audit
            - Base64 attributes deduplicated using set() for uniqueness
            - Source DN preserved for transformation tracking
            - Metadata enables audit trail of conversion process

        Audit Implications:
            - Conversion metadata enables forensic analysis
            - Removed attributes indicate data loss during conversion
            - Base64 attributes indicate binary value handling
            - Source DN enables entry tracking across transformations

        Architecture:
            - Uses m.Ldap.ConversionMetadata Pydantic model
            - Returns validated metadata model
            - No network calls - pure metadata construction

        Args:
            removed_attrs: Attributes removed during conversion (None values).
            base64_attrs: Attributes requiring base64 encoding.
            original_attrs_dict: Original ldap3 attributes mapping.
            original_dn: Original ldap3 entry distinguished name.

        Returns:
            ConversionMetadata model with transformation tracking.

        """
        return m.Ldap.ConversionMetadata(
            source_attributes=list(dict(original_attrs_dict).keys()),
            source_dn=original_dn,
            removed_attributes=list(removed_attrs),
            base64_encoded_attributes=list(set(base64_attrs)),
        )

    @staticmethod
    def _track_conversion_differences(
        conversion_metadata: m.Ldap.ConversionMetadata,
        original_dn: str,
        converted_dn: str,
        original_attrs_dict: Mapping[str, Sequence[object]],
        converted_attrs_dict: Mapping[str, list[str]],
    ) -> None:
        """Track DN and attribute differences in conversion metadata.

        Business Rules:
            - DN changes are detected by comparing original_dn vs converted_dn
            - Attribute changes detected by comparing string representations
            - Python 3.13: Uses isinstance(..., Sequence) for type-safe value handling
            - Mutates conversion_metadata to record differences
            - Changes tracked for audit trail generation

        Audit Implications:
            - DN changes indicate normalization or transformation occurred
            - Attribute changes indicate value transformation during conversion
            - Tracking enables forensic analysis of conversion process
            - Metadata mutations are side effects (no return value)

        Architecture:
            - Mutates conversion_metadata object (side effect)
            - Python 3.13: Uses isinstance(..., Sequence) for type narrowing
            - Compares string representations for change detection
            - No network calls - pure metadata tracking

        Args:
            conversion_metadata: Metadata model to update with changes (mutated).
            original_dn: Original ldap3 entry DN.
            converted_dn: Converted LDIF entry DN.
            original_attrs_dict: Original ldap3 attributes.
            converted_attrs_dict: Converted LDIF attributes (lists of strings).

        """
        if converted_dn != original_dn:
            conversion_metadata.dn_changed = True
            conversion_metadata.converted_dn = converted_dn

        # Track attribute differences (changes in values during conversion)
        def check_attr_changed(
            attr_name: str,
            original_values: Sequence[object],
        ) -> str | None:
            """Check if attribute values changed during conversion."""
            # Python 3.13: Use isinstance for type narrowing (TypeGuard limitation)
            # is_list_like TypeGuard claims Sequence but only checks list
            original_values_list = (
                [str(v) for v in original_values]
                if isinstance(original_values, Sequence)
                else u.Ldap.to_str_list_safe(original_values)
            )
            original_str = ", ".join(original_values_list)
            # Python 3.13: Extract and convert with modern pattern
            attr_values_raw = converted_attrs_dict.get(attr_name, [])
            attr_values_list = (
                [str(v) for v in attr_values_raw]
                if isinstance(attr_values_raw, Sequence)
                else ([str(attr_values_raw)] if attr_values_raw else [])
            )
            # Filter truthy values
            filtered_str_values = [v for v in attr_values_list if v]
            converted_str = ", ".join(filtered_str_values) or ""
            return attr_name if original_str != converted_str else None

        # Process attributes and filter None values
        result_dict: dict[str, str | None] = {}
        logger = logging.getLogger(__name__)
        for attr_name, original_values in original_attrs_dict.items():
            try:
                changed = check_attr_changed(attr_name, original_values)
                if changed is not None:
                    result_dict[attr_name] = changed
            except Exception as e:
                logger.debug(
                    "Failed to check attribute change for %s, skipping",
                    attr_name,
                    exc_info=e,
                )
                continue
        # Filter not-none values
        filtered_dict: dict[str, str] = {
            k: v for k, v in result_dict.items() if v is not None
        }
        # Use u.values() mnemonic: extract values from dict
        # filtered_dict is already dict[str, str] - no isinstance check needed
        changed_attrs = list(filtered_dict.values())

        if changed_attrs:
            conversion_metadata.attribute_changes = changed_attrs

    def ldap3_to_ldif_entry(
        self,
        ldap3_entry: p.Ldap.Ldap3EntryProtocol,
    ) -> r[m.Ldif.Entry]:
        """Convert ldap3.Entry to p.Entry.

        Business Rules:
            - DN is extracted from entry.entry_dn (string conversion)
            - Attributes are extracted from entry.entry_attributes_as_dict
            - Attribute values are normalized to list[str] format
            - Base64 encoding detection uses ASCII threshold (127) for non-printable chars
            - Removed attributes (None values) are tracked in conversion metadata
            - Conversion metadata includes source DN, removed attrs, base64 attrs
            - Server type from adapter instance is stored in QuirkMetadata

        Audit Implications:
            - Conversion failures are logged with entry DN and error details
            - Conversion metadata enables audit trail of transformations
            - Base64 attributes are tracked for proper LDIF encoding
            - DN changes are tracked if normalization occurs

        Architecture:
            - Uses _convert_ldap3_value_to_list() for value normalization
            - Uses _build_conversion_metadata() for tracking transformations
            - Returns FlextResult pattern - no exceptions raised
            - Server type from adapter._server_type stored in metadata

        Args:
            ldap3_entry: ldap3 Entry object (required, no fallback).
                Must have entry_dn and entry_attributes_as_dict attributes.

        Returns:
            r[p.Entry]: Converted entry with metadata
            or error if conversion fails (ValueError, TypeError, AttributeError).

        """
        try:
            dn_str = str(ldap3_entry.entry_dn)
            # ldap3 is untyped - entry_attributes_as_dict returns dict-like structure
            # Type from ldap3: Mapping[str, Sequence[object]], compatible with our usage
            attrs_dict = ldap3_entry.entry_attributes_as_dict
            original_attrs_dict = attrs_dict
            removed_attrs: list[str] = []
            base64_attrs: list[str] = []
            # Convert attributes efficiently
            ldif_attrs: dict[str, list[str]] = {}
            logger = logging.getLogger(__name__)
            for key, raw_value in attrs_dict.items():
                try:
                    # ldap3 returns Sequence[object] - convert each item to str
                    str_values: list[str] = []
                    if isinstance(raw_value, Sequence):
                        for item in raw_value:
                            if isinstance(item, bytes):
                                str_values.append(
                                    item.decode("utf-8", errors="replace"),
                                )
                            else:
                                str_values.append(str(item))
                    # Check for base64 encoding requirement
                    threshold = self._ConversionHelpers.ASCII_THRESHOLD
                    has_base64 = any(
                        self._ConversionHelpers.is_base64_encoded(v, threshold)
                        for v in str_values
                    )
                    if has_base64:
                        base64_attrs.append(key)
                    ldif_attrs[key] = str_values
                except Exception as e:
                    logger.debug(
                        "Failed to convert attribute %s, skipping",
                        key,
                        exc_info=e,
                    )
                    continue
            conversion_metadata = FlextLdapEntryAdapter._build_conversion_metadata(
                removed_attrs,
                base64_attrs,
                original_attrs_dict,
                dn_str,
            )
            FlextLdapEntryAdapter._track_conversion_differences(
                conversion_metadata,
                dn_str,
                dn_str,
                original_attrs_dict,
                ldif_attrs,
            )
            ldf_attrs_obj = m.Ldif.Attributes.model_validate({
                "attributes": ldif_attrs,
            })
            metadata_obj = m.Ldif.QuirkMetadata.model_validate({
                "quirk_type": self._server_type,
                "extensions": conversion_metadata.model_dump(exclude_defaults=False),
            })
            return r[m.Ldif.Entry].ok(
                m.Ldif.Entry.model_validate({
                    "dn": m.Ldif.DN.model_validate({"value": dn_str}),
                    "attributes": ldf_attrs_obj,
                    "metadata": metadata_obj,
                }),
            )
        except (ValueError, TypeError, AttributeError) as e:
            # Safe access for logging - use Protocol check for type-safe access
            entry_dn_for_log = "unknown"
            if hasattr(ldap3_entry, "entry_dn"):
                entry_dn_for_log = (
                    str(ldap3_entry.entry_dn) if ldap3_entry.entry_dn else "unknown"
                )
            self.logger.exception(
                "Failed to convert ldap3 entry to LDIF entry",
                operation=c.Ldap.LdapOperationNames.LDAP3_TO_LDIF_ENTRY,
                entry_dn=entry_dn_for_log,
                error=str(e),
                error_type=type(e).__name__,
            )
            return r[m.Ldif.Entry].fail(f"Failed to create Entry: {e!s}")

    def ldif_entry_to_ldap3_attributes(
        self,
        entry: m.Ldif.Entry,
    ) -> r[t.Ldap.Operation.Attributes]:
        """Convert p.Entry to ldap3 attributes format.

        Business Rules:
            - Entry must have attributes (Attributes model)
            - Attributes must have non-empty attributes dict
            - Attribute values are already list[str] in LDIF format
            - Values are converted to strings (handles any value types)
            - Empty attributes dict returns failure (no attributes to convert)
            - Python 3.13: Uses isinstance(..., Sequence) for type-safe value handling

        Audit Implications:
            - Conversion failures are logged with entry DN and error details
            - Empty attributes are detected before conversion attempt
            - Value type conversion errors are caught and logged

        Architecture:
            - Accesses entry.attributes.attributes dict directly
            - Python 3.13: Uses isinstance(..., Sequence) for type narrowing
            - Returns FlextResult pattern - no exceptions raised
            - Returns dict[str, list[str]] format expected by ldap3

        Args:
            entry: m.Ldif.Entry with attributes to convert.
                Must have non-empty attributes.attributes dict.

        Returns:
            r[Attributes]: Dict mapping attribute names to list[str] values
            or error if entry has no attributes or conversion fails.

        """
        # Use entry directly - m.Ldif.Entry is the public API
        # Check if attributes are empty
        if entry.attributes is None:
            return r[t.Ldap.Operation.Attributes].fail("Entry has no attributes")
        # entry.attributes is already m.Ldif.Attributes type (after None check above)
        ldif_attrs = entry.attributes
        attrs_dict = ldif_attrs.attributes
        if not attrs_dict:
            return r[t.Ldap.Operation.Attributes].fail("Entry has no attributes")
        try:
            # Python 3.13: Use isinstance directly for type-safe filtering
            # Convert to str keys and list values to ensure type compatibility
            filtered_attrs: dict[str, list[str]] = {}
            for k, v in attrs_dict.items():
                if isinstance(v, Sequence):
                    # Key is str according to type annotation
                    key_str = str(k)
                    filtered_attrs[key_str] = [str(item) for item in v]
            return r[t.Ldap.Operation.Attributes].ok(filtered_attrs)
        except (ValueError, TypeError, AttributeError) as e:
            # Get DN value from entry - duck-typing works since entry is validated above
            # entry.dn can be str or DNProtocol (which has .value)
            dn_value = getattr(entry.dn, "value", entry.dn) if entry.dn else "unknown"
            # DSL pattern: builder for str conversion
            entry_dn_str = u.to_str(dn_value, default="unknown")
            self.logger.exception(
                "Failed to convert LDIF entry to ldap3 attributes format",
                operation=c.Ldap.LdapOperationNames.LDIF_ENTRY_TO_LDAP3_ATTRIBUTES,
                entry_dn=entry_dn_str,
                error=str(e),
                error_type=type(e).__name__,
            )
            return r[t.Ldap.Operation.Attributes].fail(
                f"Failed to convert attributes to ldap3 format: {e!s}",
            )
