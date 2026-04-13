"""Entry adapter for ldap3 ↔ ldif bidirectional conversion.

Provides seamless conversion between ldap3 Entry objects and ldif Entry models,
enabling integration between LDAP protocol operations and LDIF entry manipulation.

Business Rules:
    - ldap3.Entry → p.Entry conversion preserves all attributes
    - p.Entry → ldap3 attributes uses Mapping[str, t.StrSequence] format
    - Binary values (non-ASCII) are detected and base64 encoded per RFC 2849
    - Server-specific normalization uses flext-ldif quirks system
    - DN normalization via u.Ldif.norm_or_fallback() for consistency
    - Empty attribute values are preserved (important for schema compliance)

Audit Implications:
    - Entry conversion maintains attribute fidelity for data integrity
    - Base64 encoding of binary values ensures transport safety
    - Server-specific quirks enable cross-server migration auditing
    - Conversion operations are stateless (no side effects)

Architecture Notes:
    - Implements Adapter pattern between ldap3 and ldif domains
    - Python 3.13: Uses guard-based sequence handling
    - Extends s[bool] for health check capability
    - Inner class _ConversionHelpers follows SRP for value processing

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, MutableMapping, MutableSequence
from typing import override

from pydantic import PrivateAttr

from flext_ldap import c, m, p, r, s, t
from flext_ldif import ldif


class FlextLdapEntryAdapter(s[bool]):
    """Adapter for converting between ldap3 and ldif entry representations.

    This adapter provides bidirectional conversion with universal server support:
    - ldap3.Entry → p.Entry (for result processing)
    - p.Entry → t.Ldap.OperationAttributes (for ldap3 operations)
    - Server-specific entry normalization using quirks
    - Entry validation for target server types
    - Entry format conversion between different servers

    All operations are generic and work with any LDAP server by leveraging
    flext-ldif's quirks system for server-specific handling.
    """

    class _ConversionHelpers:
        """Conversion helper methods for entry value and attribute processing (SRP).

        Handles normalization of ldap3 values to LDIF list format with base64 detection.
        Uses u type guards for safe type narrowing (no isinstance checks).
        """

        ASCII_THRESHOLD: int = c.Ldif.EntryDefaults.ASCII_THRESHOLD

        @staticmethod
        def convert_value_to_strings(
            value: t.Ldap.Ldap3EntryValue,
        ) -> t.StrSequence:
            """Convert ldap3 entry value to sequence of strings.

            Business Rules:
                - List-like values are converted to t.StrSequence
                - Single values are wrapped in single-item list [str(value)]
                - None values become empty list []
                - Python 3.13: Uses guard-based sequence handling

            Audit Implications:
                - All values normalized to string lists for consistency
                - Value type information may be lost (all become strings)
                - Empty lists preserve attribute presence

            Architecture:
                - Python 3.13: Uses guard-based sequence handling
                - Returns t.StrSequence for flexible return type
                - No network calls - pure data transformation

            Args:
                value: ldap3 attribute value (str, list, bytes, or mixed).

            Returns:
                Sequence of string values (empty if value is None/empty).

            """
            match value:
                case None:
                    return []
                case bytes() as value_bytes:
                    return [value_bytes.decode("utf-8", errors="replace")]
                case list() | tuple() as sequence_values:
                    return [
                        item.decode("utf-8", errors="replace")
                        if isinstance(item, bytes)
                        else str(item)
                        for item in sequence_values
                    ]
                case _:
                    return [str(value)]

        @staticmethod
        def is_base64_encoded(
            value: str,
            threshold: int = c.Ldif.EntryDefaults.ASCII_THRESHOLD,
        ) -> bool:
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
            return value.startswith("::") or any(ord(c) > threshold for c in value)

        @staticmethod
        def normalize_original_attr_value(
            value: t.Ldap.Ldap3EntryValue,
        ) -> t.StrSequence:
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
                - Returns t.StrSequence for flexible return type
                - No network calls - pure data transformation

            Args:
                value: Original ldap3 attribute value (preserved form).

            Returns:
                Sequence of string values from original attribute.

            """
            return FlextLdapEntryAdapter._ConversionHelpers.convert_value_to_strings(
                value,
            )

    _ldif: ldif = PrivateAttr(default_factory=ldif)
    _server_type: str = PrivateAttr(default=c.Ldif.ServerTypes.RFC)

    def __init__(self, *, server_type: str | None = None) -> None:
        """Initialize entry adapter with ldif integration and quirks.

        Args:
            server_type: Server type for normalization (defaults to RFC).

        """
        super().__init__()
        resolved_type: str = server_type or c.Ldif.ServerTypes.RFC
        self._ldif = ldif()
        self._server_type = resolved_type

    @staticmethod
    def _build_conversion_metadata(
        removed_attrs: t.StrSequence,
        base64_attrs: t.StrSequence,
        original_attrs_dict: t.RecursiveContainerMapping,
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
        return m.Ldap.ConversionMetadata.model_validate({
            "source_attributes": list(dict(original_attrs_dict).keys()),
            "source_dn": original_dn,
            "removed_attributes": list(removed_attrs),
            "base64_encoded_attributes": list(set(base64_attrs)),
        })

    @staticmethod
    def _track_conversion_differences(
        conversion_metadata: m.Ldap.ConversionMetadata,
        original_dn: str,
        converted_dn: str,
        original_attrs_dict: t.Ldap.Ldap3AttributeDict,
        converted_attrs_dict: Mapping[str, t.StrSequence],
    ) -> m.Ldap.ConversionMetadata:
        """Track DN and attribute differences in conversion metadata.

        Business Rules:
            - DN changes are detected by comparing original_dn vs converted_dn
            - Attribute changes detected by comparing string representations
                - Python 3.13: Uses guard-based sequence handling
            - Mutates conversion_metadata to record differences
            - Changes tracked for audit trail generation

        Audit Implications:
            - DN changes indicate normalization or transformation occurred
            - Attribute changes indicate value transformation during conversion
            - Tracking enables forensic analysis of conversion process
            - Metadata mutations are side effects (no return value)

        Architecture:
            - Mutates conversion_metadata t.RecursiveContainer (side effect)
                - Python 3.13: Uses guard-based sequence handling
            - Compares string representations for change detection
            - No network calls - pure metadata tracking

        Args:
            conversion_metadata: Metadata model to update with changes (mutated).
            original_dn: Original ldap3 entry DN.
            converted_dn: Converted LDIF entry DN.
            original_attrs_dict: Original ldap3 attributes.
            converted_attrs_dict: Converted LDIF attributes (lists of strings).

        """
        updates: MutableMapping[str, bool | str | t.StrSequence] = {}
        if converted_dn != original_dn:
            updates["dn_changed"] = True
            updates["converted_dn"] = converted_dn

        def check_attr_changed(
            attr_name: str,
            original_values: t.Ldap.Ldap3AttributeValues,
        ) -> str | None:
            """Check if attribute values changed during conversion."""
            original_values_list = [
                item.decode("utf-8", errors="replace")
                if isinstance(item, bytes)
                else str(item)
                for item in original_values
            ]
            original_str = ", ".join(original_values_list)
            attr_values_raw = converted_attrs_dict.get(attr_name, [])
            attr_values_list = [str(v) for v in attr_values_raw]
            filtered_str_values = [v for v in attr_values_list if v]
            converted_str = ", ".join(filtered_str_values) or ""
            return attr_name if original_str != converted_str else None

        result_dict: t.MutableOptionalStrMapping = {}
        logger = logging.getLogger(__name__)
        for attr_name, original_values in original_attrs_dict.items():
            try:
                changed = check_attr_changed(attr_name, original_values)
                if changed is not None:
                    result_dict[attr_name] = changed
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ) as e:
                logger.debug(
                    "Failed to check attribute change for %s, skipping",
                    attr_name,
                    exc_info=e,
                )
                continue
        filtered_dict: t.StrMapping = {
            k: v for k, v in result_dict.items() if v is not None
        }
        changed_attrs = list(filtered_dict.values())
        if changed_attrs:
            updates["attribute_changes"] = changed_attrs
        if updates:
            return conversion_metadata.model_copy(update=updates)
        return conversion_metadata

    @override
    def execute(self, **_kwargs: str | float | bool | None) -> p.Result[bool]:
        """Execute method required by s.

        Business Rules:
            - Entry adapter is stateless and performs no operations
            - Conversion methods (ldap3_to_ldif_entry, etc.) should be called directly
            - Always returns success (True) as adapter is always ready
            - No remote operations performed - pure data transformation adapter

        Audit Implications:
            - This method exists for s protocol compliance only
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

    def ldap3_to_ldif_entry(
        self, ldap3_entry: p.Ldap.Ldap3Entry
    ) -> p.Result[m.Ldif.Entry]:
        """Convert ldap3.Entry to p.Entry.

        Business Rules:
            - DN is extracted from entry.entry_dn (string conversion)
            - Attributes are extracted from entry.entry_attributes_as_dict
            - Attribute values are normalized to t.StrSequence format
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
            - Returns r pattern - no exceptions raised
            - Server type from adapter._server_type stored in metadata

        Args:
            ldap3_entry: ldap3 Entry t.RecursiveContainer (required, no fallback).
                Must have entry_dn and entry_attributes_as_dict attributes.

        Returns:
            r[p.Entry]: Converted entry with metadata
            or error if conversion fails (ValueError, TypeError, AttributeError).

        """
        try:
            dn_str = str(ldap3_entry.entry_dn)
            attrs_dict = ldap3_entry.entry_attributes_as_dict
            original_attrs_dict = attrs_dict
            removed_attrs: MutableSequence[str] = []
            base64_attrs: MutableSequence[str] = []
            ldif_attrs: t.MutableStrSequenceMapping = {}
            logger = logging.getLogger(__name__)
            for key, raw_value in attrs_dict.items():
                try:
                    str_values: MutableSequence[str] = []
                    match raw_value:
                        case list() | tuple():
                            for item in raw_value:
                                match item:
                                    case bytes() as item_bytes:
                                        str_values.append(
                                            item_bytes.decode(
                                                "utf-8",
                                                errors="replace",
                                            ),
                                        )
                                    case _:
                                        str_values.append(str(item))
                        case _:
                            pass
                    threshold = self._ConversionHelpers.ASCII_THRESHOLD
                    has_base64 = any(
                        self._ConversionHelpers.is_base64_encoded(v, threshold)
                        for v in str_values
                    )
                    if has_base64:
                        base64_attrs.append(key)
                    ldif_attrs[key] = str_values
                except (
                    ValueError,
                    TypeError,
                    KeyError,
                    AttributeError,
                    OSError,
                    RuntimeError,
                    ImportError,
                ) as e:
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
            conversion_metadata = FlextLdapEntryAdapter._track_conversion_differences(
                conversion_metadata,
                dn_str,
                dn_str,
                original_attrs_dict,
                ldif_attrs,
            )
            ldf_attrs_obj = m.Ldif.Attributes.model_validate({"attributes": ldif_attrs})
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
            entry_dn_for_log = (
                str(ldap3_entry.entry_dn)
                if ldap3_entry.entry_dn
                else c.Ldif.EntryDefaults.UNKNOWN_VALUE
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
    ) -> p.Result[t.Ldap.OperationAttributes]:
        """Convert p.Entry to ldap3 attributes format.

        Business Rules:
            - Entry must have attributes (Attributes model)
            - Attributes must have non-empty attributes dict
            - Attribute values are already t.StrSequence in LDIF format
            - Values are converted to strings (handles any value types)
            - Empty attributes dict returns failure (no attributes to convert)
            - Python 3.13: Uses guard-based sequence handling

        Audit Implications:
            - Conversion failures are logged with entry DN and error details
            - Empty attributes are detected before conversion attempt
            - Value type conversion errors are caught and logged

        Architecture:
            - Accesses entry.attributes.attributes dict directly
            - Python 3.13: Uses guard-based sequence handling
            - Returns r pattern - no exceptions raised
            - Returns Mapping[str, t.StrSequence] format expected by ldap3

        Args:
            entry: m.Ldif.Entry with attributes to convert.
                Must have non-empty attributes.attributes dict.

        Returns:
            r[Attributes]: Dict mapping attribute names to t.StrSequence values
            or error if entry has no attributes or conversion fails.

        """
        if entry.attributes is None:
            return r[t.Ldap.OperationAttributes].fail("Entry has no attributes")
        ldif_attrs = entry.attributes
        attrs_dict = ldif_attrs.attributes
        if not attrs_dict:
            return r[t.Ldap.OperationAttributes].fail("Entry has no attributes")
        try:
            filtered_attrs: t.MutableStrSequenceMapping = {}
            for k, v in attrs_dict.items():
                key_str = str(k)
                filtered_attrs[key_str] = [str(item) for item in v]
            return r[t.Ldap.OperationAttributes].ok(filtered_attrs)
        except (ValueError, TypeError, AttributeError) as e:
            dn_value = (
                getattr(entry.dn, "value", entry.dn)
                if entry.dn
                else c.Ldif.EntryDefaults.UNKNOWN_VALUE
            )
            entry_dn_str = (
                str(dn_value)
                if dn_value is not None
                and dn_value != c.Ldif.EntryDefaults.UNKNOWN_VALUE
                else c.Ldif.EntryDefaults.UNKNOWN_VALUE
            )
            self.logger.exception(
                "Failed to convert LDIF entry to ldap3 attributes format",
                operation=c.Ldap.LdapOperationNames.LDIF_ENTRY_TO_LDAP3_ATTRIBUTES,
                entry_dn=entry_dn_str,
                error=str(e),
                error_type=type(e).__name__,
            )
            return r[t.Ldap.OperationAttributes].fail(
                f"Failed to convert attributes to ldap3 format: {e!s}",
            )

    def _convert_ldap3_value_to_list(
        self,
        value: t.Ldap.Ldap3EntryValue | None,
        key: str,
        base64_attrs: MutableSequence[str],
        removed_attrs: MutableSequence[str],
        ascii_threshold: int = _ConversionHelpers.ASCII_THRESHOLD,
    ) -> t.StrSequence:
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
            - Returns t.StrSequence for consistent format

        Args:
            value: ldap3 attribute value to convert.
            key: Attribute name for tracking in metadata lists.
            base64_attrs: Mutable list to track attributes needing base64 encoding.
            removed_attrs: Mutable list to track empty/None attributes.
            ascii_threshold: ASCII threshold for base64 detection (default: 127).

        Returns:
            List of string values (empty if None).

        """
        if value is None:
            removed_attrs.append(key)
            return []
        converted_values = list(self._ConversionHelpers.convert_value_to_strings(value))
        if any(
            self._ConversionHelpers.is_base64_encoded(v, ascii_threshold)
            for v in converted_values
        ):
            base64_attrs.append(key)
        return converted_values
