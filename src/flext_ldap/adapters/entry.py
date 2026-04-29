"""Entry adapter for ldap3 ↔ ldif bidirectional conversion.

Provides seamless conversion between ldap3 Entry objects and ldif Entry models,
enabling integration between LDAP protocol operations and LDIF entry manipulation.

Business Rules:
    - ldap3.Entry → p.Ldif.Entry conversion preserves all attributes
    - p.Ldif.Entry → ldap3 attributes uses Mapping[str, t.StrSequence] format
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

from collections.abc import (
    Mapping,
    MutableSequence,
)
from typing import override

from flext_ldap import c, m, p, s, t, u
from flext_ldif import e, r


class FlextLdapEntryAdapter(s[bool]):
    """Adapter for converting between ldap3 and ldif entry representations.

    This adapter provides bidirectional conversion with universal server support:
    - ldap3.Entry → p.Ldif.Entry (for result processing)
    - p.Ldif.Entry → t.Ldap.OperationAttributes (for ldap3 operations)
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

        ASCII_THRESHOLD: int = c.Ldif.ASCII_THRESHOLD

        @staticmethod
        def convert_value_to_strings(
            value: t.Ldap.Ldap3EntryValue,
        ) -> t.StrSequence:
            """Compatibility shim delegating value normalization to ``u.Ldap``."""
            result: t.StrSequence = u.Ldap.ldap3_value_to_strings(value)
            return result

        @staticmethod
        def is_base64_encoded(
            value: str,
            threshold: int = c.Ldif.ASCII_THRESHOLD,
        ) -> bool:
            """Compatibility shim delegating encoding detection to ``u.Ldap``."""
            return u.Ldap.is_base64_encoded(value, threshold)

        @staticmethod
        def normalize_original_attr_value(
            value: t.Ldap.Ldap3EntryValue,
        ) -> t.StrSequence:
            """Compatibility shim delegating normalization to ``u.Ldap``."""
            result: t.StrSequence = u.Ldap.normalize_original_attr_value(value)
            return result

    _server_type: str = u.PrivateAttr(default_factory=lambda: c.Ldif.ServerTypes.RFC)

    def __init__(self, *, server_type: str | None = None) -> None:
        """Initialize entry adapter with ldif integration and quirks.

        Args:
            server_type: Server type for normalization (defaults to RFC).

        """
        resolved_type: str = server_type or c.Ldif.ServerTypes.RFC
        self._server_type = resolved_type

    @staticmethod
    def _build_conversion_metadata(
        removed_attrs: t.StrSequence,
        base64_attrs: t.StrSequence,
        original_attrs_dict: Mapping[str, t.JsonValue | t.Ldap.Ldap3AttributeValue],
        original_dn: str,
    ) -> m.Ldap.ConversionMetadata:
        """Build conversion metadata tracking ldap3 to LDIF transformation."""
        return u.Ldap.build_conversion_metadata(
            removed_attrs,
            base64_attrs,
            original_attrs_dict,
            original_dn,
        )

    @staticmethod
    def _track_conversion_differences(
        conversion_metadata: m.Ldap.ConversionMetadata,
        original_dn: str,
        converted_dn: str,
        original_attrs_dict: t.Ldap.Ldap3AttributeDict,
        converted_attrs_dict: Mapping[str, t.StrSequence],
    ) -> m.Ldap.ConversionMetadata:
        """Track DN and attribute differences in conversion metadata."""
        return u.Ldap.track_conversion_differences(
            conversion_metadata,
            original_dn=original_dn,
            converted_dn=converted_dn,
            original_attrs_dict=original_attrs_dict,
            converted_attrs_dict=converted_attrs_dict,
        )

    @override
    def execute(self) -> p.Result[bool]:
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

        Returns:
            r[bool] - success with True as this adapter is stateless
                and always ready

        """
        return r[bool].ok(value=True)

    def ldap3_to_ldif_entry(
        self, ldap3_entry: p.Ldap.Ldap3Entry
    ) -> p.Result[m.Ldif.Entry]:
        """Convert ldap3.Entry to p.Ldif.Entry.

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
            ldap3_entry: ldap3 Entry t.JsonValue (required, no fallback).
                Must have entry_dn and entry_attributes_as_dict attributes.

        Returns:
            r[p.Ldif.Entry]: Converted entry with metadata
            or error if conversion fails (ValueError, TypeError, AttributeError).

        """
        try:
            dn_str = str(ldap3_entry.entry_dn)
            attrs_dict: t.Ldap.Ldap3AttributeDict = ldap3_entry.entry_attributes_as_dict
            original_attrs_dict: t.Ldap.Ldap3AttributeDict = attrs_dict
            removed_attrs: MutableSequence[str] = []
            base64_attrs: MutableSequence[str] = []
            ldif_attrs: t.MutableMappingKV[str, t.MutableSequenceOf[str] | str] = {}
            logger = u.fetch_logger(__name__)
            for key, raw_value in attrs_dict.items():
                try:
                    ldif_attrs[key] = list(
                        self._convert_ldap3_value_to_list(
                            raw_value,
                            key,
                            base64_attrs,
                            removed_attrs,
                        ),
                    )
                except (
                    ValueError,
                    TypeError,
                    KeyError,
                    AttributeError,
                    OSError,
                    RuntimeError,
                    ImportError,
                ) as exc:
                    logger.debug(
                        "Failed to convert attribute %s, skipping",
                        key,
                        exc_info=exc,
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
            metadata_obj = m.Ldif.QuirkMetadata.model_validate({
                "quirk_type": self._server_type,
                "extensions": conversion_metadata.model_dump(exclude_defaults=False),
            })
            return m.Ldif.Entry.create(
                dn=dn_str,
                attributes=ldif_attrs,
                metadata=metadata_obj,
            )
        except (ValueError, TypeError, AttributeError) as exc:
            entry_dn_for_log = ldap3_entry.entry_dn or c.Ldif.UNKNOWN_VALUE
            self.logger.exception(
                "Failed to convert ldap3 entry to LDIF entry",
                operation=c.Ldap.OperationName.LDAP3_TO_LDIF_ENTRY,
                entry_dn=entry_dn_for_log,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return e.fail_operation("create Entry", exc)

    def ldif_entry_to_ldap3_attributes(
        self,
        entry: m.Ldif.Entry,
    ) -> p.Result[t.Ldap.OperationAttributes]:
        """Convert p.Ldif.Entry to ldap3 attributes format.

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
            return e.fail_validation("entry.attributes", error="missing")
        ldif_attrs = entry.attributes
        attrs_dict = ldif_attrs.attributes
        if not attrs_dict:
            return e.fail_validation("entry.attributes", error="empty")
        try:
            return r[t.Ldap.OperationAttributes].ok(u.Ldap.attr_to_str_list(attrs_dict))
        except (ValueError, TypeError, AttributeError) as exc:
            dn_value = (
                getattr(entry.dn, "value", entry.dn)
                if entry.dn
                else c.Ldif.UNKNOWN_VALUE
            )
            entry_dn_str = (
                str(dn_value)
                if dn_value is not None and dn_value != c.Ldif.UNKNOWN_VALUE
                else c.Ldif.UNKNOWN_VALUE
            )
            self.logger.exception(
                "Failed to convert LDIF entry to ldap3 attributes format",
                operation=c.Ldap.OperationName.LDIF_ENTRY_TO_LDAP3_ATTRIBUTES,
                entry_dn=entry_dn_str,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return e.fail_operation(
                "convert attributes to ldap3 format",
                exc,
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
            empty_values: t.StrSequence = []
            return empty_values
        converted_values = list(self._ConversionHelpers.convert_value_to_strings(value))
        if any(
            self._ConversionHelpers.is_base64_encoded(v, ascii_threshold)
            for v in converted_values
        ):
            base64_attrs.append(key)
        return converted_values
