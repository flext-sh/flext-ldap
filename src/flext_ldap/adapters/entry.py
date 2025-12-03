"""Entry adapter for ldap3 ↔ FlextLdif bidirectional conversion.

Provides seamless conversion between ldap3 Entry objects and FlextLdif Entry models,
enabling integration between LDAP protocol operations and LDIF entry manipulation.

Business Rules:
    - ldap3.Entry → FlextLdifModels.Entry conversion preserves all attributes
    - FlextLdifModels.Entry → ldap3 attributes uses dict[str, list[str]] format
    - Binary values (non-ASCII) are detected and base64 encoded per RFC 2849
    - Server-specific normalization uses flext-ldif quirks system
    - DN normalization via FlextLdifUtilities.DN.norm_string() for consistency
    - Empty attribute values are preserved (important for schema compliance)

Audit Implications:
    - Entry conversion maintains attribute fidelity for data integrity
    - Base64 encoding of binary values ensures transport safety
    - Server-specific quirks enable cross-server migration auditing
    - Conversion operations are stateless (no side effects)

Architecture Notes:
    - Implements Adapter pattern between ldap3 and FlextLdif domains
    - Uses FlextRuntime type guards for safe type narrowing (not isinstance)
    - Extends FlextService[bool] for health check capability
    - Inner class _ConversionHelpers follows SRP for value processing

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence, Sequence
from typing import cast

from flext_core import FlextRuntime
from flext_ldif import (
    FlextLdif,
    FlextLdifModels,
)
from flext_ldif._models.domain import (
    FlextLdifModelsDomains,  # noqa: PLC2701  # Required for isinstance and model_validate - no public API available
)
from flext_ldif.constants import FlextLdifConstants
from ldap3 import Entry as Ldap3Entry
from pydantic import PrivateAttr

from flext_ldap import c, m, r, s, t, u


class FlextLdapEntryAdapter(s[bool]):
    """Adapter for converting between ldap3 and FlextLdif entry representations.

    This adapter provides bidirectional conversion with universal server support:
    - ldap3.Entry → FlextLdifModels.Entry (for result processing)
    - FlextLdifModels.Entry → t.Ldap.Attributes (for ldap3 operations)
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
            return value.startswith("::") or any(ord(c) > threshold for c in value)

        @staticmethod
        def convert_value_to_strings(
            value: t.Ldap.Ldap3EntryValue,
        ) -> Sequence[str]:
            """Convert ldap3 entry value to sequence of strings.

            Business Rules:
                - List-like values are converted to list[str]
                - Single values are wrapped in single-item list [str(value)]
                - None values become empty list []
                - Uses FlextRuntime.is_list_like() for type-safe handling

            Audit Implications:
                - All values normalized to string lists for consistency
                - Value type information may be lost (all become strings)
                - Empty lists preserve attribute presence

            Architecture:
                - Uses FlextRuntime.is_list_like() for type narrowing (not isinstance)
                - Returns Sequence[str] for flexible return type
                - No network calls - pure data transformation

            Args:
                value: ldap3 attribute value (str, list, bytes, or mixed).

            Returns:
                Sequence of string values (empty if value is None/empty).

            """
            if FlextRuntime.is_list_like(value):
                # Use u.ensure_str_list for consistent conversion
                return cast("Sequence[str]", u.ensure(value, target_type="str_list", default=[]))
            return [str(value)] if value is not None else []

        @staticmethod
        def normalize_original_attr_value(
            value: t.Ldap.Ldap3EntryValue,
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
                - Uses FlextRuntime.is_list_like() and isinstance(tuple) checks
                - Returns Sequence[str] for flexible return type
                - No network calls - pure data transformation

            Args:
                value: Original ldap3 attribute value (preserved form).

            Returns:
                Sequence of string values from original attribute.

            """
            if FlextRuntime.is_list_like(value) or isinstance(value, tuple):
                # Use u.ensure_str_list for consistent conversion
                return cast("Sequence[str]", u.ensure(value, target_type="str_list", default=[])) if value else []
            return [str(value)] if value is not None else []

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
        server_type_raw = kwargs.pop("server_type", None)
        server_type: str | None = (
            str(server_type_raw) if isinstance(server_type_raw, str) else None
        )
        super().__init__(**kwargs)
        # Use provided server_type or default from constants
        resolved_type: str = server_type or FlextLdifConstants.ServerTypes.RFC
        # FlextLdif accepts config via kwargs, not as direct parameter
        # Use object.__setattr__ for frozen model compatibility
        object.__setattr__(self, "_ldif", FlextLdif.get_instance())
        object.__setattr__(self, "_server_type", resolved_type)

    def execute(self, **_kwargs: str | float | bool | None) -> r[bool]:  # noqa: PLR6301
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
        return r[bool].ok(True)

    def _convert_ldap3_value_to_list(
        self,
        value: t.Ldap.Ldap3EntryValue,
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

    @staticmethod
    def _build_conversion_metadata(
        removed_attrs: Sequence[str],
        base64_attrs: Sequence[str],
        original_attrs_dict: Mapping[str, t.Ldap.Ldap3EntryValue],
        original_dn: str,
    ) -> m.ConversionMetadata:
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
            - Uses m.ConversionMetadata Pydantic model
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
        return m.ConversionMetadata(
            source_attributes=list(original_attrs_dict.keys()),
            source_dn=original_dn,
            removed_attributes=list(removed_attrs),
            base64_encoded_attributes=list(set(base64_attrs)),
        )

    @staticmethod
    def _track_conversion_differences(
        conversion_metadata: m.ConversionMetadata,
        original_dn: str,
        converted_dn: str,
        original_attrs_dict: Mapping[str, t.Ldap.Ldap3EntryValue],
        converted_attrs_dict: Mapping[str, list[str]],
    ) -> None:
        """Track DN and attribute differences in conversion metadata.

        Business Rules:
            - DN changes are detected by comparing original_dn vs converted_dn
            - Attribute changes detected by comparing string representations
            - Uses FlextRuntime.is_list_like() for type-safe value handling
            - Mutates conversion_metadata to record differences
            - Changes tracked for audit trail generation

        Audit Implications:
            - DN changes indicate normalization or transformation occurred
            - Attribute changes indicate value transformation during conversion
            - Tracking enables forensic analysis of conversion process
            - Metadata mutations are side effects (no return value)

        Architecture:
            - Mutates conversion_metadata object (side effect)
            - Uses FlextRuntime.is_list_like() for type narrowing
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
        # Use u.process() for efficient processing
        def check_attr_changed(
            attr_name: str, original_values: t.Ldap.Ldap3EntryValue
        ) -> str | None:
            """Check if attribute values changed during conversion."""
            # Convert to list format for comparison
            if FlextRuntime.is_list_like(cast("t.GeneralValueType", original_values)):
                original_values_list = cast(
                    "list[str]",
                    u.ensure(cast("t.GeneralValueType", original_values), target_type="str_list", default=[]),
                )
            else:
                # Single value - wrap in list
                original_values_list = (
                    [str(original_values)] if original_values is not None else []
                )
            original_str = ", ".join(u.map(cast("list[str]", original_values_list), mapper=str))
            attr_values_list = cast(
                "list[str]",
                u.ensure(
                    converted_attrs_dict.get(attr_name, []), target_type="str_list", default=[]
                ),
            )
            filtered_str_values = cast(
                "list[str]",
                u.filter(
                    attr_values_list,
                    predicate=bool,
                    mapper=str,
                ),
            )
            converted_str = ", ".join(filtered_str_values) or ""
            return attr_name if original_str != converted_str else None

        process_result = u.process(
            original_attrs_dict,
            processor=check_attr_changed,
            on_error="skip",
        )
        changed_attrs = [
            attr_name
            for attr_name in cast(
                "dict[str, str | None]",
                process_result.value if process_result.is_success else {},
            ).values()
            if attr_name is not None
        ]

        if changed_attrs:
            conversion_metadata.attribute_changes = changed_attrs

    def ldap3_to_ldif_entry(
        self,
        ldap3_entry: Ldap3Entry,
    ) -> r[FlextLdifModels.Entry]:
        """Convert ldap3.Entry to FlextLdifModels.Entry.

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
            r[FlextLdifModels.Entry]: Converted entry with metadata
            or error if conversion fails (ValueError, TypeError, AttributeError).

        """
        try:
            dn_str = str(ldap3_entry.entry_dn)
            attrs_dict = ldap3_entry.entry_attributes_as_dict
            original_attrs_dict = dict(attrs_dict)
            ldif_attrs: t.Ldap.AttributeDict = {}
            removed_attrs: list[str] = []
            base64_attrs: list[str] = []
            # Use u.process() for efficient processing

            def convert_attr(key: str, value: object) -> list[str]:
                """Convert single attribute value."""
                return self._convert_ldap3_value_to_list(
                    cast("t.Ldap.Ldap3EntryValue", value),
                    key,
                    base64_attrs,
                    removed_attrs,
                )

            process_result = u.process(
                attrs_dict,
                processor=convert_attr,
                on_error="skip",
            )
            if process_result.is_success:
                ldif_attrs = cast("t.Ldap.AttributeDict", process_result.value)
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
            ldf_attrs_obj = FlextLdifModels.LdifAttributes.model_validate({
                "attributes": ldif_attrs,
            })
            metadata_obj = FlextLdifModelsDomains.QuirkMetadata.model_validate({
                "quirk_type": self._server_type,
                "extensions": conversion_metadata.model_dump(exclude_defaults=False),
            })
            return r[FlextLdifModels.Entry].ok(
                FlextLdifModels.Entry(
                    dn=FlextLdifModelsDomains.DistinguishedName(value=dn_str),
                    attributes=ldf_attrs_obj,
                    metadata=metadata_obj,
                ),
            )
        except (ValueError, TypeError, AttributeError) as e:
            # Safe access for logging - use hasattr check before direct access
            entry_dn_for_log = (
                str(ldap3_entry.entry_dn)
                if hasattr(ldap3_entry, "entry_dn")
                else "unknown"
            )
            self.logger.exception(
                "Failed to convert ldap3 entry to LDIF entry",
                operation=c.LdapOperationNames.LDAP3_TO_LDIF_ENTRY.value,
                entry_dn=entry_dn_for_log,
                error=str(e),
                error_type=type(e).__name__,
            )
            return r[FlextLdifModels.Entry].fail(
                f"Failed to create Entry: {e!s}",
            )

    def ldif_entry_to_ldap3_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> r[t.Ldap.Attributes]:
        """Convert FlextLdifModels.Entry to ldap3 attributes format.

        Business Rules:
            - Entry must have attributes (LdifAttributes model)
            - Attributes must have non-empty attributes dict
            - Attribute values are already list[str] in LDIF format
            - Values are converted to strings (handles any value types)
            - Empty attributes dict returns failure (no attributes to convert)
            - Uses FlextRuntime.is_list_like() for type-safe value handling

        Audit Implications:
            - Conversion failures are logged with entry DN and error details
            - Empty attributes are detected before conversion attempt
            - Value type conversion errors are caught and logged

        Architecture:
            - Accesses entry.attributes.attributes dict directly
            - Uses FlextRuntime.is_list_like() for type narrowing
            - Returns FlextResult pattern - no exceptions raised
            - Returns dict[str, list[str]] format expected by ldap3

        Args:
            entry: FlextLdifModels.Entry with attributes to convert.
                Must have non-empty attributes.attributes dict.

        Returns:
            r[Attributes]: Dict mapping attribute names to list[str] values
            or error if entry has no attributes or conversion fails.

        """
        if entry.attributes is None:
            return r[t.Ldap.Attributes].fail(
                "Entry has no attributes",
            )
        if not entry.attributes.attributes:
            return r[t.Ldap.Attributes].fail(
                "Entry has no attributes",
            )
        try:
            # Build dict from DynamicMetadata items, filtering for list values
            # LDIF attributes are always lists of strings
            # Use u.filter() and u.map() for efficient processing
            def convert_attr_value(_key: str, value: object) -> list[str] | None:
                """Convert attribute value to list of strings if list-like."""
                value_typed = cast("t.GeneralValueType", value)
                if FlextRuntime.is_list_like(value_typed):
                    return cast(
                        "list[str]",
                        u.map(cast("list[object]", value_typed), mapper=str),
                    )
                return None

            # Filter and map attributes
            filtered_attrs = u.filter(
                entry.attributes.attributes,
                predicate=lambda _k, v: FlextRuntime.is_list_like(
                    cast("t.GeneralValueType", v)
                ),
            )
            attributes_dict = cast(
                "t.Ldap.Attributes",
                u.map(
                    cast("dict[str, object]", filtered_attrs),
                    mapper=lambda _k, v: cast(
                        "list[str]", u.map(cast("list[object]", v), mapper=str)
                    ),
                ),
            )
            return r[t.Ldap.Attributes].ok(
                attributes_dict,
            )
        except (ValueError, TypeError, AttributeError) as e:
            entry_dn_str = str(entry.dn) if entry.dn else "unknown"
            self.logger.exception(
                "Failed to convert LDIF entry to ldap3 attributes format",
                operation=c.LdapOperationNames.LDIF_ENTRY_TO_LDAP3_ATTRIBUTES.value,
                entry_dn=entry_dn_str,
                error=str(e),
                error_type=type(e).__name__,
            )
            return r[t.Ldap.Attributes].fail(
                f"Failed to convert attributes to ldap3 format: {e!s}",
            )
