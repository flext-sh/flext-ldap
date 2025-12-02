"""Entry adapter for ldap3 ↔ FlextLdif bidirectional conversion.

Provides seamless conversion between ldap3 Entry objects and FlextLdif Entry models,
enabling integration between LDAP protocol operations and LDIF entry manipulation with
type safety and error handling. All operations are generic and work with any LDAP server
by leveraging flext-ldif's quirks system for server-specific handling.

Module: FlextLdapEntryAdapter
Scope: Bidirectional entry conversion, metadata preservation,
    server-specific normalization
Pattern: Service adapter extending FlextService, uses FlextLdif
    for quirks and conversion

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence, Sequence

from flext_core import FlextResult, FlextRuntime, FlextService
from flext_core.typings import FlextTypes
from flext_ldif import (
    FlextLdif,
    FlextLdifModels,
)
from flext_ldif.constants import FlextLdifConstants
from ldap3 import Entry as Ldap3Entry
from pydantic import PrivateAttr

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes

# =========================================================================
# TYPE ALIASES (Python 3.13+ PEP 695)
# =========================================================================
type Ldap3EntryValue = (
    str | bytes | int | float | bool | Sequence[str | bytes | int | float | bool] | None
)
"""Type alias for ldap3 entry attribute values.

Supports all common LDAP attribute value types:
- Scalar: str, bytes, int, float, bool, None
- Multi-valued: Sequence of scalar types
"""

type AttributeDict = dict[str, list[str]]
"""Type alias for LDIF/LDAP attribute mappings (attribute names to string lists)."""

type ConversionState = tuple[list[str], list[str]]
"""Type alias for conversion state: (removed_attrs, base64_attrs)."""


class FlextLdapEntryAdapter(FlextService[bool]):
    """Adapter for converting between ldap3 and FlextLdif entry representations.

    This adapter provides bidirectional conversion with universal server support:
    - ldap3.Entry → FlextLdifModels.Entry (for result processing)
    - FlextLdifModels.Entry → FlextLdapTypes.Ldap.Attributes (for ldap3 operations)
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

            Args:
                value: String value to check
                threshold: ASCII threshold for non-printable detection

            Returns:
                True if value contains LDIF base64 marker or non-ASCII characters

            """
            return value.startswith("::") or any(ord(c) > threshold for c in value)

        @staticmethod
        def convert_value_to_strings(value: Ldap3EntryValue) -> Sequence[str]:
            """Convert ldap3 entry value to sequence of strings.

            Uses FlextRuntime type guards for safe conversion without isinstance.

            Args:
                value: ldap3 attribute value (str, list, bytes, or mixed)

            Returns:
                Sequence of string values (empty if value is None/empty)

            """
            if FlextRuntime.is_list_like(value):
                return [str(v) for v in value]
            return [str(value)] if value is not None else []

        @staticmethod
        def normalize_original_attr_value(value: Ldap3EntryValue) -> Sequence[str]:
            """Normalize attribute value preserving original form for metadata.

            Args:
                value: Original ldap3 attribute value

            Returns:
                Sequence of string values from original attribute

            """
            if FlextRuntime.is_list_like(value) or isinstance(value, tuple):
                return [str(v) for v in value] if value else []
            return [str(value)] if value is not None else []

    _ldif: FlextLdif = PrivateAttr()
    _server_type: str = PrivateAttr()

    def __init__(
        self,
        **kwargs: FlextTypes.GeneralValueType,
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

    def execute(self, **_kwargs: str | float | bool | None) -> FlextResult[bool]:  # noqa: PLR6301
        """Execute method required by FlextService.

        Entry adapter does not perform operations itself - it converts between
        entry formats. The conversion methods (ldap3_to_ldif_entry, etc.) should be
        called directly instead of using execute().

        Args:
            **_kwargs: Unused - adapter is stateless and requires no configuration

        Returns:
            FlextResult[bool] - success with True as this adapter is stateless
                and always ready

        """
        return FlextResult[bool].ok(True)

    def _convert_ldap3_value_to_list(
        self,
        value: Ldap3EntryValue,
        key: str,
        base64_attrs: MutableSequence[str],
        removed_attrs: MutableSequence[str],
        ascii_threshold: int = _ConversionHelpers.ASCII_THRESHOLD,
    ) -> list[str]:
        """Convert ldap3 attribute value to list format, tracking metadata.

        Mutates base64_attrs and removed_attrs lists with tracking information.
        Uses type guards for safe value type narrowing.

        Args:
            value: ldap3 attribute value to convert
            key: Attribute name for tracking
            base64_attrs: Mutable list to track attributes needing base64
            removed_attrs: Mutable list to track empty/None attributes
            ascii_threshold: ASCII threshold for base64 detection

        Returns:
            List of string values (empty if None)

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
        original_attrs_dict: Mapping[str, Ldap3EntryValue],
        original_dn: str,
    ) -> FlextLdapModels.ConversionMetadata:
        """Build conversion metadata tracking ldap3 to LDIF transformation.

        Args:
            removed_attrs: Attributes removed during conversion (None values)
            base64_attrs: Attributes requiring base64 encoding
            original_attrs_dict: Original ldap3 attributes mapping
            original_dn: Original ldap3 entry distinguished name

        Returns:
            ConversionMetadata model with transformation tracking

        """
        return FlextLdapModels.ConversionMetadata(
            source_attributes=list(original_attrs_dict.keys()),
            source_dn=original_dn,
            removed_attributes=list(removed_attrs),
            base64_encoded_attributes=list(set(base64_attrs)),
        )

    @staticmethod
    def _track_conversion_differences(
        conversion_metadata: FlextLdapModels.ConversionMetadata,
        original_dn: str,
        converted_dn: str,
        original_attrs_dict: Mapping[str, Ldap3EntryValue],
        converted_attrs_dict: Mapping[str, list[str]],
    ) -> None:
        """Track DN and attribute differences in conversion metadata.

        Mutates conversion_metadata to record DN changes and attribute modifications
        detected during ldap3 to LDIF conversion.

        Args:
            conversion_metadata: Metadata model to update with changes
            original_dn: Original ldap3 entry DN
            converted_dn: Converted LDIF entry DN
            original_attrs_dict: Original ldap3 attributes
            converted_attrs_dict: Converted LDIF attributes (lists of strings)

        """
        if converted_dn != original_dn:
            conversion_metadata.dn_changed = True
            conversion_metadata.converted_dn = converted_dn

        # Track attribute differences (changes in values during conversion)
        changed_attrs = []
        for attr_name, original_values in original_attrs_dict.items():
            original_str = ", ".join(
                str(v)
                for v in (
                    original_values
                    if FlextRuntime.is_list_like(original_values)
                    else [original_values]
                )
            )
            converted_str = (
                ", ".join(str(v) for v in converted_attrs_dict.get(attr_name, [])) or ""
            )
            if original_str != converted_str:
                changed_attrs.append(attr_name)

        if changed_attrs:
            conversion_metadata.attribute_changes = changed_attrs

    def ldap3_to_ldif_entry(
        self,
        ldap3_entry: Ldap3Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert ldap3.Entry to FlextLdifModels.Entry.

        Delegates to FlextLdifModels.Entry.from_ldap3() for conversion.
        Uses railway pattern for error handling.

        Args:
            ldap3_entry: ldap3 Entry object (required, no fallback)

        Returns:
            FlextResult containing FlextLdifModels.Entry or error

        Raises:
            ValueError: If entry_dn or entry_attributes_as_dict access fails

        Notes:
            - Type annotation ensures ldap3_entry is not None
            - Pydantic/type checker will enforce this at call site
            - No runtime None check needed - type system guarantees non-None

        """
        try:
            dn_str = str(ldap3_entry.entry_dn)
            attrs_dict = ldap3_entry.entry_attributes_as_dict
            original_attrs_dict = dict(attrs_dict)
            ldif_attrs: dict[str, list[str]] = {}
            removed_attrs: list[str] = []
            base64_attrs: list[str] = []
            for key, value in attrs_dict.items():
                ldif_attrs[key] = self._convert_ldap3_value_to_list(
                    value,
                    key,
                    base64_attrs,
                    removed_attrs,
                )
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
            metadata_obj = FlextLdifModels.QuirkMetadata.model_validate({
                "quirk_type": self._server_type,
                "extensions": conversion_metadata.model_dump(exclude_defaults=False),
            })
            return FlextResult[FlextLdifModels.Entry].ok(
                FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(value=dn_str),
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
                operation=FlextLdapConstants.LdapOperationNames.LDAP3_TO_LDIF_ENTRY.value,
                entry_dn=entry_dn_for_log,
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create Entry: {e!s}",
            )

    def ldif_entry_to_ldap3_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdapTypes.Ldap.Attributes]:
        """Convert FlextLdifModels.Entry to ldap3 attributes format."""
        if entry.attributes is None:
            return FlextResult[FlextLdapTypes.Ldap.Attributes].fail(
                "Entry has no attributes",
            )
        if not entry.attributes.attributes:
            return FlextResult[FlextLdapTypes.Ldap.Attributes].fail(
                "Entry has no attributes",
            )
        try:
            # Build dict from DynamicMetadata items, filtering for list values
            # LDIF attributes are always lists of strings
            attributes_dict: FlextLdapTypes.Ldap.Attributes = {}
            for key, value in entry.attributes.attributes.items():
                if FlextRuntime.is_list_like(value):
                    # Convert list elements to strings (LDIF format)
                    attributes_dict[key] = [str(v) for v in value]
            return FlextResult[FlextLdapTypes.Ldap.Attributes].ok(
                attributes_dict,
            )
        except (ValueError, TypeError, AttributeError) as e:
            entry_dn_str = str(entry.dn) if entry.dn else "unknown"
            self.logger.exception(
                "Failed to convert LDIF entry to ldap3 attributes format",
                operation=FlextLdapConstants.LdapOperationNames.LDIF_ENTRY_TO_LDAP3_ATTRIBUTES.value,
                entry_dn=entry_dn_str,
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[FlextLdapTypes.Ldap.Attributes].fail(
                f"Failed to convert attributes to ldap3 format: {e!s}",
            )
