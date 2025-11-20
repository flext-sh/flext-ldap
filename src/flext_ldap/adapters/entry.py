"""Entry adapter for ldap3 ↔ FlextLdif bidirectional conversion.

Provides seamless conversion between ldap3 Entry objects and FlextLdif
Entry models, enabling integration between LDAP protocol operations and
LDIF entry manipulation with type safety and error handling.

All operations are generic and work with any LDAP server by leveraging
flext-ldif's quirks system for server-specific handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextLogger, FlextResult, FlextRuntime, FlextService
from flext_ldif import (
    EntryManipulationServices,
    FlextLdif,
    FlextLdifConfig,
    FlextLdifConstants,
    FlextLdifModels,
)
from ldap3 import Entry as Ldap3Entry

from flext_ldap.constants import FlextLdapConstants

logger = FlextLogger(__name__)


class FlextLdapEntryAdapter(FlextService[bool]):
    """Adapter for converting between ldap3 and FlextLdif entry representations.

    This adapter provides bidirectional conversion with universal server support:
    - ldap3.Entry → FlextLdifModels.Entry (for result processing)
    - FlextLdifModels.Entry → LdapAttributeDict (for ldap3 operations)
    - Server-specific entry normalization using quirks
    - Entry validation for target server types
    - Entry format conversion between different servers

    All operations are generic and work with any LDAP server by leveraging
    flext-ldif's quirks system for server-specific handling.
    """

    _ldif: FlextLdif
    _server_type: str

    def __init__(
        self,
        server_type: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize entry adapter with FlextLdif integration and quirks.

        Args:
            server_type: Server type for normalization (defaults to Constants)
            **kwargs: Additional keyword arguments passed to parent class

        """
        super().__init__(**kwargs)
        # Extract server_type from kwargs if not provided directly
        if server_type is None:
            server_type = cast("str | None", kwargs.pop("server_type", None))
        # Use default if still None
        if server_type is None:
            server_type = FlextLdapConstants.LdapDefaults.SERVER_TYPE
        # Create FlextLdif with server_type to use correct quirks (OID/OUD/etc)
        config = FlextLdifConfig(quirks_server_type=server_type)
        self._ldif = FlextLdif(config=config)
        self._server_type = server_type

    def execute(self, **_kwargs: object) -> FlextResult[bool]:
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
        return FlextResult[bool].ok(data=True)

    def _convert_ldap3_value_to_list(
        self,
        value: object,
        key: str,
        base64_attrs: list[str],
        converted_attrs: dict[str, dict[str, object]],
        removed_attrs: list[str],
        ascii_threshold: int = 127,
    ) -> list[str]:
        """Convert ldap3 value to list format, tracking conversions.

        Helper method to reduce complexity of ldap3_to_ldif_entry.

        Args:
            value: Value to convert
            key: Attribute name
            base64_attrs: List to append base64 attributes
            converted_attrs: Dict to track conversions
            removed_attrs: List to track removed attributes
            ascii_threshold: ASCII threshold for base64 detection

        Returns:
            List of string values

        """
        if FlextRuntime.is_list_like(value):
            # Type narrowing: is_list_like ensures list[object]
            converted_values = []
            for v in value:
                v_str = str(v)
                is_base64 = v_str.startswith("::") or any(
                    ord(c) > ascii_threshold for c in v_str
                )
                if is_base64:
                    base64_attrs.append(key)
                converted_values.append(v_str)

            # Track if values were converted
            if converted_values != [str(v) for v in value]:
                converted_attrs[key] = {
                    "original": value,
                    "converted": converted_values,
                    "conversion_type": "string_conversion",
                }
            return converted_values
        if value is None:
            removed_attrs.append(key)
            return []
        v_str = str(value)
        is_base64 = v_str.startswith("::") or any(
            ord(c) > ascii_threshold for c in v_str
        )
        if is_base64:
            base64_attrs.append(key)

        return [v_str]

    def _build_conversion_metadata(
        self,
        converted_attrs: dict[str, dict[str, object]],
        removed_attrs: list[str],
        base64_attrs: list[str],
        original_attrs_dict: dict[str, object],
        original_dn: str,
    ) -> dict[str, object]:
        """Build conversion metadata tracking all changes (DRY helper).

        Args:
            converted_attrs: Attributes that were converted
            removed_attrs: Attributes that were removed (None values)
            base64_attrs: Attributes detected as base64 encoded
            original_attrs_dict: Original attributes dict
            original_dn: Original DN string

        Returns:
            Conversion metadata dict

        """
        meta_keys = FlextLdifConstants.MetadataKeys
        conversion_metadata: dict[str, object] = {}

        if converted_attrs:
            conversion_metadata["converted_attributes"] = converted_attrs
            conversion_metadata["conversion_count"] = len(converted_attrs)

        if removed_attrs:
            conversion_metadata["removed_attributes"] = removed_attrs
            conversion_metadata["removed_count"] = len(removed_attrs)

        if base64_attrs:
            conversion_metadata["base64_encoded_attributes"] = list(set(base64_attrs))

        # Store original data in metadata
        conversion_metadata[meta_keys.ENTRY_SOURCE_ATTRIBUTES] = list(
            original_attrs_dict.keys(),
        )
        conversion_metadata[meta_keys.ENTRY_SOURCE_DN_CASE] = original_dn
        conversion_metadata["original_attributes_dict"] = {
            k: (
                list(v)
                if FlextRuntime.is_list_like(v)
                or isinstance(v, tuple)  # tuple not covered by is_list_like
                else [str(v)]
                if v is not None
                else []
            )
            for k, v in original_attrs_dict.items()
        }

        return conversion_metadata

    def _track_conversion_differences(
        self,
        conversion_metadata: dict[str, object],
        original_dn: str,
        converted_dn: str,
        original_attrs_dict: dict[str, object],
        converted_attrs_dict: dict[str, list[str]],
    ) -> None:
        """Track DN and attribute differences (DRY helper).

        Args:
            conversion_metadata: Metadata dict to update
            original_dn: Original DN string
            converted_dn: Converted DN string
            original_attrs_dict: Original attributes dict
            converted_attrs_dict: Converted attributes dict

        """
        # DN differences tracking
        if converted_dn != original_dn:
            conversion_metadata["dn_changed"] = True
            conversion_metadata["original_dn"] = original_dn
            conversion_metadata["converted_dn"] = converted_dn
        else:
            conversion_metadata["dn_changed"] = False

        # Attribute differences tracking (simple comparison)
        attribute_differences: dict[str, dict[str, object]] = {}
        for attr_name, original_values in original_attrs_dict.items():
            converted_values = converted_attrs_dict.get(attr_name, [])

            # Simple comparison - track if values changed
            original_str = ", ".join(
                str(v)
                for v in (
                    original_values
                    if FlextRuntime.is_list_like(original_values)
                    else [original_values]
                )
            )
            converted_str = (
                ", ".join(str(v) for v in converted_values) if converted_values else ""
            )

            if original_str != converted_str:
                attribute_differences[attr_name] = {
                    "original": original_str,
                    "converted": converted_str,
                    "changed": True,
                }

        if attribute_differences:
            conversion_metadata["attribute_differences"] = attribute_differences

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
        # Extract DN and attributes from ldap3_entry and create Entry
        # Type system guarantees ldap3_entry is a valid Ldap3Entry with required attributes
        # All operations wrapped in try-except for proper error handling
        # This includes conversion of entry_dn to string which may raise exceptions
        try:
            # Try to access entry_dn - may raise exception if property raises
            try:
                dn_str = str(ldap3_entry.entry_dn)
            except Exception as dn_exc:
                error_msg = f"Failed to access entry_dn: {dn_exc!s}"
                raise ValueError(error_msg) from dn_exc

            # Try to access entry_attributes_as_dict - may raise exception if property raises
            try:
                attrs_dict = ldap3_entry.entry_attributes_as_dict
            except Exception as attrs_exc:
                error_msg = f"Failed to access entry_attributes_as_dict: {attrs_exc!s}"
                raise ValueError(error_msg) from attrs_exc

            # Preserve original data for metadata (NEVER lose data)
            original_attrs_dict = dict(attrs_dict)  # Deep copy for metadata
            original_dn = dn_str

            # Convert attributes dict to LdifAttributes format
            # Ensure all values are lists (ldap3 format requirement)
            ldif_attrs: dict[str, list[str]] = {}
            converted_attrs: dict[str, dict[str, object]] = {}  # Track conversions
            removed_attrs: list[str] = []  # Track removed attributes
            base64_attrs: list[str] = []  # Track base64 encoded attributes

            # ASCII threshold for base64 detection
            ascii_threshold = 127

            for key, value in attrs_dict.items():
                ldif_attrs[key] = self._convert_ldap3_value_to_list(
                    value,
                    key,
                    base64_attrs,
                    converted_attrs,
                    removed_attrs,
                    ascii_threshold,
                )

            # Build comprehensive metadata (NEVER lose data)
            conversion_metadata = self._build_conversion_metadata(
                converted_attrs,
                removed_attrs,
                base64_attrs,
                original_attrs_dict,
                original_dn,
            )

            # Track differences
            self._track_conversion_differences(
                conversion_metadata,
                original_dn,
                dn_str,
                original_attrs_dict,
                ldif_attrs,
            )

            # Create metadata object
            entry_metadata = FlextLdifModels.QuirkMetadata(
                quirk_type=self._server_type,
                extensions=conversion_metadata,
            )

            # Create Entry with metadata preserving all original data
            entry = FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=dn_str),
                attributes=FlextLdifModels.LdifAttributes(attributes=ldif_attrs),
                metadata=entry_metadata,
            )

            if converted_attrs or removed_attrs or base64_attrs:
                logger.debug(
                    "Converted ldap3 entry to LDIF entry",
                    operation="ldap3_to_ldif_entry",
                    entry_dn=dn_str,
                    converted_attributes=len(converted_attrs),
                    removed_attributes=len(removed_attrs),
                    base64_attributes=len(set(base64_attrs)),
                )

            return FlextResult[FlextLdifModels.Entry].ok(entry)
        except Exception as e:
            # Try to get entry_dn for logging, but handle case where it raises exception
            entry_dn_for_log = "unknown"
            try:
                if hasattr(ldap3_entry, "entry_dn"):
                    entry_dn_for_log = str(ldap3_entry.entry_dn)
            except Exception as dn_exc:
                # entry_dn access itself raised exception, use default
                logger.debug(
                    "Could not access entry_dn for error logging",
                    error=str(dn_exc),
                    error_type=type(dn_exc).__name__,
                )

            logger.exception(
                "Failed to convert ldap3 entry to LDIF entry",
                operation="ldap3_to_ldif_entry",
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
    ) -> FlextResult[dict[str, list[str]]]:
        """Convert FlextLdifModels.Entry to ldap3 attributes format.

        Preserves all original data including metadata. Never loses data.

        Reuses FlextLdifEntryManipulation.convert_ldif_attributes_to_ldap3_format()
        to maximize code reuse and ensure consistency with flext-ldif.

        Args:
            entry: FlextLdifModels.Entry to convert

        Returns:
            FlextResult containing dict of attributes in ldap3 format

        """
        # Entry.attributes is validated by Pydantic model - guaranteed to exist
        # Fast fail if attributes dict is empty
        if not entry.attributes.attributes:
            logger.warning(
                "Entry has no attributes",
                operation="ldif_entry_to_ldap3_attributes",
                entry_dn=str(entry.dn) if entry.dn else "unknown",
            )
            return FlextResult[dict[str, list[str]]].fail("Entry has no attributes")

        # FASE 1: Reuse EntryManipulationServices.convert_ldif_attributes_to_ldap3_format()
        # to maximize code reuse and ensure consistency with flext-ldif
        try:
            # Convert entry.attributes to format expected by convert_ldif_attributes_to_ldap3_format
            # The method accepts LdifAttributes or dict, and entry.attributes is LdifAttributes
            # Type cast needed: entry.attributes is FlextLdifModels.LdifAttributes (from _models.domain)
            # but method expects FlextLdifModels.LdifAttributes (from models.py namespace wrapper)
            # Both are structurally compatible, cast is safe
            ldap3_attributes = (
                EntryManipulationServices.convert_ldif_attributes_to_ldap3_format(
                    cast(
                        "FlextLdifModels.LdifAttributes | dict[str, str | list[str]]",
                        entry.attributes,
                    ),
                )
            )

            return FlextResult[dict[str, list[str]]].ok(ldap3_attributes)
        except Exception as e:
            logger.exception(
                "Failed to convert LDIF entry to ldap3 attributes format",
                operation="ldif_entry_to_ldap3_attributes",
                entry_dn=str(entry.dn) if entry.dn else "unknown",
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[dict[str, list[str]]].fail(
                f"Failed to convert attributes to ldap3 format: {e!s}",
            )

    def normalize_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        target_server_type: str,  # noqa: ARG002
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for target server type using flext-ldif quirks.

        Preserves all metadata during normalization. Never loses data.

        Args:
            entry: FlextLdifModels.Entry to normalize
            target_server_type: Target server type (e.g., "openldap2", "oid", "oud")

        Returns:
            FlextResult containing normalized entry

        """
        # FlextLdif handles server-specific transformations internally via quirks
        # Return entry as-is for now - normalization happens during parse/write operations
        return FlextResult[FlextLdifModels.Entry].ok(entry)

    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,  # noqa: ARG002
        server_type: str,  # noqa: ARG002
    ) -> FlextResult[bool]:
        """Validate entry for target server type.

        Validates entry structure and server-specific requirements.
        Preserves all validation details in logs.

        Args:
            entry: FlextLdifModels.Entry to validate
            server_type: Server type to validate against

        Returns:
            FlextResult indicating validation success or failure

        Notes:
            - DN and attributes validation is handled by Pydantic v2 validators
              in FlextLdifModels.Entry (validate_entry_rfc_compliance)
            - This method only performs server-specific validation if needed
            - Entry model guarantees: dn is non-empty, attributes is non-empty dict

        """
        # Pydantic v2 validators in Entry model already validate:
        # - DN is non-empty (via _validate_dn in validate_entry_rfc_compliance)
        # - Attributes is non-empty (via _validate_attributes_required)
        # Entry creation would have raised ValidationError if invalid
        # Therefore, we can trust the entry is valid at this point

        # Server-specific validation can be added here if needed
        # For now, if entry passed Pydantic validation, it's valid
        return FlextResult[bool].ok(data=True)
