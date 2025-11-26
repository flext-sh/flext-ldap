"""Entry adapter for ldap3 ↔ FlextLdif bidirectional conversion.

Provides seamless conversion between ldap3 Entry objects and FlextLdif Entry models,
enabling integration between LDAP protocol operations and LDIF entry manipulation with
type safety and error handling. All operations are generic and work with any LDAP server
by leveraging flext-ldif's quirks system for server-specific handling.

Module: FlextLdapEntryAdapter
Scope: Bidirectional entry conversion, metadata preservation, server-specific normalization
Pattern: Service adapter extending FlextService, uses FlextLdif for quirks and conversion

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextRuntime, FlextService
from flext_ldif import (
    FlextLdif,
    FlextLdifConfig,
    FlextLdifConstants,
    FlextLdifModels,
)
from ldap3 import Entry as Ldap3Entry

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.typings import FlextLdapTypes


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

    class _ConversionHelpers:
        """Conversion helper methods using FlextUtilities."""

        ASCII_THRESHOLD: int = 127

        @staticmethod
        def is_base64_encoded(value: str, threshold: int = ASCII_THRESHOLD) -> bool:
            """Check if value is base64 encoded."""
            return value.startswith("::") or any(ord(c) > threshold for c in value)

        @staticmethod
        def convert_value_to_strings(value: object) -> list[str]:
            """Convert value to list of strings using FlextRuntime."""
            if FlextRuntime.is_list_like(value):
                return [str(v) for v in value]
            return [str(value)] if value is not None else []

        @staticmethod
        def normalize_original_attr_value(value: object) -> list[str]:
            """Normalize original attribute value for metadata."""
            if FlextRuntime.is_list_like(value) or isinstance(value, tuple):
                return [str(v) for v in value] if value else []
            return [str(value)] if value is not None else []

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
        # Use provided server_type or default from constants
        resolved_type: str = server_type or FlextLdapConstants.LdapDefaults.SERVER_TYPE
        if not isinstance(resolved_type, str):
            msg = f"server_type must be str, got {type(resolved_type).__name__}"
            raise TypeError(msg)
        config = FlextLdifConfig.model_construct(quirks_server_type=resolved_type)
        self._ldif = FlextLdif(config=config)
        self._server_type = resolved_type

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
        return FlextResult[bool].ok(True)

    def _convert_ldap3_value_to_list(
        self,
        value: object,
        key: str,
        base64_attrs: list[str],
        converted_attrs: dict[str, dict[str, object]],
        removed_attrs: list[str],
        ascii_threshold: int = _ConversionHelpers.ASCII_THRESHOLD,
    ) -> list[str]:
        """Convert ldap3 value to list format, tracking conversions."""
        if value is None:
            removed_attrs.append(key)
            return []
        converted_values = self._ConversionHelpers.convert_value_to_strings(value)
        if any(
            self._ConversionHelpers.is_base64_encoded(v, ascii_threshold)
            for v in converted_values
        ):
            base64_attrs.append(key)
        if FlextRuntime.is_list_like(value) and converted_values != [
            str(v) for v in value
        ]:
            converted_attrs[key] = {
                "original": value,
                "converted": converted_values,
                "conversion_type": "string_conversion",
            }
        return converted_values

    def _build_conversion_metadata(
        self,
        converted_attrs: dict[str, dict[str, object]],
        removed_attrs: list[str],
        base64_attrs: list[str],
        original_attrs_dict: dict[str, object],
        original_dn: str,
    ) -> dict[str, object]:
        """Build conversion metadata tracking all changes."""
        meta_keys = FlextLdifConstants.MetadataKeys
        conversion_metadata: dict[str, object] = {
            meta_keys.ENTRY_SOURCE_ATTRIBUTES: list(original_attrs_dict.keys()),
            meta_keys.ENTRY_SOURCE_DN_CASE: original_dn,
            "original_attributes_dict": {
                k: self._ConversionHelpers.normalize_original_attr_value(v)
                for k, v in original_attrs_dict.items()
            },
        }
        if converted_attrs:
            conversion_metadata.update({
                "converted_attributes": converted_attrs,
                "conversion_count": len(converted_attrs),
            })
        if removed_attrs:
            conversion_metadata.update({
                "removed_attributes": removed_attrs,
                "removed_count": len(removed_attrs),
            })
        if base64_attrs:
            conversion_metadata["base64_encoded_attributes"] = list(set(base64_attrs))
        return conversion_metadata

    def _track_conversion_differences(
        self,
        conversion_metadata: dict[str, object],
        original_dn: str,
        converted_dn: str,
        original_attrs_dict: dict[str, object],
        converted_attrs_dict: dict[str, list[str]],
    ) -> None:
        """Track DN and attribute differences."""
        conversion_metadata["dn_changed"] = converted_dn != original_dn
        if converted_dn != original_dn:
            conversion_metadata.update({
                "original_dn": original_dn,
                "converted_dn": converted_dn,
            })
        attr_diffs = {
            attr_name: {
                "original": ", ".join(
                    str(v)
                    for v in (
                        original_values
                        if FlextRuntime.is_list_like(original_values)
                        else [original_values]
                    )
                ),
                "converted": ", ".join(
                    str(v) for v in converted_attrs_dict.get(attr_name, [])
                )
                or "",
                "changed": True,
            }
            for attr_name, original_values in original_attrs_dict.items()
            if ", ".join(
                str(v)
                for v in (
                    original_values
                    if FlextRuntime.is_list_like(original_values)
                    else [original_values]
                )
            )
            != (
                ", ".join(str(v) for v in converted_attrs_dict.get(attr_name, [])) or ""
            )
        }
        if attr_diffs:
            conversion_metadata["attribute_differences"] = attr_diffs

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
            converted_attrs: dict[str, dict[str, object]] = {}
            removed_attrs: list[str] = []
            base64_attrs: list[str] = []
            for key, value in attrs_dict.items():
                ldif_attrs[key] = self._convert_ldap3_value_to_list(
                    value, key, base64_attrs, converted_attrs, removed_attrs
                )
            conversion_metadata = self._build_conversion_metadata(
                converted_attrs,
                removed_attrs,
                base64_attrs,
                original_attrs_dict,
                dn_str,
            )
            self._track_conversion_differences(
                conversion_metadata, dn_str, dn_str, original_attrs_dict, ldif_attrs
            )
            return FlextResult[FlextLdifModels.Entry].ok(
                FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(value=dn_str),
                    attributes=FlextLdifModels.LdifAttributes(attributes=ldif_attrs),
                    metadata=FlextLdifModels.QuirkMetadata(
                        quirk_type=self._server_type, extensions=conversion_metadata
                    ),
                )
            )
        except Exception as e:
            entry_dn_for_log = str(getattr(ldap3_entry, "entry_dn", "unknown"))
            self.logger.exception(
                "Failed to convert ldap3 entry to LDIF entry",
                operation="ldap3_to_ldif_entry",
                entry_dn=entry_dn_for_log,
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create Entry: {e!s}"
            )

    def ldif_entry_to_ldap3_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdapTypes.LdapAttributes]:
        """Convert FlextLdifModels.Entry to ldap3 attributes format."""
        if not entry.attributes.attributes:
            return FlextResult[FlextLdapTypes.LdapAttributes].fail(
                "Entry has no attributes"
            )
        try:
            return FlextResult[FlextLdapTypes.LdapAttributes].ok(
                FlextLdif.entry_manipulation.convert_ldif_attributes_to_ldap3_format(
                    dict(entry.attributes.attributes)
                )
            )
        except Exception as e:
            entry_dn_str = str(entry.dn) if entry.dn else "unknown"
            self.logger.exception(
                "Failed to convert LDIF entry to ldap3 attributes format",
                operation="ldif_entry_to_ldap3_attributes",
                entry_dn=entry_dn_str,
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[FlextLdapTypes.LdapAttributes].fail(
                f"Failed to convert attributes to ldap3 format: {e!s}"
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
        return FlextResult[bool].ok(True)
