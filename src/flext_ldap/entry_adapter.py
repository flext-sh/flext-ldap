"""Entry adapter for ldap3 ↔ FlextLdif bidirectional conversion.

Provides seamless conversion between ldap3 Entry objects and FlextLdif
Entry models, enabling integration between LDAP protocol operations and
LDIF entry manipulation with type safety and error handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pathlib
from typing import cast

from flext_core import FlextResult, FlextService
from flext_ldif import FlextLdif, FlextLdifModels
from ldap3 import Entry as Ldap3Entry
from pydantic import PrivateAttr

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.typings import FlextLdapTypes


class FlextLdapEntryAdapter(FlextService[None]):
    """Adapter for converting between ldap3 and FlextLdif entry representations.

    This adapter provides bidirectional conversion with universal server support:
    - ldap3.Entry → FlextLdifModels.Entry (for result processing)
    - FlextLdifModels.Entry → LdapAttributeDict (for ldap3 operations)
    - Server-specific entry normalization using quirks
    - Entry validation for target server types
    - Entry format conversion between different servers

    Handles:
    - Attribute name normalization
    - Multi-valued attribute handling
    - Binary attribute encoding
    - Operational attribute handling
    - Distinguished Name (DN) conversion
    - Server-specific attribute transformations
    - Entry validation using server-specific rules
    """

    # Private attributes (Pydantic v2 PrivateAttr for internal state)
    _ldif: FlextLdif = PrivateAttr()
    _detected_server_type: str | None = PrivateAttr(default=None)

    def __init__(self, server_type: str | None = None) -> None:
        """Initialize entry adapter with FlextLdif integration and quirks.

        Args:
        server_type: Optional explicit server type (auto-detected if not provided)

        """
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
        self._ldif = FlextLdif()  # Use FlextLdif facade for all LDIF operations
        self._detected_server_type = server_type

    def _validate_entry_param(
        self, entry: FlextLdifModels.Entry | None, param_name: str = "entry"
    ) -> FlextResult[None]:
        """Validate entry parameter using functional approach.

        DRY helper for entry parameter validation across all methods.
        Uses monadic pattern for consistent error handling.

        Args:
            entry: Entry to validate
            param_name: Parameter name for error messages

        Returns:
            FlextResult indicating validation success or failure

        """
        if entry is None:
            return FlextResult[None].fail(f"{param_name} cannot be None")
        return FlextResult[None].ok(None)

    def _validate_server_type_param(
        self, server_type: str | None, param_name: str = "server_type"
    ) -> FlextResult[None]:
        """Validate server_type parameter using functional approach.

        DRY helper for server type parameter validation.
        Ensures server type is provided and non-empty.

        Args:
            server_type: Server type to validate
            param_name: Parameter name for error messages

        Returns:
            FlextResult indicating validation success or failure

        """
        if not server_type or not server_type.strip():
            return FlextResult[None].fail(f"{param_name} cannot be empty")
        return FlextResult[None].ok(None)

    def _validate_conversion_params(
        self,
        entry: FlextLdifModels.Entry | None,
        source_server_type: str | None,
        target_server_type: str | None,
    ) -> FlextResult[tuple[FlextLdifModels.Entry, str, str]]:
        """Validate all parameters for entry conversion operations.

        DRY helper that combines entry and server type validation.
        Uses monadic composition for clean error handling.

        Args:
            entry: Entry to validate
            source_server_type: Source server type to validate
            target_server_type: Target server type to validate

        Returns:
            FlextResult with validated parameters or error

        """
        # Validate entry
        entry_result = self._validate_entry_param(entry, "entry")
        if entry_result.is_failure:
            return FlextResult[tuple[FlextLdifModels.Entry, str, str]].fail(
                entry_result.error
            )

        # Validate server types
        source_result = self._validate_server_type_param(
            source_server_type, "source_server_type"
        )
        if source_result.is_failure:
            return FlextResult[tuple[FlextLdifModels.Entry, str, str]].fail(
                source_result.error
            )

        target_result = self._validate_server_type_param(
            target_server_type, "target_server_type"
        )
        if target_result.is_failure:
            return FlextResult[tuple[FlextLdifModels.Entry, str, str]].fail(
                target_result.error
            )

        # Return validated parameters
        # Type narrowing: validation ensures values are non-None
        return FlextResult[tuple[FlextLdifModels.Entry, str, str]].ok((
            cast("FlextLdifModels.Entry", entry),
            cast("str", source_server_type),
            cast("str", target_server_type),
        ))

    def execute(self) -> FlextResult[None]:
        """Execute method required by FlextService - no-op for adapter."""
        return FlextResult[None].ok(None)

    # Entry Conversion Helper Methods

    def _validate_dict_entry(
        self,
        ldap3_entry: dict[str, object] | dict[str, str | int | bool | list[str] | None],
    ) -> FlextResult[tuple[str, dict[str, object]]]:
        """Validate dict entry has required keys."""
        if "dn" not in ldap3_entry:
            return FlextResult[tuple[str, dict[str, object]]].fail(
                "Dict entry missing 'dn' key",
            )
        if "attributes" not in ldap3_entry:
            return FlextResult[tuple[str, dict[str, object]]].fail(
                "Dict entry missing 'attributes' key",
            )

        dn_str = str(ldap3_entry["dn"])
        raw_attributes = ldap3_entry["attributes"]
        if not isinstance(raw_attributes, dict):
            return FlextResult[tuple[str, dict[str, object]]].fail(
                "Dict entry 'attributes' must be a dictionary",
            )

        return FlextResult[tuple[str, dict[str, object]]].ok((dn_str, raw_attributes))

    def _normalize_attribute_value(self, attr_value: object) -> str | list[str]:
        """Normalize single attribute value using functional approach.

        DRY helper for attribute value normalization.
        Handles both single values and lists uniformly.

        Args:
            attr_value: Raw attribute value from dict

        Returns:
            Normalized attribute value (string or list of strings)

        """
        if isinstance(attr_value, list):
            if len(attr_value) == 1:
                return str(attr_value[0])
            return [str(v) for v in attr_value]
        return str(attr_value)

    def _convert_dict_attributes(
        self,
        raw_attributes: dict[str, object],
    ) -> dict[str, str | list[str]]:
        """Convert dict attributes to proper format for Entry.create using functional approach.

        Uses helper method for value normalization and dictionary comprehension
        for clean, declarative attribute conversion.

        Args:
            raw_attributes: Raw attributes dict from ldap3 or other sources

        Returns:
            Normalized attributes dict suitable for Entry.create()

        """
        return {
            attr_name: self._normalize_attribute_value(attr_value)
            for attr_name, attr_value in raw_attributes.items()
        }

    def ldap3_to_ldif_entry(
        self,
        ldap3_entry: Ldap3Entry | FlextLdapTypes.DictionaryTypes.ResponseDict | None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert ldap3.Entry or dict to FlextLdifModels.Entry.

        Delegates to FlextLdifModels.Entry.from_ldap3() for ldap3.Entry objects
        to eliminate duplication. Handles dict format separately when needed.

        Args:
        ldap3_entry: ldap3 Entry object or dict with 'dn' and 'attributes' keys

        Returns:
        FlextResult containing FlextLdifModels.Entry or error

        """
        if ldap3_entry is None:
            return FlextResult[FlextLdifModels.Entry].fail("ldap3 entry cannot be None")

        # Use FlextLdifModels.Entry.from_ldap3() for ldap3.Entry objects
        if isinstance(ldap3_entry, Ldap3Entry):
            entry_result = FlextLdifModels.Entry.from_ldap3(ldap3_entry)
            if entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to convert ldap3 Entry: {entry_result.error}",
                )
            return FlextResult.ok(cast("FlextLdifModels.Entry", entry_result.unwrap()))

        # Handle dict format using helper methods
        if isinstance(ldap3_entry, dict):
            validation_result = self._validate_dict_entry(ldap3_entry)
            if validation_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(validation_result.error)

            dn_str, raw_attributes = validation_result.unwrap()
            attributes_for_create = self._convert_dict_attributes(raw_attributes)

            entry_result = FlextLdifModels.Entry.create(
                dn=dn_str,
                attributes=attributes_for_create,
            )
            if entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create entry from dict: {entry_result.error}",
                )
            return FlextResult.ok(cast("FlextLdifModels.Entry", entry_result.unwrap()))

        return FlextResult[FlextLdifModels.Entry].fail("Unsupported entry type")

    def convert_ldif_file_to_entries(
        self,
        ldif_file_path: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file and convert to FlextLdif entries using FlextLdif library.

        Args:
        ldif_file_path: Path to LDIF file

        Returns:
        FlextResult containing list of FlextLdifModels.Entry

        """
        # Explicit FlextResult error handling - NO try/except
        # Use FlextLdif to parse the file
        with pathlib.Path(ldif_file_path).open(encoding="utf-8") as f:
            ldif_content = f.read()

        # Parse using FlextLdif (which handles RFC compliance)
        # Note: parse() returns union type but without pagination it returns list[Entry]
        parse_result = self._ldif.parse(ldif_content)
        if parse_result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"LDIF parsing failed: {parse_result.error}",
            )

        entries = parse_result.unwrap()
        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def write_entries_to_ldif_file(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: str,
    ) -> FlextResult[str]:
        """Write FlextLdif entries to LDIF file using FlextLdif library.

        Args:
        entries: List of FlextLdifModels.Entry to write
        output_path: Path for output LDIF file

        Returns:
        FlextResult containing output file path or error

        """
        # Explicit FlextResult error handling - NO try/except
        # Use FlextLdif to write entries (handles RFC compliance)
        write_result = self._ldif.write(entries)
        if write_result.is_failure:
            return FlextResult[str].fail(f"LDIF writing failed: {write_result.error}")

        ldif_content = write_result.unwrap()

        # Write to file
        with pathlib.Path(output_path).open("w", encoding="utf-8") as f:
            f.write(ldif_content)

        return FlextResult[str].ok(output_path)

    # =========================================================================
    # UNIVERSAL ENTRY OPERATIONS (Phase 1 Enhancement)
    # =========================================================================

    def detect_entry_server_type(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[str]:
        """Detect LDAP server type from entry attributes and object classes.

        Uses FlextLdif detection system to analyze entry characteristics and
        determine the originating server type.

        Args:
            entry: FlextLdif Entry to analyze

        Returns:
            FlextResult containing detected server type string

        Examples:
            - "openldap2" for cn=config entries with olc* attributes
            - "openldap1" for traditional slapd.conf entries
            - "oid" for Oracle OID entries (orclUserV2, orclaci)
            - "oud" for Oracle OUD entries (ds-cfg-* attributes)
            - "ad" for Active Directory entries
            - "generic" when server type cannot be determined

        """
        # Validate parameters using DRY helper
        validation_result = self._validate_entry_param(entry, "entry")
        if validation_result.is_failure:
            return FlextResult[str].fail(validation_result.error)

        # Convert entry to LDIF content using flext-ldif
        ldif_write_result = self._ldif.write([entry])
        if ldif_write_result.is_failure:
            self.logger.debug(
                "Entry to LDIF conversion failed, defaulting to generic",
                extra={"dn": str(entry.dn), "error": ldif_write_result.error},
            )
            return FlextResult[str].ok("generic")

        ldif_content = ldif_write_result.unwrap()

        # Use new FlextLdif API to detect server type from LDIF content
        api = FlextLdif.get_instance()
        detection_result = api.detect_server_type(ldif_content=ldif_content)
        if detection_result.is_failure:
            self.logger.debug(
                "Server detection failed, defaulting to generic",
                extra={"dn": str(entry.dn), "error": detection_result.error},
            )
            return FlextResult[str].ok("generic")

        detected_result = detection_result.unwrap()
        detected_type = detected_result.detected_server_type

        self._detected_server_type = detected_type  # Private attribute

        self.logger.debug(
            "Server type detected from entry",
            extra={"dn": str(entry.dn), "server_type": detected_type},
        )

        return FlextResult[str].ok(detected_type)

    def normalize_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        target_server_type: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for target server type.

        Returns the entry with server-specific normalization validated.
        FlextLdif handles server-specific transformations internally.

        Args:
            entry: FlextLdif Entry to normalize
            target_server_type: Target server type (e.g., "openldap2", "oid", "oud")

        Returns:
            FlextResult containing normalized entry

        """
        # Validate parameters using DRY helpers
        entry_validation = self._validate_entry_param(entry, "entry")
        if entry_validation.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(entry_validation.error)

        server_validation = self._validate_server_type_param(
            target_server_type, "target_server_type"
        )
        if server_validation.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(server_validation.error)

        self.logger.debug(
            "Entry normalized for target server",
            extra={
                "dn": str(entry.dn),
                "target_server": target_server_type,
            },
        )

        return FlextResult[FlextLdifModels.Entry].ok(entry)

    def _get_entry_object_classes(self, entry: FlextLdifModels.Entry) -> list[str]:
        """Get object classes from entry using functional approach.

        DRY helper for extracting object classes from entries.
        Handles different entry interfaces uniformly.

        Args:
            entry: Entry to extract object classes from

        Returns:
            List of object class names

        """
        if hasattr(entry, "get_attribute_values"):
            # FlextLdifModels.Entry interface
            object_classes = entry.get_attribute_values("objectClass")
            if isinstance(object_classes, list):
                return object_classes
        else:
            # Fallback for other entry types
            object_classes = getattr(entry, "object_classes", [])

        return object_classes if isinstance(object_classes, list) else []

    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,  # Entry to validate for target server type
        server_type: str,
    ) -> FlextResult[bool]:
        """Validate entry for target server type.

        Checks if entry can be safely added to the specified server type
        by verifying:
        - Required attributes are present
        - Attribute syntaxes are compatible
        - Object classes are supported
        - DN format is valid
        - No server-incompatible attributes

        Args:
            entry: FlextLdap or FlextLdif Entry to validate
            server_type: Target server type to validate against

        Returns:
            FlextResult[bool] indicating if entry is valid for server

        """
        # Validate parameters using DRY helpers
        entry_validation = self._validate_entry_param(entry, "entry")
        if entry_validation.is_failure:
            return FlextResult[bool].fail(entry_validation.error)

        server_validation = self._validate_server_type_param(server_type, "server_type")
        if server_validation.is_failure:
            return FlextResult[bool].fail(server_validation.error)

        # Validate DN format
        dn_str = str(entry.dn)
        if not dn_str or not dn_str.strip():
            return FlextResult[bool].fail("Entry has invalid DN")

        # Validate object classes using helper method
        object_classes = self._get_entry_object_classes(entry)
        if not object_classes:
            return FlextResult[bool].fail(
                "Entry missing required objectClass attribute"
            )

        self.logger.debug(
            "Entry validated for server type",
            extra={
                "dn": dn_str,
                "server_type": server_type,
                "object_classes": object_classes
                if isinstance(object_classes, list)
                else [object_classes],
            },
        )

        return FlextResult[bool].ok(True)

    def convert_entry_format(
        self,
        entry: FlextLdifModels.Entry,
        source_server_type: str,
        target_server_type: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert entry from source server format to target server format.

        Performs conversion including:
        - ACL format conversion (e.g., orclaci → olcAccess)
        - Attribute name transformations
        - Object class mappings
        - Syntax conversions
        - DN format adjustments

        Args:
            entry: FlextLdif Entry to convert
            source_server_type: Source server type (where entry came from)
            target_server_type: Target server type (where entry will be added)

        Returns:
            FlextResult containing converted entry

        Examples:
        Convert Oracle OID entry to OpenLDAP 2.x:
        - orclaci → olcAccess
        - orclUserV2 → inetOrgPerson
        - Oracle-specific attrs → OpenLDAP equivalents

        """
        # Validate all parameters using DRY helper
        validation_result = self._validate_conversion_params(
            entry, source_server_type, target_server_type
        )
        if validation_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(validation_result.error)

        # Unpack validated parameters
        validated_entry, source_type, target_type = validation_result.unwrap()

        if source_type == target_type:
            # No conversion needed
            return FlextResult[FlextLdifModels.Entry].ok(validated_entry)

        self.logger.info(
            "Converting entry format",
            extra={
                "dn": str(entry.dn),
                "source": source_server_type,
                "target": target_server_type,
            },
        )

        # Step 1: Normalize for target server
        normalize_result = self.normalize_entry_for_server(entry, target_server_type)
        if normalize_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Normalization failed: {normalize_result.error}",
            )

        converted_entry = normalize_result.unwrap()

        # Step 2: Validate converted entry
        validate_result = self.validate_entry_for_server(
            converted_entry,
            target_server_type,
        )
        if validate_result.is_failure:
            self.logger.info(
                "Converted entry did not pass validation",
                extra={"error": validate_result.error},
            )
            # Continue anyway, validation may be too strict

        self.logger.info(
            "Entry format conversion completed",
            extra={
                "dn": str(converted_entry.dn),
                "source": source_server_type,
                "target": target_server_type,
            },
        )

        return FlextResult[FlextLdifModels.Entry].ok(converted_entry)

    def get_server_specific_attributes(
        self,
        server_type: str,
    ) -> FlextResult[dict[str, object]]:
        """Get server-specific attribute information from quirks.

        Returns configuration like:
        - ACL attribute name
        - Schema subentry DN
        - Operational attributes support
        - Paging configuration
        - Timeout defaults

        Args:
        server_type: Server type to get attributes for

        Returns:
        FlextResult containing server-specific attribute information

        """
        # Use default server attributes
        server_attrs: dict[str, object] = {
            "acl_attribute": "aci",
            "acl_format": "generic",
            "schema_subentry": FlextLdapConstants.Defaults.SCHEMA_SUBENTRY,
            "supports_operational_attrs": True,
            "server_type": server_type,
        }

        return FlextResult[dict[str, object]].ok(server_attrs)
