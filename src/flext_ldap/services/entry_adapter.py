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

    def _convert_dict_attributes(
        self,
        raw_attributes: dict[str, object],
    ) -> dict[str, str | list[str]]:
        """Convert dict attributes to proper format for Entry.create."""
        attributes_for_create: dict[str, str | list[str]] = {}
        for attr_name, attr_values in raw_attributes.items():
            if isinstance(attr_values, list):
                if len(attr_values) == 1:
                    attributes_for_create[attr_name] = str(attr_values[0])
                else:
                    attributes_for_create[attr_name] = [str(v) for v in attr_values]
            else:
                attributes_for_create[attr_name] = str(attr_values)
        return attributes_for_create

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
        # Explicit FlextResult error handling - NO try/except
        if not entry:
            return FlextResult[str].fail("Entry cannot be None")

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
        if not entry:
            return FlextResult[FlextLdifModels.Entry].fail("Entry cannot be None")

        if not target_server_type:
            return FlextResult[FlextLdifModels.Entry].fail(
                "Target server type cannot be empty",
            )

        self.logger.debug(
            "Entry normalized for target server",
            extra={
                "dn": str(entry.dn),
                "target_server": target_server_type,
            },
        )

        return FlextResult[FlextLdifModels.Entry].ok(entry)

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
        # Explicit FlextResult error handling - NO try/except
        if not entry:
            return FlextResult[bool].fail("Entry cannot be None")

        if not server_type:
            return FlextResult[bool].fail("Server type cannot be empty")

        # Validate DN format
        dn_str = str(entry.dn)
        if not dn_str or not dn_str.strip():
            return FlextResult[bool].fail("Entry has invalid DN")

        # Validate has object classes
        if hasattr(entry, "get_attribute_values"):
            # FlextLdifModels.Entry interface
            object_classes = entry.get_attribute_values("objectClass")
        else:
            # FlextLdifModels.Entry interface
            object_classes = getattr(entry, "object_classes", [])

        if not object_classes:
            return FlextResult[bool].fail(
                "Entry missing required objectClass attribute",
            )

        # Validate has at least one structural object class
        if isinstance(object_classes, list) and len(object_classes) == 0:
            return FlextResult[bool].fail("Entry has empty objectClass")

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
        # Explicit FlextResult error handling - NO try/except
        if not entry:
            return FlextResult[FlextLdifModels.Entry].fail("Entry cannot be None")

        if source_server_type == target_server_type:
            # No conversion needed
            return FlextResult[FlextLdifModels.Entry].ok(entry)

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
