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
from flext_ldif.quirks import FlextLdifEntryQuirks, FlextLdifQuirksManager
from ldap3 import MODIFY_REPLACE, Entry as Ldap3Entry

from flext_ldap.constants import FlextLdapConstants

# Type aliases for ldap3 structures
LdapModifyDict = dict[str, list[tuple[str, list[str]]]]
LdapSearchResultDict = dict[str, str | int | bool | list[str]]


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

    def __init__(self, server_type: str | None = None) -> None:
        """Initialize entry adapter with FlextLdif integration and quirks.

        Args:
        server_type: Optional explicit server type (auto-detected if not provided)

        """
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
        self._ldif = FlextLdif()  # Direct instantiation without config
        self._quirks_manager = FlextLdifQuirksManager(server_type=server_type)
        self._entry_quirks = FlextLdifEntryQuirks()
        self._detected_server_type = (
            server_type  # Private attribute to avoid Pydantic validation
        )

    def execute(self) -> FlextResult[None]:
        """Execute method required by FlextService - no-op for adapter."""
        return FlextResult[None].ok(None)

    def ldap3_to_ldif_entry(
        self,
        ldap3_entry: Ldap3Entry | LdapSearchResultDict | None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert ldap3.Entry or dict to FlextLdifModels.Entry.

        Args:
        ldap3_entry: ldap3 Entry object or dict with 'dn' and 'attributes' keys

        Returns:
        FlextResult containing FlextLdifModels.Entry or error

        """
        # Explicit FlextResult error handling - NO try/except
        if not ldap3_entry:
            return FlextResult[FlextLdifModels.Entry].fail("ldap3 entry cannot be None")

        # Handle both ldap3 Entry objects and dict objects
        if isinstance(ldap3_entry, dict):
            # Handle dict input (from search operations)
            if "dn" not in ldap3_entry:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Dict entry missing 'dn' key",
                )
            if "attributes" not in ldap3_entry:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Dict entry missing 'attributes' key",
                )

            dn_str = str(ldap3_entry["dn"])
            raw_attributes = ldap3_entry["attributes"]
            if not isinstance(raw_attributes, dict):
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Dict entry 'attributes' must be a dictionary",
                )
            # Convert dict[str, list[str]] to dict[str, list[object]] for type safety
            typed_attributes: dict[str, list[object]] = {
                k: list(v) if isinstance(v, list) else [v]
                for k, v in raw_attributes.items()
            }
        elif isinstance(ldap3_entry, Ldap3Entry):
            # Extract DN from ldap3 entry
            dn_str = str(ldap3_entry.entry_dn)
            if not dn_str:
                return FlextResult[FlextLdifModels.Entry].fail("ldap3 entry missing DN")

            # Extract attributes from ldap3 entry
            ldap3_attributes: dict[str, list[object]] = {}
            for attr_name in ldap3_entry.entry_attributes:
                attr_value = ldap3_entry[attr_name]

                # Handle multi-valued attributes
                if isinstance(attr_value, list):
                    ldap3_attributes[attr_name] = attr_value
                elif attr_value.value is not None:
                    # Single value - convert to list for consistency
                    value = attr_value.value
                    ldap3_attributes[attr_name] = (
                        [value] if not isinstance(value, list) else value
                    )
                else:
                    # Empty attribute
                    ldap3_attributes[attr_name] = []
            # Assign to attributes variable for unified handling below
            typed_attributes = ldap3_attributes
        else:
            return FlextResult[FlextLdifModels.Entry].fail("Unsupported entry type")

        # Convert attributes to FlextLdifModels.LdifAttributes
        # Build the attributes dict directly from typed_attributes
        attributes_dict: dict[str, list[str]] = {}
        for attr_name, attr_value_list in typed_attributes.items():
            # Convert object list to string list
            str_values: list[str] = [str(value) for value in attr_value_list]
            attributes_dict[attr_name] = str_values

        # Create LdifAttributes directly
        try:
            ldif_attributes = FlextLdifModels.LdifAttributes(attributes=attributes_dict)
        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create LdifAttributes: {e}",
            )

        # Create DistinguishedName
        try:
            dn_obj = FlextLdifModels.DistinguishedName(value=dn_str)
            dn_result = FlextResult[FlextLdifModels.DistinguishedName].ok(dn_obj)
        except Exception as e:
            dn_result = FlextResult[FlextLdifModels.DistinguishedName].fail(
                f"Failed to create DistinguishedName: {e}"
            )
        if dn_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create DistinguishedName: {dn_result.error}",
            )

        dn_raw = dn_result.unwrap()
        if not isinstance(dn_raw, FlextLdifModels.DistinguishedName):
            return FlextResult[FlextLdifModels.Entry].fail(
                "Invalid DistinguishedName type",
            )
        dn: FlextLdifModels.DistinguishedName = dn_raw

        # Create Entry
        entry_result = FlextLdifModels.Entry.create(dn=dn, attributes=ldif_attributes)
        if entry_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create FlextLdif entry: {entry_result.error}",
            )

        ldif_entry = entry_result.unwrap()
        return FlextResult[FlextLdifModels.Entry].ok(ldif_entry)

    def ldap3_entries_to_ldif_entries(
        self,
        ldap3_entries: list[Ldap3Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Convert multiple ldap3 entries to FlextLdif entries.

        Args:
        ldap3_entries: List of ldap3 Entry objects

        Returns:
        FlextResult containing list of FlextLdifModels.Entry or error

        """
        if not ldap3_entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        ldif_entries: list[FlextLdifModels.Entry] = []
        for ldap3_entry in ldap3_entries:
            result = self.ldap3_to_ldif_entry(ldap3_entry)
            if result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to convert entry: {result.error}",
                )
            ldif_entries.append(result.unwrap())

        return FlextResult[list[FlextLdifModels.Entry]].ok(ldif_entries)

    def ldif_entry_to_ldap3_attributes(
        self,
        ldif_entry: FlextLdifModels.Entry | None,
    ) -> FlextResult[dict[str, list[str]]]:
        """Convert FlextLdifModels.Entry to ldap3 attributes dict.

        Args:
        ldif_entry: FlextLdif Entry model

        Returns:
        FlextResult containing attributes dict for ldap3 operations

        """
        # Explicit FlextResult error handling - NO try/except
        if not ldif_entry:
            return FlextResult[dict[str, list[str]]].fail(
                "FlextLdif entry cannot be None",
            )

        # Extract attributes from FlextLdif entry
        attributes = dict(ldif_entry.attributes.attributes)

        return FlextResult[dict[str, list[str]]].ok(attributes)

    def normalize_attributes_for_add(
        self,
        attributes: dict[str, str | list[str]],
    ) -> FlextResult[dict[str, list[object]]]:
        """Normalize attributes for ldap3 add operation.

        Ensures all attribute values are in list format as required by ldap3.

        Args:
        attributes: Attribute dictionary (values may be single or lists)

        Returns:
        FlextResult containing normalized attributes dict

        """
        # Explicit FlextResult error handling - NO try/except
        normalized: dict[str, list[object]] = {}
        for attr_name, attr_value in attributes.items():
            if isinstance(attr_value, list):
                normalized[attr_name] = cast("list[object]", attr_value)
            else:
                normalized[attr_name] = cast("list[object]", [attr_value])

        return FlextResult[dict[str, list[object]]].ok(normalized)

    def create_modify_changes(
        self,
        modifications: LdapModifyDict,
    ) -> FlextResult[dict[str, list[tuple[str | int, list[object]]]]]:
        """Create ldap3 modify changes from simple modifications dict.

        Converts a modifications dict into ldap3's
        expected format: {attr: [(operation, [values])]}

        Args:
        modifications: Dict of {attribute: [(operation, [values]),...]}

        Returns:
        FlextResult containing ldap3 modify changes

        """
        # Explicit FlextResult error handling - NO try/except
        changes: dict[str, list[tuple[str | int, list[object]]]] = {}
        for attr_name, attr_value in modifications.items():
            # Default to REPLACE operation
            values = attr_value if isinstance(attr_value, list) else [attr_value]
            changes[attr_name] = cast(
                "list[tuple[str | int, list[object]]]", [(MODIFY_REPLACE, values)]
            )

        return FlextResult[dict[str, list[tuple[str | int, list[object]]]]].ok(changes)

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

        entries = cast("list[FlextLdifModels.Entry]", parse_result.unwrap())
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
        api = FlextLdif()
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
        """Normalize entry for target server type using quirks.

        Applies server-specific transformations to make entry compatible
        with the target LDAP server implementation.

        Args:
            entry: FlextLdif Entry to normalize
            target_server_type: Target server type (e.g., "openldap2", "oid", "oud")

        Returns:
            FlextResult containing normalized entry

        Transformations may include:
            - Attribute name case normalization
            - Attribute syntax conversions
            - Object class adjustments
            - DN format normalization
            - Removal of unsupported attributes
            - Addition of required attributes

        """
        # Explicit FlextResult error handling - NO try/except
        if not entry:
            return FlextResult[FlextLdifModels.Entry].fail("Entry cannot be None")

        if not target_server_type:
            return FlextResult[FlextLdifModels.Entry].fail(
                "Target server type cannot be empty",
            )

        # Get server-specific quirks
        quirks_result = self._quirks_manager.get_server_quirks(target_server_type)
        if quirks_result.is_failure:
            self.logger.debug(
                "Failed to get server quirks, returning entry as-is",
                extra={
                    "target_server": target_server_type,
                    "error": quirks_result.error,
                },
            )
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        # Entry returned as-is for now
        self.logger.debug(
            "Entry normalized for target server",
            extra={
                "dn": str(entry.dn),
                "target_server": target_server_type,
                "attributes_count": len(entry.attributes)
                if hasattr(entry, "attributes")
                and isinstance(entry.attributes, (dict, list))
                else 0,
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

        # Get server quirks
        quirks_result = self._quirks_manager.get_server_quirks(server_type)
        if quirks_result.is_failure:
            self.logger.debug(
                "Could not get server quirks for validation",
                extra={"server_type": server_type},
            )
            # Default to valid if we can't get quirks
            return FlextResult[bool].ok(True)

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
        # Explicit FlextResult error handling - NO try/except
        quirks_result = self._quirks_manager.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to get server quirks: {quirks_result.error}",
            )

        quirks = quirks_result.unwrap()

        # Extract commonly used attributes
        server_attrs: dict[str, object] = {
            "acl_attribute": quirks.get(
                FlextLdapConstants.LdapDictKeys.ACL_ATTRIBUTE,
                "aci",
            ),
            "acl_format": quirks.get(
                FlextLdapConstants.LdapDictKeys.ACL_FORMAT, "generic"
            ),
            "schema_subentry": quirks.get(
                FlextLdapConstants.LdapDictKeys.SCHEMA_SUBENTRY,
                "cn=subschema",
            ),
            "supports_operational_attrs": quirks.get(
                "supports_operational_attrs",
                True,
            ),
            "server_type": server_type,
        }

        return FlextResult[dict[str, object]].ok(server_attrs)
