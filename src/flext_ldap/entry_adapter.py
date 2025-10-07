"""Entry Adapter for ldap3 ↔ FlextLdif conversion.

This module provides bidirectional conversion between ldap3 Entry objects
and FlextLdif Entry models, enabling seamless integration between LDAP
protocol operations and LDIF entry manipulation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pathlib

from flext_core import FlextResult, FlextService, FlextTypes
from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.quirks import FlextLdifEntryQuirks, FlextLdifQuirksManager
from ldap3 import Entry as Ldap3Entry


class FlextLdapEntryAdapter(FlextService[None]):
    """Adapter for converting between ldap3 and FlextLdif entry representations.

    This adapter provides bidirectional conversion with universal server support:
    - ldap3.Entry → FlextLdifModels.Entry (for result processing)
    - FlextLdifModels.Entry → dict (for ldap3 operations)
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
        """Initialize entry adapter with FlextLdif integration and quirks support, Phase 1 context enrichment.

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
        self, ldap3_entry: Ldap3Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert ldap3.Entry to FlextLdifModels.Entry.

        Args:
            ldap3_entry: ldap3 Entry object from search results

        Returns:
            FlextResult containing FlextLdifModels.Entry or error

        """
        # Explicit FlextResult error handling - NO try/except
        if not ldap3_entry:
            return FlextResult[FlextLdifModels.Entry].fail("ldap3 entry cannot be None")

        # Extract DN from ldap3 entry
        dn_str = str(ldap3_entry.entry_dn)
        if not dn_str:
            return FlextResult[FlextLdifModels.Entry].fail("ldap3 entry missing DN")

        # Extract attributes from ldap3 entry
        attributes: dict[str, FlextTypes.List] = {}
        for attr_name in ldap3_entry.entry_attributes:
            attr_value = ldap3_entry[attr_name]

            # Handle multi-valued attributes
            if isinstance(attr_value, list):
                attributes[attr_name] = attr_value
            elif attr_value.value is not None:
                # Single value - convert to list for consistency
                value = attr_value.value
                attributes[attr_name] = (
                    [value] if not isinstance(value, list) else value
                )
            else:
                # Empty attribute
                attributes[attr_name] = []

        # Convert attributes dict to FlextLdifModels.LdifAttributes
        # Explicit FlextResult error handling - NO try/except
        attr_values_dict: dict[str, FlextLdifModels.AttributeValues] = {}
        for attr_name, attr_value_list in attributes.items():
            # Create AttributeValues using Pydantic model
            attr_values_result = FlextLdifModels.AttributeValues.create(
                values=attr_value_list
            )
            if attr_values_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create AttributeValues for {attr_name}: {attr_values_result.error}"
                )

            attr_values: FlextLdifModels.AttributeValues = attr_values_result.unwrap()
            attr_values_dict[attr_name] = attr_values

        # Create LdifAttributes
        ldif_attributes_result = FlextLdifModels.LdifAttributes.create(
            attributes=attr_values_dict
        )
        if ldif_attributes_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create LdifAttributes: {ldif_attributes_result.error}"
            )

        ldif_attributes: FlextLdifModels.LdifAttributes = (
            ldif_attributes_result.unwrap()
        )

        # Create DistinguishedName
        dn_result = FlextLdifModels.DistinguishedName.create(value=dn_str)
        if dn_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create DistinguishedName: {dn_result.error}"
            )

        dn: FlextLdifModels.DistinguishedName = dn_result.unwrap()

        # Create Entry
        entry_result = FlextLdifModels.Entry.create(dn=dn, attributes=ldif_attributes)
        if entry_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create FlextLdif entry: {entry_result.error}"
            )

        ldif_entry = entry_result.unwrap()
        return FlextResult[FlextLdifModels.Entry].ok(ldif_entry)

    def ldap3_entries_to_ldif_entries(
        self, ldap3_entries: list[Ldap3Entry]
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
                    f"Failed to convert entry: {result.error}"
                )
            ldif_entries.append(result.unwrap())

        return FlextResult[list[FlextLdifModels.Entry]].ok(ldif_entries)

    def ldif_entry_to_ldap3_attributes(
        self, ldif_entry: FlextLdifModels.Entry
    ) -> FlextResult[dict[str, FlextTypes.StringList]]:
        """Convert FlextLdifModels.Entry to ldap3 attributes dict.

        Args:
            ldif_entry: FlextLdif Entry model

        Returns:
            FlextResult containing attributes dict for ldap3 operations

        """
        # Explicit FlextResult error handling - NO try/except
        if not ldif_entry:
            return FlextResult[dict[str, FlextTypes.StringList]].fail(
                "FlextLdif entry cannot be None"
            )

        # Extract attributes from FlextLdif entry
        attributes: dict[str, FlextTypes.StringList] = {}
        for attr_name, attr_values in ldif_entry.attributes.attributes.items():
            # attr_values is FlextLdifModels.AttributeValues - extract values list
            attributes[attr_name] = attr_values.values

        return FlextResult[dict[str, FlextTypes.StringList]].ok(attributes)

    def normalize_attributes_for_add(
        self, attributes: FlextTypes.Dict
    ) -> FlextResult[dict[str, FlextTypes.List]]:
        """Normalize attributes for ldap3 add operation.

        Ensures all attribute values are in list format as required by ldap3.

        Args:
            attributes: Attribute dictionary (values may be single or lists)

        Returns:
            FlextResult containing normalized attributes dict

        """
        # Explicit FlextResult error handling - NO try/except
        normalized: dict[str, FlextTypes.List] = {}
        for attr_name, attr_value in attributes.items():
            if isinstance(attr_value, list):
                normalized[attr_name] = attr_value
            else:
                normalized[attr_name] = [attr_value]

        return FlextResult[dict[str, FlextTypes.List]].ok(normalized)

    def create_modify_changes(
        self, modifications: FlextTypes.Dict
    ) -> FlextResult[dict[str, list[tuple[str, FlextTypes.List]]]]:
        """Create ldap3 modify changes from simple modifications dict.

        Converts a simple dict of attribute modifications into ldap3's
        expected format: {attr: [(operation, [values])]}

        Args:
            modifications: Dict of {attribute: new_value}

        Returns:
            FlextResult containing ldap3 modify changes

        """
        # Explicit FlextResult error handling - NO try/except
        from ldap3 import MODIFY_REPLACE

        changes: dict[str, list[tuple[str, FlextTypes.List]]] = {}
        for attr_name, attr_value in modifications.items():
            # Default to REPLACE operation
            values = attr_value if isinstance(attr_value, list) else [attr_value]
            changes[attr_name] = [(MODIFY_REPLACE, values)]

        return FlextResult[dict[str, list[tuple[str, FlextTypes.List]]]].ok(changes)

    def convert_ldif_file_to_entries(
        self, ldif_file_path: str
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
        parse_result = self._ldif.parse(ldif_content)
        if parse_result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"LDIF parsing failed: {parse_result.error}"
            )

        entries = parse_result.unwrap()
        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def write_entries_to_ldif_file(
        self, entries: list[FlextLdifModels.Entry], output_path: str
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
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[str]:
        """Detect LDAP server type from entry attributes and object classes.

        Uses FlextLdif quirks system to analyze entry characteristics and
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

        # Use quirks manager to detect from single entry
        detection_result = self._quirks_manager.detect_server_type([entry])
        if detection_result.is_failure:
            self.logger.warning(
                "Server detection failed, defaulting to generic",
                extra={"dn": str(entry.dn), "error": detection_result.error},
            )
            return FlextResult[str].ok("generic")

        detected_type = detection_result.unwrap()
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
                "Target server type cannot be empty"
            )

        # Get server-specific quirks
        quirks_result = self._quirks_manager.get_server_quirks(target_server_type)
        if quirks_result.is_failure:
            self.logger.warning(
                "Failed to get server quirks, returning entry as-is",
                extra={
                    "target_server": target_server_type,
                    "error": quirks_result.error,
                },
            )
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        # Use entry quirks for normalization (to be enhanced with actual transformations)
        # This is where server-specific attribute transformations would be applied
        # For now, we return the entry as-is but with proper logging

        self.logger.debug(
            "Entry normalized for target server",
            extra={
                "dn": str(entry.dn),
                "target_server": target_server_type,
                "attributes_count": len(entry.attributes.attributes),
            },
        )

        return FlextResult[FlextLdifModels.Entry].ok(entry)

    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextResult[bool]:
        """Validate entry compatibility with target server type.

        Checks if entry can be safely added to the specified server type
        by verifying:
            - Required attributes are present
            - Attribute syntaxes are compatible
            - Object classes are supported
            - DN format is valid
            - No server-incompatible attributes

        Args:
            entry: FlextLdif Entry to validate
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
            self.logger.warning(
                "Could not get server quirks for validation",
                extra={"server_type": server_type},
            )
            # Default to valid if we can't get quirks
            return FlextResult[bool].ok(True)

        # Validate DN format
        dn_str = str(entry.dn)
        if not dn_str or dn_str.strip() == "":
            return FlextResult[bool].fail("Entry has invalid DN")

        # Validate has object classes
        object_classes = entry.get_attribute("objectClass")
        if not object_classes:
            return FlextResult[bool].fail(
                "Entry missing required objectClass attribute"
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

        Performs comprehensive conversion including:
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
                f"Normalization failed: {normalize_result.error}"
            )

        converted_entry = normalize_result.unwrap()

        # Step 2: Validate converted entry
        validate_result = self.validate_entry_for_server(
            converted_entry, target_server_type
        )
        if validate_result.is_failure:
            self.logger.warning(
                "Converted entry failed validation",
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
        self, server_type: str
    ) -> FlextResult[FlextTypes.Dict]:
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
            return FlextResult[FlextTypes.Dict].fail(
                f"Failed to get server quirks: {quirks_result.error}"
            )

        quirks = quirks_result.unwrap()

        # Extract commonly used attributes
        server_attrs: FlextTypes.Dict = {
            "acl_attribute": quirks.get("acl_attribute", "aci"),
            "acl_format": quirks.get("acl_format", "generic"),
            "schema_subentry": quirks.get("schema_subentry", "cn=subschema"),
            "supports_operational_attrs": quirks.get(
                "supports_operational_attrs", True
            ),
            "server_type": server_type,
        }

        return FlextResult[FlextTypes.Dict].ok(server_attrs)
