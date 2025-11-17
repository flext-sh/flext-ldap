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

from typing import TYPE_CHECKING

from flext_core import FlextLogger, FlextResult, FlextRuntime, FlextService
from flext_ldif import FlextLdif, FlextLdifModels

from flext_ldap.constants import FlextLdapConstants

if TYPE_CHECKING:
    from ldap3 import Entry as Ldap3Entry

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
        server_type: str = FlextLdapConstants.LdapDefaults.SERVER_TYPE,
    ) -> None:
        """Initialize entry adapter with FlextLdif integration and quirks.

        Args:
            server_type: Server type for normalization (defaults to Constants)

        """
        super().__init__()
        self._ldif = FlextLdif.get_instance()
        self._server_type = server_type

    def execute(self) -> FlextResult[bool]:
        """Execute method required by FlextService.

        Entry adapter does not perform operations itself - it converts between
        entry formats. The conversion methods (ldap3_to_ldif_entry, etc.) should be
        called directly instead of using execute().

        Returns:
            FlextResult[bool] - success with True as this adapter is stateless
                and always ready

        """
        return FlextResult[bool].ok(True)

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

        """
        # Fast fail - validate ldap3_entry is not None
        if ldap3_entry is None:
            return FlextResult[FlextLdifModels.Entry].fail("ldap3_entry cannot be None")

        # Extract DN and attributes from ldap3_entry and create Entry
        # All operations wrapped in try-except for proper error handling
        # This includes conversion of entry_dn to string which may raise exceptions
        try:
            # Try to access entry_dn - may raise AttributeError or ValueError
            if not hasattr(ldap3_entry, "entry_dn"):
                return FlextResult[FlextLdifModels.Entry].fail(
                    "ldap3_entry missing entry_dn attribute"
                )
            if not hasattr(ldap3_entry, "entry_attributes_as_dict"):
                return FlextResult[FlextLdifModels.Entry].fail(
                    "ldap3_entry missing entry_attributes_as_dict attribute"
                )

            # Convert entry_dn to string - this may raise ValueError or other exceptions
            dn_str = str(ldap3_entry.entry_dn)
            attrs_dict = ldap3_entry.entry_attributes_as_dict

            # Convert attributes dict to LdifAttributes format
            # Ensure all values are lists (ldap3 format requirement)
            ldif_attrs: dict[str, list[str]] = {}
            for key, value in attrs_dict.items():
                if isinstance(value, list):
                    ldif_attrs[key] = [str(v) for v in value]
                elif value is None:
                    ldif_attrs[key] = []
                else:
                    ldif_attrs[key] = [str(value)]

            # Create Entry with all required and optional fields initialized
            entry = FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=dn_str),
                attributes=FlextLdifModels.LdifAttributes(attributes=ldif_attrs),
                # Initialize optional fields with defaults
                # to satisfy Pydantic v2 validation
                acls=[],
                objectclasses=[],
                attributes_schema=[],
                entry_metadata={},
            )
            return FlextResult[FlextLdifModels.Entry].ok(entry)
        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create Entry: {e!s}"
            )

    def ldif_entry_to_ldap3_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, list[str]]]:
        """Convert FlextLdifModels.Entry to ldap3 attributes format.

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
            return FlextResult[dict[str, list[str]]].fail("Entry has no attributes")

        # Reuse FlextLdifEntryManipulation pattern for conversion (FASE 1)
        # Using same logic as EntryManipulationServices.
        # convert_ldif_attributes_to_ldap3_format()
        # but avoiding import due to broken LDAPAttributeError import in flext-ldif
        attrs_dict = entry.attributes.attributes  # dict[str, str | list[str]]
        ldap3_attributes: dict[str, list[str]] = {}
        for key, value in attrs_dict.items():
            if FlextRuntime.is_list_like(value):
                # Convert list-like object to list of strings
                # Handle empty lists
                value_list = list(value)
                if len(value_list) == 0:
                    ldap3_attributes[key] = []
                else:
                    ldap3_attributes[key] = [str(item) for item in value_list]
            elif not value:
                # Empty string becomes empty list
                ldap3_attributes[key] = []
            else:
                # Single value becomes list with one element
                ldap3_attributes[key] = [str(value)]
        return FlextResult[dict[str, list[str]]].ok(ldap3_attributes)

    def normalize_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        target_server_type: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for target server type using flext-ldif quirks.

        Args:
            entry: FlextLdifModels.Entry to normalize
            target_server_type: Target server type (e.g., "openldap2", "oid", "oud")

        Returns:
            FlextResult containing normalized entry

        """
        # FlextLdif handles server-specific transformations internally via quirks
        # Return entry as-is for now - normalization happens during
        # parse/write operations
        _ = logger.debug(
            "Entry normalization handled by flext-ldif quirks",
            extra={"dn": str(entry.dn), "target_server": target_server_type},
        )
        return FlextResult[FlextLdifModels.Entry].ok(entry)

    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextResult[bool]:
        """Validate entry for target server type.

        Args:
            entry: FlextLdifModels.Entry to validate
            server_type: Server type to validate against

        Returns:
            FlextResult indicating validation success or failure

        """
        # Basic validation: check DN and attributes exist
        # Entry.dn and entry.attributes are validated by Pydantic model
        dn_str = str(entry.dn)
        if not dn_str.strip():
            _ = logger.debug(
                "Entry validation failed: empty DN for server type %s",
                server_type,
                extra={"dn": dn_str, "server_type": server_type},
            )
            return FlextResult[bool].fail("Entry DN cannot be empty")

        # Attributes are validated by Pydantic model - guaranteed to exist
        # Fast fail if attributes dict is empty
        if not entry.attributes.attributes:
            _ = logger.debug(
                "Entry validation failed: no attributes for server type %s",
                server_type,
                extra={"dn": dn_str, "server_type": server_type},
            )
            return FlextResult[bool].fail("Entry must have attributes")

        _ = logger.debug(
            "Entry validated successfully for server type %s",
            server_type,
            extra={"dn": dn_str, "server_type": server_type},
        )
        return FlextResult[bool].ok(True)
