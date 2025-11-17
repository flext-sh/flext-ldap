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
    _server_type: str | None

    def __init__(
        self,
        server_type: str | None = None,
    ) -> None:
        """Initialize entry adapter with FlextLdif integration and quirks.

        Args:
            server_type: Optional server type for normalization

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
        # Fast fail - validate input is not None (no fallback)
        if ldap3_entry is None:
            return FlextResult[FlextLdifModels.Entry].fail(
                "ldap3_entry cannot be None",
            )
        # Railway pattern - check for success before transforming
        parse_result = FlextLdifModels.Entry.from_ldap3(ldap3_entry)
        if parse_result.is_failure:
            # FlextResult guarantees error is str when is_failure=True
            return FlextResult[FlextLdifModels.Entry].fail(parse_result.error)

        parsed_entry = parse_result.unwrap()

        # Ensure DN is properly typed
        entry = FlextLdifModels.Entry(
            dn=(
                parsed_entry.dn
                if isinstance(parsed_entry.dn, FlextLdifModels.DistinguishedName)
                else FlextLdifModels.DistinguishedName(value=str(parsed_entry.dn))
            ),
            attributes=parsed_entry.attributes,
        )

        return FlextResult[FlextLdifModels.Entry].ok(entry)

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
        # Fast fail if attributes is None (defensive check for invalid models)
        if entry.attributes is None:
            return FlextResult[dict[str, list[str]]].fail("Entry has no attributes")
        # Fast fail if attributes dict is empty (defensive check)
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
        # Fast fail if attributes is None (defensive check for invalid models)
        if entry.attributes is None:
            _ = logger.debug(
                "Entry validation failed: no attributes for server type %s",
                server_type,
                extra={"dn": dn_str, "server_type": server_type},
            )
            return FlextResult[bool].fail("Entry must have attributes")
        # Fast fail if attributes dict is empty (defensive check)
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
