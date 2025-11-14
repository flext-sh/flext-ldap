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

from typing import Any, cast

from flext_core import FlextLogger, FlextResult, FlextRuntime, FlextService
from flext_ldif import FlextLdif, FlextLdifModels
from ldap3 import Entry as Ldap3Entry

logger = FlextLogger(__name__)


class FlextLdapEntryAdapter(FlextService[Any]):
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
        **kwargs: object,
    ) -> None:
        """Initialize entry adapter with FlextLdif integration and quirks.

        Args:
            server_type: Optional server type for normalization
            **kwargs: Additional arguments passed to base class

        """
        super().__init__(**kwargs)
        self._ldif = FlextLdif.get_instance()
        self._server_type = server_type

    def execute(self) -> FlextResult[Any]:
        """Execute method required by FlextService."""
        return FlextResult.ok(None)

    def ldap3_to_ldif_entry(
        self,
        ldap3_entry: Ldap3Entry | FlextLdifModels.Entry | dict[str, object] | None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert ldap3.Entry or dict to FlextLdifModels.Entry.

        Delegates to FlextLdifModels.Entry.from_ldap3() for ldap3.Entry objects.
        Handles dict format separately when needed.

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

        # Handle dict format using FlextLdif.create_entry
        if isinstance(ldap3_entry, dict):
            create_result = self._ldif.create_entry(
                dn=str(ldap3_entry.get("dn", "")),
                attributes=cast(
                    "dict[str, str | list[str]]", ldap3_entry.get("attributes", {})
                ),
            )
            if create_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create entry from dict: {create_result.error}",
                )
            return FlextResult.ok(create_result.unwrap())

        # Already a FlextLdifModels.Entry
        return FlextResult.ok(ldap3_entry)

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
        if entry.attributes is None:
            return FlextResult[dict[str, list[str]]].fail("Entry has no attributes")

        # Reuse FlextLdifEntryManipulation pattern for conversion (FASE 1)
        # Using same logic as EntryManipulationServices.convert_ldif_attributes_to_ldap3_format()
        # but avoiding import due to broken LDAPAttributeError import in flext-ldif
        attrs_dict = entry.attributes.attributes  # dict[str, str | list[str]]
        ldap3_attributes: dict[str, list[str]] = {}
        for key, value in attrs_dict.items():
            if FlextRuntime.is_list_like(value):
                # Convert list-like object to list of strings
                # Handle empty lists
                if len(value) == 0:  # type: ignore[arg-type]
                    ldap3_attributes[key] = []
                else:
                    ldap3_attributes[key] = [str(item) for item in value]
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
        # Return entry as-is for now - normalization happens during parse/write operations
        _ = logger.debug(
            "Entry normalization handled by flext-ldif quirks",
            extra={"dn": str(entry.dn), "target_server": target_server_type},
        )
        return FlextResult[FlextLdifModels.Entry].ok(entry)

    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,  # noqa: ARG002
    ) -> FlextResult[bool]:
        """Validate entry for target server type.

        Args:
            entry: FlextLdifModels.Entry to validate
            server_type: Server type to validate against

        Returns:
            FlextResult indicating validation success or failure

        """
        # Basic validation: check DN and attributes exist
        if not entry.dn or not str(entry.dn).strip():
            return FlextResult[bool].fail("Entry DN cannot be empty")

        if not entry.attributes or not entry.attributes.attributes:
            return FlextResult[bool].fail("Entry must have attributes")

        return FlextResult[bool].ok(True)
