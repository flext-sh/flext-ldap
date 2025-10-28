"""ACL parsers for FLEXT LDAP - Defers to flext-ldif for full ACL processing.

This module provides stub parsers that defer full ACL parsing responsibility
to flext-ldif, following FLEXT ecosystem architectural separation of concerns.

Full ACL parsing including server-specific format handling (OpenLDAP, Oracle OID/OUD,
Active Directory, etc.) is implemented in flext-ldif with proper FlextLdifModels
integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldap.constants import FlextLdapConstants


class FlextLdapAclParsers:
    """ACL parsers - delegates full parsing to flext-ldif."""

    def handle(self, message: object) -> FlextResult[FlextResult[object]]:
        """Handle ACL parsing operations with proper delegation to flext-ldif.

        Args:
            message: Message containing ACL format and string to parse.

        Returns:
            FlextResult indicating that ACL parsing should be handled by flext-ldif.

        Note:
            Full ACL parsing including server-specific format handling (OpenLDAP,
            Oracle, ACI, Active Directory) is implemented in flext-ldif to ensure
            proper FlextLdifModels validation and field compatibility.

        """
        if not isinstance(message, dict):
            return FlextResult[FlextResult[object]].fail(
                "Message must be a dictionary",
            )

        acl_string_raw = message.get(FlextLdapConstants.LdapDictKeys.ACL_STRING)
        if not isinstance(acl_string_raw, str) or not acl_string_raw:
            return FlextResult[FlextResult[object]].fail(
                "ACL string must be provided",
            )

        # Defer to flext-ldif for full ACL parsing
        wrapped_result = FlextResult[object].fail(
            "ACL parsing deferred to flext-ldif. Use flext-ldif.FlextLdifParsers "
            "for server-specific ACL format handling.",
        )
        return FlextResult[FlextResult[object]].ok(wrapped_result)


__all__ = ["FlextLdapAclParsers"]
