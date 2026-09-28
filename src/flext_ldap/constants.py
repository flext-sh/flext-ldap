"""FlextLdap constants module.

This module provides constants for LDAP operations, extending c.
"""

from __future__ import annotations

from flext_ldif import FlextLdifConstants

from ._constants.base import FlextLdapConstantsBase


class FlextLdapConstants(FlextLdifConstants):
    """FlextLdap domain constants extending c.

    Hierarchy:
    FlextConstants (flext-core)
    -> c (flext-ldif)
    -> FlextLdapConstants (this module)

    Access patterns:
    - c.Ldap.* (LDAP-specific constants)
    - c.Ldif.* (inherited from c - do NOT override)
    - c.* (inherited from FlextConstants via c)

    NOTE: Ldif namespace is inherited from parent - do NOT override.
    """

    class Ldap(FlextLdapConstantsBase):
        """LDAP-related constants.

        Every constant and enumeration is owned by the private ``_constants``
        tier (``FlextLdapConstantsBase`` over ``FlextLdapConstantsEnums``,
        ENFORCE-079) and re-exported here via inheritance; ``c.Ldap.*``
        resolves through the MRO.
        """


c = FlextLdapConstants

__all__: list[str] = ["FlextLdapConstants", "c"]
