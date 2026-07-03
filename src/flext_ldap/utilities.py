"""FLEXT LDAP utility facade."""

from __future__ import annotations

from flext_ldap._utilities.comparison import FlextLdapUtilitiesComparison
from flext_ldap._utilities.conversion import FlextLdapUtilitiesConversion
from flext_ldap._utilities.root_dse import FlextLdapUtilitiesRootDse
from flext_ldap._utilities.server import FlextLdapUtilitiesServer
from flext_ldap._utilities.validation import FlextLdapUtilitiesValidation
from flext_ldif import u


class FlextLdapUtilities(u):
    """LDAP-specific utility facade."""

    class Ldap(
        FlextLdapUtilitiesServer,
        FlextLdapUtilitiesConversion,
        FlextLdapUtilitiesComparison,
        FlextLdapUtilitiesRootDse,
    ):
        """LDAP-specific utility namespace."""

        Validation: type[FlextLdapUtilitiesValidation] = FlextLdapUtilitiesValidation


u = FlextLdapUtilities

__all__: list[str] = ["FlextLdapUtilities", "u"]
