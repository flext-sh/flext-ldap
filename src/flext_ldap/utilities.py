"""FLEXT LDAP utility facade."""

from __future__ import annotations

from flext_ldif import u

from ._utilities.comparison import FlextLdapUtilitiesComparison
from ._utilities.conversion import FlextLdapUtilitiesConversion
from ._utilities.root_dse import FlextLdapUtilitiesRootDse
from ._utilities.server import FlextLdapUtilitiesServer
from ._utilities.validation import FlextLdapUtilitiesValidation


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
