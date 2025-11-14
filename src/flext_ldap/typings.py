"""LDAP Type Definitions - Type System for FLEXT LDAP Operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TypeVar

from flext_core import FlextTypes
from flext_ldif.models import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants

# Generic TypeVars
ServiceT = TypeVar("ServiceT", bound=object)


class FlextLdapTypes(FlextTypes):
    """LDAP-specific type definitions extending FlextTypes.

    Domain-specific type system for LDAP operations.
    Minimal types - reuses FlextLdifTypes when possible.
    """

    # =========================================================================
    # SERVICE RETURN TYPE ALIASES
    # =========================================================================

    type EntryOrString = FlextLdifModels.Entry | str
    type DnInput = str | FlextLdifModels.DistinguishedName

    # =========================================================================
    # LDAP OPERATION TYPES
    # =========================================================================

    SearchScope = FlextLdapConstants.LiteralTypes.SearchScope
    OperationType = FlextLdapConstants.LiteralTypes.OperationType

    # =========================================================================
    # LDAP SEARCH RESULT TYPES
    # =========================================================================

    type SearchResult = list[FlextLdifModels.Entry]
    type OperationResult = dict[str, object]
