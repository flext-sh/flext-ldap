from __future__ import annotations

from typing import TypeAlias

from flext_core import r

from flext_ldap.models import FlextLdapModels

OperationResultType: TypeAlias = r[FlextLdapModels.Ldap.OperationResult]

SearchResultType: TypeAlias = r[FlextLdapModels.Ldap.SearchResult]

LdapEntry: TypeAlias = FlextLdapModels.Ldif.Entry
