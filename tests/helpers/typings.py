from __future__ import annotations

from flext_core import r

from flext_ldap.models import FlextLdapModels

type OperationResultType = r[FlextLdapModels.Ldap.OperationResult]

type SearchResultType = r[FlextLdapModels.Ldap.SearchResult]

type LdapEntry = FlextLdapModels.Ldif.Entry
