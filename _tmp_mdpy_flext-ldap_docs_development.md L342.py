# from flext-ldap/docs/development.md:342
from __future__ import annotations

# ✅ CORRECT - Parameter objects for complex operations
@dataclass
class SearchRequest:
    base_dn: str
    filter_str: str
    scope: str
    attributes: t.StringList
    size_limit: int = 100
    time_limit: int = 30

def search_entries(self, request: SearchRequest) -> p.Result[List[LdapEntry]]:
    # Implementation using parameter object

# ❌ WRONG - Multiple parameters
def search_entries(self, base_dn: str, filter_str: str, scope: str,
                        attributes: t.StringList, size_limit: int, time_limit: int):
    # FORBIDDEN - use parameter objects```
**4. Value Object Validation**

