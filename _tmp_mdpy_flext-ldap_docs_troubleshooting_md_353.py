# from flext-ldap_docs/troubleshooting.md:353
from __future__ import annotations

import time
from flext_ldap import FlextLdapEntities
from flext_ldap.api import ldap


def diagnose_performance():
    api = ldap

    # Test different search scopes and filters
    test_cases = [
        {
            "name": "Base scope (fastest)",
            "base_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "scope": "base",
            "filter": "(objectClass=*)",
        },
        {
            "name": "One level scope",
            "base_dn": "dc=example,dc=com",
            "scope": "onelevel",
            "filter": "(objectClass=organizationalUnit)",
        },
        {
            "name": "Subtree scope (slowest)",
            "base_dn": "dc=example,dc=com",
            "scope": "subtree",
            "filter": "(objectClass=person)",
        },
    ]

    for test_case in test_cases:
        start_time = time.time()

        search_request = FlextLdapEntities.SearchRequest(
            base_dn=test_case["base_dn"],
            filter_str=test_case["filter"],
            scope=test_case["scope"],
            attributes=["dn"],
            size_limit=100,
        )

        result = api.search_entries(search_request)
        duration = time.time() - start_time

        if result.success:
            count = len(result.unwrap())
            print(f"{test_case['name']}: {count} results in {duration:.2f}s")
        else:
            print(f"{test_case['name']}: Failed - {result.error}")


run(diagnose_performance())```
**Optimization Solutions:**

1. **Use specific base DNs:**

