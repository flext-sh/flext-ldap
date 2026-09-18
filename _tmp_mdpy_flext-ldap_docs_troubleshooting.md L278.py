# from flext-ldap/docs/troubleshooting.md:278
from __future__ import annotations


def validate_filter(filter_string: str) -> bool:
    """Validate LDAP filter syntax."""
    try:
        ldap_filter = FlextLdapModels.Values.Filter(expression=filter_string)
        return True
    except ValueError as e:
        print(f"Invalid filter: {e}")
        return False


# Test filters
test_filters = [
    "(objectClass=person)",
    "(&(objectClass=person)(uid=j*))",
    "(|(cn=John*)(mail=*@example.com))",
    "invalid-filter-format",
]

for test_filter in test_filters:
    result = validate_filter(test_filter)
    print(f"{test_filter}: {'✅' if result else '❌'}")```
### Search Base DN Not Found

**Symptom:**

