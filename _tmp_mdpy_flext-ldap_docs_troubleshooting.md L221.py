# from flext-ldap/docs/troubleshooting.md:221
from __future__ import annotations
from flext_ldap import m


def validate_dn(dn_string: str) -> bool:
    """Validate DN format."""
    try:
        dn = m.Ldif.DN(value=dn_string)
        return True
    except ValueError as e:
        print(f"Invalid DN: {e}")
        return False


# Test DN validation
test_dns = [
    "cn=John Doe,ou=users,dc=example,dc=com",
    "uid=john.doe,ou=people,dc=company,dc=org",
    "invalid-dn-format",
]

for test_dn in test_dns:
    result = validate_dn(test_dn)
    print(f"{test_dn}: {'✅' if result else '❌'}")```
______________________________________________________________________

## Search and Query Issues

### Search Filter Syntax Errors

**Symptom:**

