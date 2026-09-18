# from flext-ldap_docs/troubleshooting.md:169
from __future__ import annotations

from flext_ldap.api import ldap


def diagnose_auth():
    api = ldap

    # Test connection without authentication
    connection_result = api.test_connection()
    print(f"Connection: {connection_result.success}")

    # Test with known REDACTED_LDAP_BIND_PASSWORD credentials
    auth_result = api.authenticate_user(
        "REDACTED_LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD-password"
    )
    print(f"Auth result: {auth_result.success}")
    if auth_result.failure:
        print(f"Error: {auth_result.error}")


run(diagnose_auth())```
**Solutions:**

1. **Verify bind DN format** - must be RFC 4514 compliant
1. **Check bind password** - ensure no special characters are escaped incorrectly
1. **Confirm user exists** in the directory
1. **Test with LDAP REDACTED_LDAP_BIND_PASSWORD tools** first

### DN Format Issues

**Symptom:**

