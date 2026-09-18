# from flext-ldap_docs/getting-started.md:243
from __future__ import annotations

from flext_ldap.api import ldap


def authenticate_user():
    """Authenticate a user against LDAP."""
    api = ldap

    username = "john.doe"
    password = "user-password"

    result = api.authenticate_user(username, password)
    if result.success:
        user = result.unwrap()
        print(f"✅ Authentication successful for {user.uid}")
    else:
        print(f"❌ Authentication failed: {result.error}")


run(authenticate_user())```
______________________________________________________________________

## Universal LDAP Interface

### **Server-Specific Operations**

FLEXT-LDAP provides server-specific implementations with automatic server detection:

