# from flext-ldap_docs/getting-started.md:192
from __future__ import annotations

from flext_ldap.api import ldap


def test_connection():
    """Test basic LDAP connectivity."""
    api = ldap

    result = api.test_connection()
    if result.success:
        print("✅ LDAP connection successful")
    else:
        print(f"❌ Connection failed: {result.error}")


run(test_connection())```
### **Simple Directory Search**

