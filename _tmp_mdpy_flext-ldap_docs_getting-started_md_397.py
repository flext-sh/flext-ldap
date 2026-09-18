# from flext-ldap_docs/getting-started.md:397
from __future__ import annotations

from flext_ldap import OpenLDAP2Operations
import ldap3


def manage_acls():
    """Get and set ACLs on OpenLDAP 2.x server."""
    ops = OpenLDAP2Operations()

    connection = ldap3.Connection(
        ldap3.Server("ldap://server:389"),
        user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        password="password",
        auto_bind=True,
    )

    # Get ACLs
    dn = "olcDatabase={1}mdb,cn=settings"
    acl_result = ops.get_acls(connection, dn)

    if acl_result.success:
        acls = acl_result.unwrap()
        print(f"Found {len(acls)} ACLs")

        # Set new ACLs
        new_acls = [
            {
                "raw": '{0}to * by dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" write'
            },
            {"raw": "{1}to * by self write by anonymous auth"},
        ]

        set_result = ops.set_acls(connection, dn, new_acls)
        if set_result.success:
            print("ACLs updated successfully")


run(manage_acls())```
### **Paged Search**

Execute paged searches with automatic pagination:

