# from flext-ldap_docs/api-reference.md:816
from flext_ldap import OpenLDAP2Operations

ops = OpenLDAP2Operations()

# Get ACLs from cn=settings entry
result = ops.get_acls(connection, dn="olcDatabase={1}mdb,cn=settings")

if result.success:
    acls = result.unwrap()
    for acl in acls:
        print(f"ACL: {acl.get('raw')}")```
##### `set_acls(connection, dn, acls) -> p.Result[bool]`

Set ACLs on entry.

**Example:**

