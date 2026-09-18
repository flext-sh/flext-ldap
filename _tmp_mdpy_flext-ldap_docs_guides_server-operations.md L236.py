# from flext-ldap/docs/guides/server-operations.md:236
# Get ACLs from cn=settings entry
acl_result = ops.get_acls(connection, dn="olcDatabase={1}mdb,cn=settings")

if acl_result.success:
    acls = acl_result.unwrap()
    for acl in acls:
        print(f"ACL: {acl}")

# Set ACLs
new_acls = [
    {"raw": '{0}to * by dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" write'},
    {"raw": "{1}to * by self write by anonymous auth"},
]

set_result = ops.set_acls(
    connection, dn="olcDatabase={1}mdb,cn=settings", acls=new_acls
)```
### **Entry Operations**

