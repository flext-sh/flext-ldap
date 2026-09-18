# from flext-ldap_docs/guides/server-operations.md:367
# Get orclaci ACLs
acl_result = ops.get_acls(connection, dn="dc=example,dc=com")

if acl_result.success:
    acls = acl_result.unwrap()
    for acl in acls:
        print(f"OID ACL: {acl['raw']}")

# Set orclaci ACLs
oid_acls = [
    {
        "raw": 'access to entry by group="cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com" (browse,add,delete)'
    }
]

set_result = ops.set_acls(connection, "dc=example,dc=com", oid_acls)```
### **Oracle-Specific Features**

