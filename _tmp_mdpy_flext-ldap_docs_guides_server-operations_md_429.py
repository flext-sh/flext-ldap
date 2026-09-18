# from flext-ldap_docs/guides/server-operations.md:429
# Get ds-privilege-name ACLs
acl_result = ops.get_acls(connection, dn="dc=example,dc=com")

# Set ds-privilege-name ACLs
oud_acls = [{"raw": "bypass-acl"}, {"raw": "settings-read"}, {"raw": "password-reset"}]

set_result = ops.set_acls(
    connection, "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", oud_acls
)```
### **OUD-Specific Features**

