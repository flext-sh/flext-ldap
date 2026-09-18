# from flext-ldap/docs/guides/acl-management.md:194
# Simple ACI
'(target="ldap:///ou=users,dc=example,dc=com")(version 3.0; acl "User Read"; allow (read) userdn="ldap:///anyone";)'

# Deny ACL
'(target="ldap:///dc=example,dc=com")(version 3.0; acl "Deny Delete"; deny (delete) userdn="ldap:///anyone";)'

# Group-based ACI
'(target="ldap:///ou=data,dc=example,dc=com")(version 3.0; acl "Admin Access"; allow (read,
    write) groupdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com";)'```
## Creating Custom ACLs

### Using the Unified Model

