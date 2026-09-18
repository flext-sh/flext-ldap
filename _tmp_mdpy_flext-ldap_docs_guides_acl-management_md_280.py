# from flext-ldap_docs/guides/acl-management.md:280
# Parse OpenLDAP slapd.conf ACLs
openldap_acls = [
    "access to attrs=userPassword by self write by anonymous auth",
    'access to dn.exact="ou=users,dc=example,dc=com" by users read',
]

# Convert to ACI format for 389 DS
for acl in openldap_acls:
    result = api.convert_acl(
        acl, FlextLdapConstants.AclFormat.OPENLDAP, FlextLdapConstants.AclFormat.ACI
    )

    if result.success:
        conv = result.unwrap()
        print(f"389 DS ACI: {conv.converted_acl}")```
## Advanced Features

### ACL with Conditions

