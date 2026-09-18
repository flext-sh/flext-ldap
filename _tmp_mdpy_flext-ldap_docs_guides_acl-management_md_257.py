# from flext-ldap_docs/guides/acl-management.md:257
# Parse Oracle ACLs from existing directory
oracle_acls = [
    'access to attr=(cn, sn) by group="cn=users" (read)',
    'access to attr=(userPassword) by group="cn=REDACTED_LDAP_BIND_PASSWORDs" (write)',
    'access to entry by user="cn=REDACTED_LDAP_BIND_PASSWORD" (read,write,delete)',
]

# Convert to OpenLDAP format
for oracle_acl in oracle_acls:
    result = api.convert_acl(
        oracle_acl,
        FlextLdapConstants.AclFormat.ORACLE,
        FlextLdapConstants.AclFormat.OPENLDAP,
    )

    if result.success:
        conv = result.unwrap()
        print(f"OpenLDAP ACL: {conv.converted_acl}")
        if conv.warnings:
            print(f"Warnings: {conv.warnings}")```
### OpenLDAP to 389 DS Migration

