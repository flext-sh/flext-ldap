# from flext-ldap_docs/guides/acl-management.md:135
# Convert OpenLDAP to Oracle format
openldap_acl = "access to attrs=mail by users read"

conversion_result = api.convert_acl(
    openldap_acl,
    source_format=FlextLdapConstants.AclFormat.OPENLDAP,
    target_format=FlextLdapConstants.AclFormat.ORACLE,
)

if conversion_result.success:
    conv = conversion_result.unwrap()
    print(f"Oracle ACL: {conv.converted_acl}")
    # Output: access to attr=(mail) by group="*" (read)```
### Batch Conversion

