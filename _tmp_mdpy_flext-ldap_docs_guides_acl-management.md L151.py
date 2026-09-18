# from flext-ldap/docs/guides/acl-management.md:151
# Convert multiple ACLs at once
acl_list = [
    "access to attrs=cn by self write",
    "access to attrs=mail by users read",
    "access to attrs=telephoneNumber by self write",
]

batch_result = api.batch_convert_acls(
    acl_list,
    source_format=FlextLdapConstants.AclFormat.OPENLDAP,
    target_format=FlextLdapConstants.AclFormat.ACI,
)

if batch_result.success:
    for conv in batch_result.unwrap():
        print(f"Converted: {conv.converted_acl}")```
## ACL Format Examples

### OpenLDAP Format

