# from flext-ldap_docs/guides/acl-management.md:241
# Validate ACL syntax
acl_string = "access to attrs=mail by self write"

validation_result = api.validate_acl_syntax(
    acl_string, FlextLdapConstants.AclFormat.OPENLDAP
)

if validation_result.success:
    print("ACL syntax is valid")
else:
    print(f"Invalid ACL: {validation_result.error}")```
## Migration Scenarios

### Oracle to OpenLDAP Migration

