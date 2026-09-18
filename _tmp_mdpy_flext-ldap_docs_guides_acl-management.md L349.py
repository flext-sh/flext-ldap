# from flext-ldap/docs/guides/acl-management.md:349
# Example: Convert Oracle OUD ACLs to OpenLDAP format
from flext_ldap import ldap
from flext_ldap import FlextLdapConstants

api = ldap()

# Read Oracle ACLs from OUD
oracle_acls = read_oracle_acls()  # Your existing function

# Convert each ACL
converted_acls = []
for acl in oracle_acls:
    result = api.convert_acl(
        acl, FlextLdapConstants.AclFormat.ORACLE, FlextLdapConstants.AclFormat.OPENLDAP
    )

    if result.success:
        converted_acls.append(result.unwrap().converted_acl)
    else:
        print(f"Conversion failed for: {acl} - {result.error}")

# Write to OpenLDAP configuration
write_openldap_acls(converted_acls)```
## Best Practices

1. **Always validate ACL syntax** before applying to production directory
1. **Test conversions** with sample ACLs before bulk migration
1. **Review conversion warnings** to understand potential feature loss
1. **Use unified model** for complex ACL manipulation
1. **Batch operations** for better performance with multiple ACLs

## API Reference

### ldap ACL Methods

- `parse(acl_string, format_type)` - Parse ACL to unified model
- `convert_acl(acl_string, source_format, target_format)` - Convert ACL between formats
- `batch_convert_acls(acl_list, source_format, target_format)` - Batch conversion
- `validate_acl_syntax(acl_string, format_type)` - Validate ACL syntax

### FlextLdapAclManager Methods

- `parse()` - Parse ACL to unified format
- `convert_acl()` - Convert between formats
- `batch_convert()` - Batch conversion
- `validate_acl_syntax()` - Syntax validation
- `create_unified_acl()` - Create from components

## See Also

- [FLEXT LDAP API Documentation](README.md)
- [Server Operations Guide](server-operations.md)
- [Clean Architecture Patterns](../architecture.md)
