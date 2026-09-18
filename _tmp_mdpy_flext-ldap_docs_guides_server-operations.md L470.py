# from flext-ldap/docs/guides/server-operations.md:470
from flext_ldap import ActiveDirectoryOperations

ops = ActiveDirectoryOperations()

# Available methods (return NotImplementedError)
try:
    schema_result = ops.discover_schema(connection)
except Exception as e:
    print(f"AD not implemented: {e}")
    # Output: "Active Directory schema discovery not yet implemented..."

# Basic info available
port = ops.get_default_port()  # 389 (LDAP) or 636 (LDAPS)
acl_attr = ops.get_acl_attribute_name()  # "nTSecurityDescriptor"
schema_dn = ops.get_schema_dn()  # "cn=schema,cn=configuration"```
### **Contributing AD Implementation**

If you want to contribute Active Directory support:

1. Implement schema discovery with AD schema format
1. Implement nTSecurityDescriptor parsing and formatting
1. Handle GUID-based DNs
1. Implement AD-specific entry normalization
1. Add Global Catalog support

See `src/flext_ldap/servers/ad_operations.py` for stub methods.

##

## 🔧 Generic Server Operations

### **Purpose**

RFC-compliant fallback for unknown or unimplemented LDAP servers. Provides basic operations that should work with any RFC 4510-compliant server.

### **Features**

- **aci** attribute (generic format)
- **cn=subschema** schema location (RFC 4512)
- Basic LDAP operations
- Conservative defaults
- Paged search support

### **Usage**

