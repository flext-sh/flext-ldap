# from flext-ldap/docs/guides/server-operations.md:441
# Extended SASL mechanisms
mechanisms = ops.get_bind_mechanisms()
# Returns: ["SIMPLE", "SASL/EXTERNAL", "SASL/DIGEST-MD5", "SASL/GSSAPI", "SASL/PLAIN"]

# Schema location
schema_dn = ops.get_schema_dn()  # "cn=schema"

# VLV and paged results
supports_vlv = ops.supports_vlv()  # True
supports_paging = ops.supports_paged_results()  # True```
##

## 🔧 Active Directory Operations (Stub)

### **Status**

Currently implemented as a stub with `NotImplementedError` for most operations. Provides the interface for future implementation.

### **Planned Features**

- **nTSecurityDescriptor** ACLs (Windows Security Descriptor format)
- **cn=schema,cn=configuration** schema location
- GUID-based DNs
- Global Catalog support
- SASL/GSSAPI authentication

### **Current Usage**

