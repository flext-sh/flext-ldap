# from flext-ldap_docs/guides/server-operations.md:386
# Get OID defaults
port = ops.get_default_port()  # 389 (LDAP) or 636 (LDAPS)
schema_dn = ops.get_schema_dn()  # "cn=subschemasubentry"
supports_vlv = ops.supports_vlv()  # True

# Bind mechanisms
mechanisms = ops.get_bind_mechanisms()
# Returns: ["SIMPLE", "SASL/EXTERNAL", "SASL/DIGEST-MD5"]```
##

## 🔧 Oracle OUD Operations

### **Features**

- **ds-privilege-name** ACL attribute
- **cn=schema** schema location
- Based on 389 Directory Server
- Extended SASL support (GSSAPI, PLAIN)
- Full enterprise features

### **Basic Usage**

