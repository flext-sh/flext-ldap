# from flext-ldap_docs/guides/server-operations.md:318
from flext_ldap import OpenLDAP1Operations

ops = OpenLDAP1Operations()

# ACL attribute is different
acl_attr = ops.get_acl_attribute_name()  # Returns "access"

# ACL format is legacy syntax
# access to <what> by <who> <access>
legacy_acl = {
    "raw": 'access to * by dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" write'
}```
**Note**: OpenLDAP 1.x extends OpenLDAP 2.x operations, only overriding ACL-related methods for the legacy syntax.

##

## 🔧 Oracle OID Operations

### **Features**

- **orclaci** ACL syntax
- **cn=subschemasubentry** schema location
- Oracle-specific object classes (orclUserV2, orclContainer)
- VLV support
- Full replication support

### **Basic Usage**

