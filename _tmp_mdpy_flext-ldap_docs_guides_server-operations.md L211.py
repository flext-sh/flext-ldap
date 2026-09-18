# from flext-ldap/docs/guides/server-operations.md:211
from flext_ldap import OpenLDAP2Operations
import ldap3

# Initialize operations
ops = OpenLDAP2Operations()

# Connection
connection = ldap3.Connection(
    ldap3.Server("ldap://openldap-server:389"),
    user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    password="password",
    auto_bind=True,
)

# Schema discovery
schema_result = ops.discover_schema(connection)
if schema_result.success:
    schema = schema_result.unwrap()
    print(f"Object classes: {len(schema['object_classes'])}")
    print(f"Attribute types: {len(schema['attribute_types'])}")
    print(f"Syntaxes: {len(schema['syntaxes'])}")
    print(f"Matching rules: {len(schema['matching_rules'])}")```
### **ACL Operations**

