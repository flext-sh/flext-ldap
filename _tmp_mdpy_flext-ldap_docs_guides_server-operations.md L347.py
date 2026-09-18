# from flext-ldap/docs/guides/server-operations.md:347
from flext_ldap import OracleOIDOperations

ops = OracleOIDOperations()

# Connection to Oracle OID
connection = ldap3.Connection(
    ldap3.Server("ldap://oid-server:389"),
    user="cn=invalid_user",
    password="password",
    auto_bind=True,
)

# Schema discovery (Oracle-specific)
schema_result = ops.discover_schema(connection)
if schema_result.success:
    schema = schema_result.unwrap()
    print(f"Server type: {schema['server_type']}")  # "oid"```
### **Oracle OID ACLs**

