# from flext-ldap/docs/guides/server-operations.md:409
from flext_ldap import OracleOUDOperations

ops = OracleOUDOperations()

# Connection to Oracle OUD
connection = ldap3.Connection(
    ldap3.Server("ldap://oud-server:389"),
    user="cn=Directory Manager",
    password="password",
    auto_bind=True,
)

# Schema discovery
schema_result = ops.discover_schema(connection)
if schema_result.success:
    schema = schema_result.unwrap()
    print(f"Server type: {schema['server_type']}")  # "oud"```
### **ds-privilege-name ACLs**

