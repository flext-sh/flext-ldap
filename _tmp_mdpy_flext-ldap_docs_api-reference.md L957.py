# from flext-ldap/docs/api-reference.md:957
from flext_ldap import OpenLDAP2Operations
import ldap3

ops = OpenLDAP2Operations()

connection = ldap3.Connection(
    ldap3.Server("ldap://openldap-server:389"),
    user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    password="password",
    auto_bind=True,
)

# Schema discovery
schema = ops.discover_schema(connection)

# ACL management
acls = ops.get_acls(connection, "olcDatabase={1}mdb,cn=settings")```
#### OracleOIDOperations

Complete implementation for Oracle Internet Directory.

**Import:**

