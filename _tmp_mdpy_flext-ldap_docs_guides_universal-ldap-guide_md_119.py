# from flext-ldap_docs/guides/universal-ldap-guide.md:119
from flext_ldap import OpenLDAP2Operations, OracleOUDOperations

# OpenLDAP 2.x operations
openldap = OpenLDAP2Operations()
print(f"Port: {openldap.get_default_port()}")
print(f"Supports TLS: {openldap.supports_start_tls()}")
print(f"ACL attribute: {openldap.get_acl_attribute_name()}")

# Oracle OUD operations
oud = OracleOUDOperations()
print(f"Privileges: {oud.get_oud_privileges()}")
print(f"Replication: {oud.get_replication_mechanism()}")```
## Universal API Methods

### 1. Get Detected Server Type

