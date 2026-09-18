# from flext-ldap_docs/guides/universal-ldap-guide.md:479
# Manual server type specification
from flext_ldap import ServerOperationsFactory

factory = ServerOperationsFactory()
ops_result = factory.create_from_server_type("openldap2")```
### Conversion Failures

If conversion fails, check entry compatibility:

