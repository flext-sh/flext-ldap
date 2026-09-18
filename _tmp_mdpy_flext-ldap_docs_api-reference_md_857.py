# from flext-ldap_docs/api-reference.md:857
from flext_ldif import FlextLdifModels
from flext_ldap import OpenLDAP2Operations

ops = OpenLDAP2Operations()

entry = FlextLdifModels.Entry(
    dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
    attributes=FlextLdifModels.Attributes(
        attributes={
            "objectClass": ["person", "organizationalPerson"],
            "cn": ["test"],
            "sn": ["Test User"],
            "mail": ["test@example.com"],
        }
    ),
)

result = ops.add_entry(connection, entry)
if result.success:
    print("Entry added successfully")```
##### `modify_entry(connection, dn, modifications) -> p.Result[bool]`

Modify entry attributes.

**Example:**

