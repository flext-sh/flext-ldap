# from flext-ldap/docs/guides/server-operations.md:256
from flext_ldif import FlextLdifModels

# Create entry
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

# Add entry
add_result = ops.add_entry(connection, entry)
if add_result.success:
    print("Entry added successfully")

# Modify entry
modify_result = ops.modify_entry(
    connection,
    dn="cn=test,dc=example,dc=com",
    modifications={"mail": ["newemail@example.com"]},
)

# Delete entry
delete_result = ops.delete_entry(connection, dn="cn=test,dc=example,dc=com")```
### **Paged Search**

