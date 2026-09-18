# from flext-ldap/docs/guides/server-operations.md:726
# Check if server is properly connected
if not connection.bound:
    print("Connection not bound - check credentials")

# Check schema DN
schema_dn = ops.get_schema_dn()
print(f"Trying schema DN: {schema_dn}")```
**ACL Operations Not Working**:

