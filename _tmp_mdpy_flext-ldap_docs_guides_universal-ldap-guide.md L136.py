# from flext-ldap/docs/guides/universal-ldap-guide.md:136
from flext_ldap import ldap

api = ldap()
api.connect()

# Get detected server type
server_type_result = api.get_detected_server_type()
if server_type_result.success:
    server_type = server_type_result.unwrap()
    print(f"Connected to: {server_type}")
    # Output: "Connected to: openldap2" or "oud", "oid", etc.```
### 2. Get Server Capabilities

