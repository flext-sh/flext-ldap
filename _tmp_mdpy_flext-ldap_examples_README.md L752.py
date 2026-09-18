# from flext-ldap/examples/README.md:752
from flext_ldap import ldap
from flext_ldap import FlextLdapSettings

# Create and configure
settings = FlextLdapSettings(
    ldap_server_uri="ldap://localhost:389",
    ldap_bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    ldap_bind_password="REDACTED_LDAP_BIND_PASSWORD",
)
api = ldap()

# Connect
result = api.connect()
if result.is_failure:
    print(f"Connection failed: {result.error}")
    return

# Use API
search_result = api.search(...)

# Disconnect
api.unbind()
