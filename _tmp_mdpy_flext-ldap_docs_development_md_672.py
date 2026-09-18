# from flext-ldap_docs/development.md:672
# Use connection pooling for high-traffic scenarios
from Flext_ldap import FlextLdapSettings

settings = FlextLdapSettings(
    host="ldap.example.com",
    pool_size=10,  # Adjust based on load
    connection_timeout=5,
    receive_timeout=15,
)```
### Search Optimization

