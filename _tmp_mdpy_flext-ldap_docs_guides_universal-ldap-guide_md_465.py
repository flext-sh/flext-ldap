# from flext-ldap_docs/guides/universal-ldap-guide.md:465
# Good: Use servers system for server-specific behavior
from flext_ldap import FlextLdapEntryAdapter

adapter = FlextLdapEntryAdapter(server_type="oud")

# Adapter handles Oracle OUD servers automatically
normalized = adapter.normalize_entry_for_server(entry, "oud")```
## Troubleshooting

### Server Detection Issues

If server type is not detected:

