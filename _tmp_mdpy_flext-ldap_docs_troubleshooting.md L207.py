# from flext-ldap/docs/troubleshooting.md:207
# ❌ WRONG - Spaces around commas
dn = "cn=John Doe , ou=users , dc=example , dc=com"

# ❌ WRONG - Wrong attribute names
dn = "name=John Doe,unit=users,domain=example"

# ✅ CORRECT - Proper RFC 4514 format
dn = "cn=John Doe,ou=users,dc=example,dc=com"

# ✅ CORRECT - Escaped special characters
dn = "cn=John\\, Doe,ou=users,dc=example,dc=com"```
**Validation:**

