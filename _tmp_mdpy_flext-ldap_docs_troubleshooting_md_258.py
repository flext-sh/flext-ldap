# from flext-ldap_docs/troubleshooting.md:258
# ❌ WRONG - Missing parentheses
filter_str = "objectClass=person"

# ❌ WRONG - Invalid operators
filter_str = "(uid == john.doe)"

# ❌ WRONG - Unescaped special characters
filter_str = "(cn=John (Doe))"

# ✅ CORRECT - Proper LDAP filter syntax
filter_str = "(objectClass=person)"
filter_str = "(uid=john.doe)"
filter_str = "(cn=John \\28Doe\\29)"  # Escaped parentheses

# ✅ CORRECT - Complex filters
filter_str = "(&(objectClass=person)(uid=j*))"
filter_str = "(|(cn=John*)(mail=*@example.com))"```
**Filter Validation:**

