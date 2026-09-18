# from flext-ldap_docs/development.md:317
from __future__ import annotations


# ✅ CORRECT - Explicit error handling
def create_user(self, request: CreateUserRequest) -> p.Result[FlextLdapUser]:
    if not request.is_valid():
        return r[FlextLdapUser].fail("Invalid user data")

    result = self._client.create_entry(request.to_ldap_entry())
    if result.failure:
        return r[FlextLdapUser].fail(f"User creation failed: {result.error}")

    return r[FlextLdapUser].ok(FlextLdapUser.from_ldap_entry(result.unwrap()))


# ❌ WRONG - Try/catch fallbacks
def create_user(self, request: CreateUserRequest) -> FlextLdapUser | None:
    try:
        # Implementation...
        return user
    except Exception:
        return None  # FORBIDDEN```
**3. Parameter Object Pattern**

