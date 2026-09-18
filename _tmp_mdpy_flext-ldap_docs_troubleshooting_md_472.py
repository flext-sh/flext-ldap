# from flext-ldap_docs/troubleshooting.md:472
from __future__ import annotations


class LDAPService:
    def __init__(self):
        self._api = ldap  # Reuse single instance

    def multiple_operations(self, users: list):
        """Perform multiple operations with same connection."""
        results = []
        for user in users:
            result = self._api.authenticate_user(user.username, user.password)
            results.append(result)
        return results```
______________________________________________________________________

## Configuration Issues

### Environment Variable Problems

**Diagnosis:**

