# from flext-ldap_docs/development.md:299
from __future__ import annotations


class FlextLdapUserService:
    """Single responsibility - user operations only."""

    def __init__(self) -> None:
        self._client = get_ldap_client()
        self.logger = u.fetch_logger(__name__)

    def authenticate_user(
        self, username: str, password: str
    ) -> p.Result[FlextLdapUser]:
        """Authenticate user with proper error handling."""
        # Implementation...```
**2. r Pattern**

