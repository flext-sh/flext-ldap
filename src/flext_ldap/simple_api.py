"""Simple API interface for FLEXT-LDAP v0.7.0.

REFACTORED: Using flext-core DI patterns and ServiceResult - NO duplication.
Provides clean API interface for all LDAP operations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.config import get_container

if TYPE_CHECKING:
    from uuid import UUID

    from flext_core.domain.types import ServiceResult

    from flext_ldap.application.services import LDAPConnectionService, LDAPUserService
    from flext_ldap.domain.entities import LDAPConnection, LDAPUser


class LDAPAPI:
    """Simple API interface for LDAP operations.

    Uses dependency injection to resolve services from flext-core container.
    All operations return ServiceResult for type-safe error handling.
    """

    def __init__(self) -> None:
        """Initialize API with dependency injection container."""
        self._container = get_container()

        # Lazy load services
        self._user_service: LDAPUserService | None = None
        self._connection_service: LDAPConnectionService | None = None

    @property
    def user_service(self) -> LDAPUserService:
        """Get user service with lazy loading."""
        if self._user_service is None:
            from flext_ldap.application.services import LDAPUserService  # noqa: PLC0415

            self._user_service = self._container.resolve(LDAPUserService)
        return self._user_service

    @property
    def connection_service(self) -> LDAPConnectionService:
        """Get connection service with lazy loading."""
        if self._connection_service is None:
            from flext_ldap.application.services import \
                LDAPConnectionService  # noqa: PLC0415

            self._connection_service = self._container.resolve(LDAPConnectionService)
        return self._connection_service

    # Connection operations
    async def create_connection(
        self,
        server_uri: str,
        bind_dn: str,
        pool_name: str | None = None,  # noqa: ARG002
        pool_size: int = 1,  # noqa: ARG002
    ) -> ServiceResult[LDAPConnection]:
        """Create a new LDAP connection."""
        # Note: pool_name and pool_size are API parameters but not used by underlying service
        return await self.connection_service.create_connection(
            server_uri=server_uri,
            bind_dn=bind_dn,
        )

    async def connect(self, connection_id: UUID) -> ServiceResult[LDAPConnection]:
        """Connect to LDAP server."""
        return await self.connection_service.connect(connection_id)

    async def disconnect(self, connection_id: UUID) -> ServiceResult[LDAPConnection]:
        """Disconnect from LDAP server."""
        return await self.connection_service.disconnect(connection_id)

    async def bind(self, connection_id: UUID) -> ServiceResult[LDAPConnection]:
        """Bind to LDAP server."""
        return await self.connection_service.bind(connection_id)

    # User operations
    async def create_user(
        self,
        dn: str,
        uid: str,
        cn: str,
        sn: str,
        mail: str | None = None,
        phone: str | None = None,
        ou: str | None = None,
        department: str | None = None,
        title: str | None = None,
        object_classes: list[str] | None = None,
    ) -> ServiceResult[LDAPUser]:
        """Create a new LDAP user."""
        # Import at module level to avoid issues
        from flext_ldap.domain.value_objects import CreateUserRequest  # noqa: PLC0415

        request = CreateUserRequest(
            dn=dn,
            uid=uid,
            cn=cn,
            sn=sn,
            mail=mail,
            phone=phone,
            ou=ou,
            department=department,
            title=title,
            object_classes=object_classes,
        )
        return await self.user_service.create_user(request)

    async def get_user(self, user_id: UUID) -> ServiceResult[LDAPUser | None]:
        """Get user by ID."""
        return await self.user_service.get_user(user_id)

    async def find_user_by_dn(self, dn: str) -> ServiceResult[LDAPUser | None]:
        """Find user by distinguished name."""
        return await self.user_service.find_user_by_dn(dn)

    async def find_user_by_uid(self, uid: str) -> ServiceResult[LDAPUser | None]:
        """Find user by UID."""
        return await self.user_service.find_user_by_uid(uid)

    async def update_user(
        self,
        user_id: UUID,
        updates: dict[str, Any],
    ) -> ServiceResult[LDAPUser]:
        """Update user attributes."""
        return await self.user_service.update_user(user_id, updates)

    async def lock_user(self, user_id: UUID) -> ServiceResult[LDAPUser]:
        """Lock user account."""
        return await self.user_service.lock_user(user_id)

    async def unlock_user(self, user_id: UUID) -> ServiceResult[LDAPUser]:
        """Unlock user account."""
        return await self.user_service.unlock_user(user_id)

    async def delete_user(self, user_id: UUID) -> ServiceResult[bool]:
        """Delete user account."""
        return await self.user_service.delete_user(user_id)

    async def list_users(
        self,
        ou: str | None = None,
        limit: int = 100,
    ) -> ServiceResult[list[LDAPUser]]:
        """List users in organizational unit."""
        return await self.user_service.list_users(ou=ou, limit=limit)


# Factory function for easy API creation
def create_ldap_api() -> LDAPAPI:
    """Create and return LDAP API instance."""
    return LDAPAPI()
