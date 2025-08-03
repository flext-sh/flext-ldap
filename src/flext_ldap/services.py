"""FLEXT-LDAP Service Layer - Thin Wrappers for Backward Compatibility.

Provides thin wrapper services that delegate to application/ldap_service.py
to eliminate duplication while maintaining API compatibility.

ARCHITECTURE: Clean delegation pattern - no business logic here.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextResult, get_logger

from flext_ldap.application.ldap_service import FlextLdapService as CoreLdapService
from flext_ldap.entities import FlextLdapGroup, FlextLdapUser

if TYPE_CHECKING:
    from flext_ldap.values import FlextLdapCreateUserRequest

logger = get_logger(__name__)


# Thin wrapper services that delegate to CoreLdapService


class FlextLdapUserApplicationService:
    """User service wrapper - delegates to application/ldap_service.py."""

    def __init__(self) -> None:
        """Initialize user service wrapper."""
        self._core_service = CoreLdapService()
        logger.debug("Initialized FlextLdapUserApplicationService wrapper")

    async def create_user(
        self, user_request: FlextLdapCreateUserRequest
    ) -> FlextResult[FlextLdapUser]:
        """Create user - delegates to core service."""
        return await self._core_service.create_user(user_request)

    async def get_user(self, user_id: str) -> FlextResult[FlextLdapUser]:
        """Get user by ID - delegates to core service."""
        # Core service uses find_user_by_uid for this
        return await self._core_service.find_user_by_uid(user_id)

    async def find_user_by_dn(self, dn: str) -> FlextResult[FlextLdapUser]:
        """Find user by DN - delegates to core service."""
        # For now, return failure as core service doesn't have this exact method
        logger.warning(f"find_user_by_dn not implemented in core service, dn: {dn}")
        return FlextResult.fail("find_user_by_dn not implemented")

    async def find_user_by_uid(self, uid: str) -> FlextResult[FlextLdapUser]:
        """Find user by UID - delegates to core service."""
        return await self._core_service.find_user_by_uid(uid)

    async def update_user(
        self, user_id: str, updates: dict[str, str]
    ) -> FlextResult[FlextLdapUser]:
        """Update user - delegates to core service."""
        return await self._core_service.update_user(user_id, updates)

    async def delete_user(self, user_id: str) -> FlextResult[bool]:
        """Delete user - delegates to core service."""
        return await self._core_service.delete_user(user_id)

    async def list_users(self) -> FlextResult[list[FlextLdapUser]]:
        """List users - delegates to core service."""
        return await self._core_service.list_users()


class FlextLdapGroupService:
    """Group service wrapper - delegates to application/ldap_service.py."""

    def __init__(self) -> None:
        """Initialize group service wrapper."""
        self._core_service = CoreLdapService()
        logger.debug("Initialized FlextLdapGroupService wrapper")

    async def create_group(self, **kwargs) -> FlextResult[FlextLdapGroup]:
        """Create group - placeholder implementation."""
        logger.warning("create_group not fully implemented in core service")
        return FlextResult.fail("create_group not implemented")

    async def find_group_by_dn(self, dn: str) -> FlextResult[FlextLdapGroup]:
        """Find group by DN - placeholder implementation."""
        logger.warning(f"find_group_by_dn not implemented in core service, dn: {dn}")
        return FlextResult.fail("find_group_by_dn not implemented")


class FlextLdapOperationService:
    """Operation service wrapper - delegates to application/ldap_service.py."""

    def __init__(self) -> None:
        """Initialize operation service wrapper."""
        self._core_service = CoreLdapService()
        logger.debug("Initialized FlextLdapOperationService wrapper")


class FlextLdapConnectionApplicationService:
    """Connection service wrapper - delegates to application/ldap_service.py."""

    def __init__(self) -> None:
        """Initialize connection service wrapper."""
        self._core_service = CoreLdapService()
        logger.debug("Initialized FlextLdapConnectionApplicationService wrapper")


# Legacy aliases for backward compatibility
FlextLdapUserService = FlextLdapUserApplicationService
FlextLdapConnectionService = FlextLdapConnectionApplicationService
