import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import ClassVar, Final

from _typeshed import Incomplete
from flext_core import FlextResult

from flext_ldap.models import FlextLdapGroup, FlextLdapUser

__all__ = [
    "MAX_PASSWORD_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "FlextLdapActiveUserSpecification",
    "FlextLdapCompleteUserSpecification",
    "FlextLdapDistinguishedNameSpecification",
    "FlextLdapDomainFactory",
    "FlextLdapDomainSpecification",
    "FlextLdapEmailSpecification",
    "FlextLdapGroupManagementService",
    "FlextLdapGroupMemberAddedEvent",
    "FlextLdapGroupSpecification",
    "FlextLdapPasswordChangedEvent",
    "FlextLdapPasswordService",
    "FlextLdapPasswordSpecification",
    "FlextLdapUserCreatedEvent",
    "FlextLdapUserDeletedEvent",
    "FlextLdapUserManagementService",
    "FlextLdapUserSpecification",
]

MIN_PASSWORD_LENGTH: Final[int]
MAX_PASSWORD_LENGTH: Final[int]

class FlextLdapDomainSpecification(ABC):
    name: Incomplete
    description: Incomplete
    def __init__(self, name: str, description: str = "") -> None: ...
    @abstractmethod
    def is_satisfied_by(self, candidate: object) -> bool: ...
    def get_validation_error(self, candidate: object) -> str: ...

class FlextLdapUserSpecification(FlextLdapDomainSpecification):
    def __init__(self) -> None: ...
    def is_satisfied_by(self, candidate: object) -> bool: ...
    def get_validation_error(self, candidate: object) -> str: ...

class FlextLdapGroupSpecification(FlextLdapDomainSpecification):
    def __init__(self) -> None: ...
    def is_satisfied_by(self, candidate: object) -> bool: ...
    def get_validation_error(self, candidate: object) -> str: ...

class FlextLdapDistinguishedNameSpecification(FlextLdapDomainSpecification):
    DN_PATTERN: ClassVar[re.Pattern[str]]
    def __init__(self) -> None: ...
    def is_satisfied_by(self, candidate: object) -> bool: ...
    def get_validation_error(self, candidate: object) -> str: ...

class FlextLdapPasswordSpecification(FlextLdapDomainSpecification):
    def __init__(self) -> None: ...
    def is_satisfied_by(self, candidate: object) -> bool: ...
    def get_validation_error(self, candidate: object) -> str: ...

class FlextLdapActiveUserSpecification(FlextLdapDomainSpecification):
    def __init__(self) -> None: ...
    def is_satisfied_by(self, candidate: object) -> bool: ...
    def get_validation_error(self, candidate: object) -> str: ...

class FlextLdapEmailSpecification(FlextLdapDomainSpecification):
    EMAIL_PATTERN: ClassVar[re.Pattern[str]]
    def __init__(self) -> None: ...
    def is_satisfied_by(self, candidate: object) -> bool: ...
    def get_validation_error(self, candidate: object) -> str: ...

class FlextLdapCompleteUserSpecification(FlextLdapDomainSpecification):
    def __init__(self) -> None: ...
    def is_satisfied_by(self, candidate: object) -> bool: ...
    def get_validation_error(self, candidate: object) -> str: ...

class FlextLdapUserManagementService:
    def __init__(self) -> None: ...
    def validate_user_creation(
        self, user_data: dict[str, object]
    ) -> FlextResult[None]: ...
    def can_delete_user(
        self, user: FlextLdapUser, requesting_user: FlextLdapUser
    ) -> FlextResult[bool]: ...
    def generate_username(
        self, first_name: str, last_name: str
    ) -> FlextResult[str]: ...

class FlextLdapGroupManagementService:
    def __init__(self) -> None: ...
    def can_add_member(
        self,
        group: FlextLdapGroup,
        user: FlextLdapUser,
        *,
        allow_inactive: bool = False,
    ) -> FlextResult[bool]: ...
    def validate_group_creation(
        self, group_data: dict[str, object]
    ) -> FlextResult[None]: ...

class FlextLdapPasswordService:
    def __init__(self) -> None: ...
    def validate_password_change(
        self, current_password: str, new_password: str
    ) -> FlextResult[None]: ...
    def generate_secure_password(self, length: int = 12) -> FlextResult[str]: ...

class FlextLdapDomainEvent:
    occurred_at: Incomplete
    def __init__(
        self, occurred_at: datetime | None = None, **kwargs: object
    ) -> None: ...

class FlextLdapBaseUserEvent(FlextLdapDomainEvent):
    user_id: Incomplete
    user_dn: Incomplete
    actor: Incomplete
    def __init__(
        self,
        user_id: str,
        user_dn: str,
        actor: str,
        occurred_at: datetime | None = None,
    ) -> None: ...
    @classmethod
    def create_with_timestamp(
        cls, user_id: str, user_dn: str, actor: str
    ) -> FlextLdapDomainEvent: ...

class FlextLdapUserCreatedEvent(FlextLdapBaseUserEvent):
    @classmethod
    def create(
        cls, user_id: str, user_dn: str, created_by: str
    ) -> FlextLdapUserCreatedEvent: ...

class FlextLdapUserDeletedEvent(FlextLdapBaseUserEvent):
    @classmethod
    def create(
        cls, user_id: str, user_dn: str, deleted_by: str
    ) -> FlextLdapUserDeletedEvent: ...

class FlextLdapBaseGroupEvent(FlextLdapDomainEvent):
    group_dn: Incomplete
    actor: Incomplete
    def __init__(
        self, group_dn: str, actor: str, occurred_at: datetime | None = None
    ) -> None: ...
    @classmethod
    def create_with_timestamp(
        cls, group_dn: str, actor: str
    ) -> FlextLdapDomainEvent: ...

class FlextLdapGroupMemberAddedEvent(FlextLdapBaseGroupEvent):
    member_dn: Incomplete
    added_by: Incomplete
    def __init__(
        self,
        group_dn: str,
        member_dn: str,
        added_by: str,
        occurred_at: datetime | None = None,
    ) -> None: ...
    @classmethod
    def create(
        cls, group_dn: str, member_dn: str, added_by: str
    ) -> FlextLdapGroupMemberAddedEvent: ...

class FlextLdapPasswordChangedEvent(FlextLdapDomainEvent):
    user_dn: Incomplete
    changed_by: Incomplete
    is_self_change: Incomplete
    def __init__(
        self,
        user_dn: str,
        changed_by: str,
        *,
        is_self_change: bool | None = None,
        occurred_at: datetime | None = None,
    ) -> None: ...
    @classmethod
    def create(cls, user_dn: str, changed_by: str) -> FlextLdapPasswordChangedEvent: ...

class EntityParameterBuilder:
    @staticmethod
    def safe_str(value: object) -> str | None: ...
    @staticmethod
    def safe_list(value: object, default: list[str] | None = None) -> list[str]: ...
    @staticmethod
    def safe_dict(value: object) -> dict[str, object]: ...

class UserEntityBuilder:
    params: Incomplete
    builder: Incomplete
    def __init__(self, params: dict[str, object]) -> None: ...
    def build(self) -> object: ...

class GroupEntityBuilder:
    params: Incomplete
    builder: Incomplete
    def __init__(self, params: dict[str, object]) -> None: ...
    def build(self) -> object: ...

class FlextLdapDomainFactory:
    def __init__(self) -> None: ...
    def create_user_from_data(
        self, user_data: dict[str, object]
    ) -> FlextResult[FlextLdapUser]: ...
    def create_group_from_data(
        self, group_data: dict[str, object]
    ) -> FlextResult[FlextLdapGroup]: ...
