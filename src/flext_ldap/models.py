"""FLEXT-LDAP Unified Models Module.

This module provides unified Pydantic models for FLEXT-LDAP, following the FLEXT standards
of having a single unified class per module that inherits from FlextModels.

Contains only the actively used models from the FLEXT-LDAP project.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from flext_core import FlextModels, FlextResult, FlextTypes
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations

__all__ = ["FlextLdapModels"]


class FlextLdapModels(FlextModels):
    """Unified LDAP Models class inheriting from FlextModels.

    This class provides only the actively used LDAP-specific Pydantic models as nested classes,
    following the FLEXT standard architecture pattern.
    """

    class SearchRequest(BaseModel):
        """LDAP Search Request Model - actively used in API."""

        base_dn: str = Field(description="Base DN for search")
        filter_str: str = Field(
            default=FlextLdapConstants.DefaultValues.DEFAULT_SEARCH_FILTER,
            description="LDAP search filter",
        )
        scope: str = Field(
            default=FlextLdapConstants.Scopes.SUBTREE,
            description="Search scope",
        )
        attributes: list[str] | None = Field(
            default=None,
            description="Attributes to retrieve",
        )
        size_limit: int = Field(
            default=FlextLdapConstants.Connection.MAX_SIZE_LIMIT,
            description="Maximum number of entries to return",
            gt=0,
        )
        time_limit: int = Field(
            default=FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS,
            description="Search timeout in seconds",
            gt=0,
        )

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, value: str) -> str:
            """Validate base DN using centralized validation."""
            validation_result = FlextLdapValidations.validate_dn(
                value.strip(), "Base DN"
            )
            if validation_result.is_failure:
                raise ValueError(validation_result.error)

            return value.strip()

        @field_validator("scope")
        @classmethod
        def validate_scope(cls, value: str) -> str:
            """Validate search scope."""
            if value not in FlextLdapConstants.Scopes.VALID_SCOPES:
                valid_scopes = ", ".join(sorted(FlextLdapConstants.Scopes.VALID_SCOPES))
                msg = f"Invalid scope. Must be one of: {valid_scopes}"
                raise ValueError(msg)
            return value

        @classmethod
        def create_user_search(
            cls, base_dn: str, uid: str | None = None
        ) -> FlextLdapModels.SearchRequest:
            """Factory method for common user search patterns."""
            filter_str = (
                f"(&(objectClass=person)(uid={uid}))" if uid else "(objectClass=person)"
            )
            return cls(
                base_dn=base_dn,
                filter_str=filter_str,
                scope="subtree",
                attributes=["uid", "cn", "sn", "mail"],
                size_limit=100,
                time_limit=30,
            )

    class Entry(BaseModel):
        """LDAP Entry Model - actively used in API."""

        id: str = Field(description="Entry identifier")
        dn: str = Field(description="Distinguished Name")
        object_classes: list[str] = Field(
            default_factory=list,
            description="Object classes",
        )
        attributes: FlextLdapTypes.Entry.AttributeDict = Field(
            default_factory=dict,
            description="Entry attributes",
        )
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, value: str) -> str:
            """Validate DN format using centralized validation."""
            validation_result = FlextLdapValidations.validate_dn(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return value.strip()

        def get_attribute_value(self, attribute_name: str) -> str | None:
            """Get single attribute value."""
            attr_value = self.attributes.get(attribute_name)
            if isinstance(attr_value, list) and attr_value:
                return str(attr_value[0])
            if isinstance(attr_value, (str, bytes)):
                return str(attr_value)
            return None

        def get_attribute_values(self, attribute_name: str) -> list[str]:
            """Get all attribute values."""
            attr_value = self.attributes.get(attribute_name, [])
            if isinstance(attr_value, list):
                return [str(v) for v in attr_value]
            return [str(attr_value)]

        def get_attribute(self, attribute_name: str) -> list[str] | None:
            """Get attribute value (for backward compatibility)."""
            attr_value = self.attributes.get(attribute_name)
            if attr_value is None:
                return None
            if isinstance(attr_value, list):
                return [str(v) for v in attr_value]
            return [str(attr_value)]

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate entry business rules."""
            # Basic entry validations
            if not self.dn:
                return FlextResult[None].fail("Entry must have a DN")

            # LDAP entries must have at least one object class
            if not self.object_classes:
                return FlextResult[None].fail(
                    "Entry must have at least one object class"
                )

            return FlextResult[None].ok(None)

    class User(BaseModel):
        """LDAP User Model - actively used in API."""

        id: str = Field(description="User identifier")
        dn: str = Field(description="Distinguished Name")
        uid: str | None = Field(default=None, description="User ID")
        cn: str | None = Field(default=None, description="Common Name")
        sn: str | None = Field(default=None, description="Surname")
        given_name: str | None = Field(default=None, description="Given Name")
        mail: str | None = Field(default=None, description="Email Address")
        display_name: str | None = Field(default=None, description="Display Name")
        user_password: str | None = Field(default=None, description="User password")
        status: str | None = Field(default=None, description="User status")
        created_at: str | None = Field(default=None, description="Creation timestamp")
        object_classes: list[str] = Field(
            default_factory=list,
            description="Object classes",
        )
        attributes: FlextLdapTypes.Entry.AttributeDict = Field(
            default_factory=dict,
            description="User attributes",
        )
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, value: str) -> str:
            """Validate DN format using centralized validation."""
            validation_result = FlextLdapValidations.validate_dn(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return value.strip()

        @field_validator("mail")
        @classmethod
        def validate_email(cls, value: str | None) -> str | None:
            """Validate email format using centralized validation."""
            validation_result = FlextLdapValidations.validate_email(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)

            return value

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate user business rules."""
            # User-specific validations
            if "person" not in self.object_classes:
                return FlextResult[None].fail("User must have 'person' object class")

            if not self.cn:
                return FlextResult[None].fail("User must have a Common Name")

            return FlextResult[None].ok(None)

    class Group(BaseModel):
        """LDAP Group Model - actively used in API."""

        id: str = Field(description="Group identifier")
        dn: str = Field(description="Distinguished Name")
        cn: str | None = Field(default=None, description="Common Name")
        description: str | None = Field(default=None, description="Group Description")
        status: str | None = Field(default=None, description="Group status")
        members: list[str] = Field(
            default_factory=list,
            description="Group members (DNs)",
        )
        object_classes: list[str] = Field(
            default_factory=list,
            description="Object classes",
        )
        attributes: FlextLdapTypes.Entry.AttributeDict = Field(
            default_factory=dict,
            description="Group attributes",
        )
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, value: str) -> str:
            """Validate DN format using centralized validation."""
            validation_result = FlextLdapValidations.validate_dn(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return value.strip()

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate group business rules."""
            # Group-specific validations
            if "groupOfNames" not in self.object_classes:
                return FlextResult[None].fail(
                    "Group must have 'groupOfNames' object class"
                )

            return FlextResult[None].ok(None)

        def has_member(self, member_dn: str) -> bool:
            """Check if DN is a member of this group."""
            return member_dn in self.members

        def add_member(self, member_dn: str) -> FlextResult[None]:
            """Add member to group."""
            if member_dn not in self.members:
                self.members.append(member_dn)
                return FlextResult[None].ok(None)
            return FlextResult[None].ok(None)  # Already a member, no-op

        def remove_member(self, member_dn: str) -> FlextResult[None]:
            """Remove member from group."""
            if member_dn in self.members:
                self.members.remove(member_dn)
                return FlextResult[None].ok(None)
            return FlextResult[None].fail(f"Member {member_dn} not found in group")

    class CreateUserRequest(BaseModel):
        """Create User Request Model - actively used in API."""

        dn: str = Field(description="User DN")
        uid: str = Field(description="User ID")
        cn: str = Field(description="Common Name")
        sn: str = Field(description="Surname")
        given_name: str | None = Field(default=None, description="Given Name")
        mail: str | None = Field(default=None, description="Email Address")
        description: str | None = Field(default=None, description="User description")
        telephone_number: str | None = Field(default=None, description="Phone number")
        user_password: str | None = Field(default=None, description="User Password")
        object_classes: list[str] = Field(
            default_factory=lambda: [
                FlextLdapConstants.ObjectClasses.TOP,
                FlextLdapConstants.ObjectClasses.PERSON,
                FlextLdapConstants.ObjectClasses.INET_ORG_PERSON,
            ],
            description="Object classes for user",
        )
        additional_attributes: dict[str, list[str]] = Field(
            default_factory=dict,
            description="Additional user attributes",
        )

        @field_validator("mail")
        @classmethod
        def validate_email(cls, value: str | None) -> str | None:
            """Validate email format using centralized validation."""
            validation_result = FlextLdapValidations.validate_email(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)

            return value

        @field_validator("user_password")
        @classmethod
        def validate_password(cls, value: str | None) -> str | None:
            """Validate password requirements using centralized validation."""
            validation_result = FlextLdapValidations.validate_password(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)

            return value

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate create user request business rules."""
            if not self.dn:
                return FlextResult[None].fail("DN cannot be empty")
            if not self.uid:
                return FlextResult[None].fail("UID cannot be empty")
            if not self.cn:
                return FlextResult[None].fail("Common Name cannot be empty")
            return FlextResult[None].ok(None)

        def to_user_entity(self) -> FlextLdapModels.User:
            """Convert request to user entity."""
            return FlextLdapModels.User(
                id=f"user_{self.uid}",
                dn=self.dn,
                uid=self.uid,
                cn=self.cn,
                sn=self.sn,
                given_name=self.given_name,
                mail=self.mail,
                user_password=self.user_password,
                object_classes=self.object_classes.copy(),
                attributes={},
                modified_at=None,
            )

    class CreateGroupRequest(BaseModel):
        """Create Group Request Model - actively used in API."""

        dn: str = Field(description="Group DN")
        cn: str = Field(description="Common Name")
        description: str | None = Field(default=None, description="Group Description")
        member_dns: list[str] = Field(
            default_factory=list,
            description="Initial group members (DNs)",
        )
        object_classes: list[str] = Field(
            default_factory=lambda: [
                FlextLdapConstants.ObjectClasses.TOP,
                FlextLdapConstants.ObjectClasses.GROUP_OF_NAMES,
            ],
            description="Object classes for group",
        )
        additional_attributes: dict[str, list[str]] = Field(
            default_factory=dict,
            description="Additional group attributes",
        )

    class UpdateGroupRequest(BaseModel):
        """Update Group Request Model - used in protocols."""

        dn: str = Field(description="Distinguished Name of group to update")
        cn: str | None = Field(default=None, description="New Common Name")
        description: str | None = Field(
            default=None, description="New group description"
        )
        member_dns: list[str] | None = Field(
            default=None,
            description="New list of member DNs (replaces existing)",
        )

    class SearchResponse(BaseModel):
        """Search Response Model - used in protocols."""

        entries: list[FlextTypes.Core.Dict] = Field(
            default_factory=list,
            description="Search result entries",
        )
        total_count: int = Field(default=0, description="Total number of entries found")
        has_more: bool = Field(
            default=False,
            description="Whether more entries are available",
        )
        search_time_ms: float = Field(
            default=0.0,
            description="Search execution time in ms",
        )

    class ConnectionConfig(BaseModel):
        """LDAP Connection Configuration Model - used in protocols."""

        server: str = Field(description="LDAP server URI")
        bind_dn: str | None = Field(
            default=None, description="Bind DN for authentication"
        )
        bind_password: str | None = Field(default=None, description="Bind password")
        timeout: int = Field(
            default=30,
            description="Connection timeout in seconds",
            gt=0,
            le=300,
        )
        use_tls: bool = Field(default=False, description="Use TLS encryption")

    class ConnectionRequest(BaseModel):
        """LDAP Connection Request Model - used for operational requests."""

        server_uri: str = Field(description="LDAP server URI")
        bind_dn: str | None = Field(
            default=None, description="Bind DN for authentication"
        )
        bind_password: str | None = Field(default=None, description="Bind password")
        operation_type: str = Field(
            description="Operation type: test, connect, bind, terminate"
        )
        timeout: int = Field(
            default=30,
            description="Connection timeout in seconds",
            gt=0,
            le=300,
        )

    # NO ALIASES ALLOWED - Use Entry class directly

    # Factory methods for creating models
    @classmethod
    def create_search_request(
        cls,
        base_dn: str,
        filter_str: str = FlextLdapConstants.DefaultValues.DEFAULT_SEARCH_FILTER,
        scope: str = FlextLdapConstants.Scopes.SUBTREE,
        attributes: list[str] | None = None,
        size_limit: int = FlextLdapConstants.Connection.MAX_SIZE_LIMIT,
        time_limit: int = FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS,
    ) -> SearchRequest:
        """Create search request."""
        return cls.SearchRequest(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
            size_limit=size_limit,
            time_limit=time_limit,
        )

    @classmethod
    def create_user_from_entry(cls, entry: Entry) -> User:
        """Create User model from LDAP entry."""
        return cls.User(
            id=entry.id,
            dn=entry.dn,
            object_classes=entry.object_classes,
            attributes=entry.attributes,
            modified_at=entry.modified_at,
            uid=entry.get_attribute_value(FlextLdapConstants.Attributes.USER_ID),
            cn=entry.get_attribute_value(FlextLdapConstants.Attributes.COMMON_NAME),
            sn=entry.get_attribute_value(FlextLdapConstants.Attributes.SURNAME),
            given_name=entry.get_attribute_value(
                FlextLdapConstants.Attributes.GIVEN_NAME,
            ),
            mail=entry.get_attribute_value(FlextLdapConstants.Attributes.MAIL),
            display_name=entry.get_attribute_value(
                FlextLdapConstants.Attributes.DISPLAY_NAME,
            ),
        )

    @classmethod
    def create_group_from_entry(cls, entry: Entry) -> Group:
        """Create Group model from LDAP entry."""
        return cls.Group(
            id=entry.id,
            dn=entry.dn,
            object_classes=entry.object_classes,
            attributes=entry.attributes,
            modified_at=entry.modified_at,
            cn=entry.get_attribute_value(FlextLdapConstants.Attributes.COMMON_NAME),
            description=entry.get_attribute_value(
                FlextLdapConstants.Attributes.DESCRIPTION,
            ),
            members=entry.get_attribute_values(FlextLdapConstants.Attributes.MEMBER),
        )

    class ErrorMessages:
        """Error message constants following TRY003 and EM101/EM102 rules."""

        INVALID_EMAIL_FORMAT = "Invalid email format"
        EMAIL_VALIDATION_FAILED = "Invalid email format: {error}"
        DN_CANNOT_BE_EMPTY = "DN cannot be empty"
        INVALID_DN_FORMAT = "Invalid DN format"
