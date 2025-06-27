"""LDAP Connection Base Components - Professional extraction from algar-oud-mig."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, ClassVar, Literal

import ldap3
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
)

# Constants for magic values
BYTES_PER_KB = 1024
DEFAULT_BUFFER_SIZE = 4096

LDAPS_GC_PORT = 3269

LDAP_GC_PORT = 3268
SECONDS_PER_HOUR = 3600
SECONDS_PER_MINUTE = 60

from ldap_core_shared.utils.constants import (
    DEFAULT_LDAP_PORT,
    DEFAULT_LDAP_SIZE_LIMIT,
    DEFAULT_LDAP_TIME_LIMIT,
    DEFAULT_LDAP_TIMEOUT,
    DEFAULT_MAX_ITEMS,
    LDAP_DEFAULT_PORT,
    LDAPS_DEFAULT_PORT,
    SENSITIVE_DATA_MASK,
)


class LDAPSearchScope(StrEnum):
    """LDAP search scope enumeration."""

    BASE = "base"
    ONELEVEL = "onelevel"
    SUBTREE = "subtree"


class LDAPAuthenticationMethod(StrEnum):
    """LDAP authentication methods following RFC 4513.

    This enum defines the standardized authentication methods supported
    by LDAP v3 protocol for secure directory access.
    """

    SIMPLE = "SIMPLE"
    SASL = "SASL"
    ANONYMOUS = "ANONYMOUS"


class LDAPConnectionInfo(BaseModel):
    """Professional LDAP connection configuration extracted from algar-oud-mig.

    This class encapsulates all connection parameters needed to establish
    secure LDAP connections, with enterprise-grade validation and security.

    Follows the Single Responsibility Principle by handling only connection
    configuration concerns.

    Security Features:
        - Encrypted password storage using SecretStr
        - SSL/TLS validation and configuration
        - Port validation with enterprise defaults
        - DN format validation

    Example:
        Basic connection:
        >>> conn_info = LDAPConnectionInfo(
        ...     host="ldap.example.com",
        ...     port=LDAP_DEFAULT_PORT,
        ...     use_ssl=False,
        ...     bind_dn="cn=admin,dc=example,dc=com",
        ...     bind_password="secret",
        ...     base_dn="dc=example,dc=com",
        ... )

        Secure connection with SSL:
        >>> secure_conn = LDAPConnectionInfo(
        ...     host="ldaps.example.com",
        ...     port=LDAPS_DEFAULT_PORT,
        ...     use_ssl=True,
        ...     bind_dn="cn=admin,dc=example,dc=com",
        ...     bind_password="secret",
        ...     base_dn="dc=example,dc=com",
        ...     timeout=SECONDS_PER_MINUTE,
        ... )
    """

    model_config = ConfigDict(
        # Pydantic v2 configuration for enterprise use
        strict=True,  # Strict type validation
        extra="forbid",  # No extra fields allowed
        frozen=True,  # Immutable after creation
        validate_assignment=True,  # Validate on field assignment
        str_strip_whitespace=True,  # Auto-strip whitespace
        use_enum_values=True,  # Use enum values for serialization
    )

    # Core connection parameters
    host: str = Field(
        description="LDAP server hostname or IP address",
        min_length=1,
        max_length=255,
    )

    port: int = Field(
        default=DEFAULT_LDAP_PORT,
        description="LDAP server port (LDAP_DEFAULT_PORT for plain, LDAPS_DEFAULT_PORT for SSL)",
        ge=1,
        le=65535,
    )

    use_ssl: bool = Field(
        default=False,
        description="Enable SSL/TLS encryption for secure connections",
    )

    # Authentication parameters
    bind_dn: str = Field(
        description="Distinguished Name for binding to LDAP server",
        min_length=3,
        max_length=BYTES_PER_KB,
    )

    bind_password: SecretStr = Field(
        description="Password for LDAP authentication (encrypted storage)",
        min_length=1,
    )

    base_dn: str = Field(
        description="Base Distinguished Name for LDAP operations",
        min_length=3,
        max_length=BYTES_PER_KB,
    )

    # Connection options with enterprise defaults
    timeout: int = Field(
        default=DEFAULT_LDAP_TIMEOUT,
        description="Connection timeout in seconds",
        ge=1,
        le=SECONDS_PER_HOUR,
    )

    auto_bind: bool = Field(
        default=True,
        description="Automatically bind after connection establishment",
    )

    authentication: LDAPAuthenticationMethod = Field(
        default=LDAPAuthenticationMethod.SIMPLE,
        description="LDAP authentication method",
    )

    # Class constants for validation
    _VALID_LDAP_PORTS: ClassVar[set[int]] = {
        LDAP_DEFAULT_PORT,
        LDAPS_DEFAULT_PORT,
        LDAP_GC_PORT,
        LDAPS_GC_PORT,
    }
    _SECURE_PORTS: ClassVar[set[int]] = {LDAPS_DEFAULT_PORT, LDAPS_GC_PORT}

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        """Validate LDAP server hostname following enterprise standards.

        Args:
            value: Hostname or IP address to validate

        Returns:
            Validated hostname

        Raises:
            ValueError: If hostname is invalid or contains forbidden characters
        """
        if not value or value.isspace():
            msg = "Host cannot be empty or whitespace"
            raise ValueError(msg)

        # Remove any protocol prefixes that might be accidentally included
        if "://" in value:
            msg = "Host should not include protocol (ldap:// or ldaps://)"
            raise ValueError(msg)

        # Basic validation for obvious invalid characters
        forbidden_chars = {" ", "\t", "\n", "\r", "/", "\\"}
        if any(char in value for char in forbidden_chars):
            msg = f"Host contains forbidden characters: {forbidden_chars}"
            raise ValueError(msg)

        return value.lower().strip()

    @field_validator("port")
    @classmethod
    def validate_port_security(cls, value: int, info: ValidationInfo) -> int:
        """Validate port and check SSL consistency.

        Args:
            value: Port number to validate
            info: Validation context containing other field values

        Returns:
            Validated port number

        Raises:
            ValueError: If port configuration is inconsistent with SSL settings
        """
        # Check if this is a known secure port
        if value in cls._SECURE_PORTS:
            # Secure port should use SSL
            if hasattr(info, "data") and info.data.get("use_ssl") is False:
                msg = (
                    f"Port {value} is typically used with SSL, "
                    f"but use_ssl=False. Consider setting use_ssl=True"
                )
                raise ValueError(
                    msg,
                )

        return value

    @field_validator("bind_dn", "base_dn")
    @classmethod
    def validate_dn_format(cls, value: str) -> str:
        """Validate Distinguished Name format following RFC 4514.

        Args:
            value: DN string to validate

        Returns:
            Validated DN string

        Raises:
            ValueError: If DN format is invalid
        """
        if not value or value.isspace():
            msg = "DN cannot be empty or whitespace"
            raise ValueError(msg)

        # Basic DN format validation
        value = value.strip()

        # DN should contain at least one component with =
        if "=" not in value:
            msg = "DN must contain at least one attribute=value pair"
            raise ValueError(msg)

        # DN should not start or end with comma
        if value.startswith(",") or value.endswith(","):
            msg = "DN cannot start or end with comma"
            raise ValueError(msg)

        # Check for common DN component types
        valid_prefixes = {
            "cn=",
            "ou=",
            "dc=",
            "uid=",
            "o=",
            "c=",
            "street=",
            "l=",
            "st=",
        }
        has_valid_component = any(
            component.strip().lower().startswith(prefix)
            for component in value.split(",")
            for prefix in valid_prefixes
        )

        if not has_valid_component:
            msg = (
                f"DN should contain recognized components like: "
                f"{', '.join(valid_prefixes)}"
            )
            raise ValueError(
                msg,
            )

        return value

    def get_ldap3_authentication(self) -> str:
        """Get ldap3 library authentication constant.

        Returns:
            ldap3 authentication constant for the configured method
        """
        mapping = {
            LDAPAuthenticationMethod.SIMPLE: ldap3.SIMPLE,
            LDAPAuthenticationMethod.SASL: ldap3.SASL,
            LDAPAuthenticationMethod.ANONYMOUS: ldap3.ANONYMOUS,
        }
        return mapping[self.authentication]

    def is_secure_connection(self) -> bool:
        """Check if this connection configuration uses secure transport.

        Returns:
            True if connection uses SSL/TLS or secure port
        """
        return self.use_ssl or self.port in self._SECURE_PORTS

    def get_connection_url(self, *, include_credentials: bool = False) -> str:
        """Generate LDAP URL for this connection.

        Args:
            include_credentials: Whether to include bind DN in URL

        Returns:
            LDAP URL string
        """
        protocol = "ldaps" if self.use_ssl else "ldap"
        url = f"{protocol}://{self.host}:{self.port}"

        if include_credentials:
            url += f"??base={self.base_dn}"

        return url

    def mask_sensitive_data(self) -> dict[str, Any]:
        """Get configuration dict with sensitive data masked.

        Returns:
            Configuration dictionary with password masked
        """
        data = self.model_dump()
        data["bind_password"] = SENSITIVE_DATA_MASK
        return data


class LDAPSearchConfig(BaseModel):
    """Professional LDAP search configuration extracted from algar-oud-mig.

    Encapsulates search parameters following the Interface Segregation Principle
    by providing a focused interface for search operations only.

    Example:
        Basic search:
        >>> search_config = LDAPSearchConfig(
        ...     search_base="ou=people,dc=example,dc=com",
        ...     search_filter="(objectClass=person)",
        ... )

        Advanced search with limits:
        >>> advanced_search = LDAPSearchConfig(
        ...     search_base="dc=example,dc=com",
        ...     search_filter="(&(objectClass=user)(department=IT)",
        ...     attributes=["cn", "mail", "department"],
        ...     size_limit=DEFAULT_MAX_ITEMS,
        ...     time_limit=DEFAULT_TIMEOUT_SECONDS,
        ... )
    """

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
        str_strip_whitespace=True,
    )

    search_base: str = Field(
        description="Base DN for search operations",
        min_length=3,
        max_length=BYTES_PER_KB,
    )

    search_filter: str = Field(
        default="(objectClass=*)",
        description="LDAP search filter following RFC 4515",
        min_length=3,
        max_length=DEFAULT_BUFFER_SIZE,
    )

    attributes: list[str] | None = Field(
        default=None,
        description="List of attributes to retrieve (None for all)",
    )

    search_scope: Literal["BASE", "ONELEVEL", "SUBTREE"] = Field(
        default="SUBTREE",
        description="LDAP search scope",
    )

    size_limit: int = Field(
        default=DEFAULT_LDAP_SIZE_LIMIT,
        description="Maximum number of entries to return",
        ge=0,
        le=100000,
    )

    time_limit: int = Field(
        default=DEFAULT_LDAP_TIME_LIMIT,
        description="Search timeout in seconds",
        ge=0,
        le=SECONDS_PER_HOUR,
    )

    @field_validator("search_filter")
    @classmethod
    def validate_search_filter(cls, value: str) -> str:
        """Validate LDAP search filter format.

        Args:
            value: Search filter to validate

        Returns:
            Validated search filter

        Raises:
            ValueError: If filter format is invalid
        """
        value = value.strip()

        if not value:
            msg = "Search filter cannot be empty"
            raise ValueError(msg)

        # Basic filter validation - should start and end with parentheses
        if not (value.startswith("(") and value.endswith(")")):
            msg = "Search filter must be enclosed in parentheses"
            raise ValueError(msg)

        # Check for balanced parentheses
        paren_count = 0
        for char in value:
            if char == "(":
                paren_count += 1
            elif char == ")":
                paren_count -= 1
                if paren_count < 0:
                    msg = "Unbalanced parentheses in search filter"
                    raise ValueError(msg)

        if paren_count != 0:
            msg = "Unbalanced parentheses in search filter"
            raise ValueError(msg)

        return value

    def get_ldap3_scope(self) -> str:
        """Get ldap3 library scope constant.

        Returns:
            ldap3 scope constant for the configured search scope
        """
        mapping = {
            "BASE": ldap3.BASE,
            "ONELEVEL": ldap3.LEVEL,
            "SUBTREE": ldap3.SUBTREE,
            "base": ldap3.BASE,
            "onelevel": ldap3.LEVEL,
            "subtree": ldap3.SUBTREE,
        }
        return mapping[self.search_scope]


class LDAPConnectionOptions(BaseModel):
    """Complete LDAP connection options including SSH tunnel configuration.

    This class follows the Composition principle by combining connection info
    with additional operational parameters.

    Extracted and enhanced from algar-oud-mig LDAPConnectionOptions.
    """

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    connection_info: LDAPConnectionInfo = Field(
        description="Core LDAP connection configuration",
    )

    enable_ssh_tunnel: bool = Field(
        default=False,
        description="Enable SSH tunnel for secure connections",
    )

    ssh_host: str | None = Field(
        default=None,
        description="SSH server hostname for tunnel",
    )

    ssh_port: int = Field(
        default=22,
        description="SSH server port",
        ge=1,
        le=65535,
    )

    ssh_username: str | None = Field(
        default=None,
        description="SSH username for tunnel authentication",
    )

    connection_pool_enabled: bool = Field(
        default=True,
        description="Enable connection pooling for performance",
    )

    max_pool_size: int = Field(
        default=10,
        description="Maximum connections in pool",
        ge=1,
        le=DEFAULT_MAX_ITEMS,
    )

    @field_validator("ssh_host")
    @classmethod
    def validate_ssh_config(cls, value: str | None, info: ValidationInfo) -> str | None:
        """Validate SSH tunnel configuration consistency.

        Args:
            value: SSH host value
            info: Validation context

        Returns:
            Validated SSH host

        Raises:
            ValueError: If SSH configuration is inconsistent
        """
        enable_ssh = info.data.get("enable_ssh_tunnel", False) if info.data else False

        if enable_ssh and not value:
            msg = "SSH host is required when SSH tunnel is enabled"
            raise ValueError(msg)

        if not enable_ssh and value:
            msg = "SSH host provided but SSH tunnel is disabled"
            raise ValueError(msg)

        return value
