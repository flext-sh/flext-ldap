"""FLEXT LDAP Connection Configuration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from pathlib import Path

from flext_core import FlextConfig, FlextLogger, FlextResult, FlextValidations
from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict


class FlextLDAPConnectionConfig(FlextConfig):
    """LDAP connection configuration with validation."""

    model_config = SettingsConfigDict(
        extra="ignore",  # Allow client-a and other project-specific environment variables
        validate_assignment=True,
        str_strip_whitespace=True,
    )

    def __init__(
        self,
        /,
        *,
        _factory_mode: bool = False,
        _env_file: str | None = None,
        _env_format: str = "env",
        **_data: object,
    ) -> None:
        """Initialize LDAP connection configuration."""
        super().__init__(
            _factory_mode=_factory_mode,
            _env_file=_env_file,
            _env_format=_env_format,
            **_data,
        )
        self._logger = FlextLogger(__name__)

    # Basic Connection Settings
    server: str = Field(
        default="ldap://localhost",
        description="LDAP server URI (e.g., 'ldap://host' or 'ldaps://host:636')",
        min_length=1,
    )

    port: int = Field(
        default=389,
        description="LDAP server port (389 for LDAP, 636 for LDAPS)",
        ge=1,
        le=65535,
    )

    use_ssl: bool = Field(
        default=False,
        description="Use SSL/TLS encryption (LDAPS)",
    )

    # Authentication Settings
    bind_dn: str = Field(
        default="",
        description="Bind Distinguished Name for authentication",
    )

    bind_password: str = Field(
        default="",
        description="Password for bind DN",
        repr=False,  # Hide password in repr
    )

    # Connection Pool Settings
    timeout: int = Field(
        default=30,
        description="Connection timeout in seconds",
        ge=1,
        le=300,
    )

    pool_size: int = Field(
        default=5,
        description="Maximum number of connections in pool",
        ge=1,
        le=50,
    )

    # TLS/SSL Settings
    ca_cert_file: Path | None = Field(
        default=None,
        description="Path to CA certificate file for SSL verification",
    )

    client_cert_file: Path | None = Field(
        default=None,
        description="Path to client certificate file",
    )

    client_key_file: Path | None = Field(
        default=None,
        description="Path to client private key file",
    )

    verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates",
    )

    @field_validator("server")
    @classmethod
    def validate_server_uri(cls, v: str) -> str:
        """Validate LDAP server URI format using FlextValidations - NO DUPLICATION."""
        # Use FlextValidations instead of custom validation
        if not FlextValidations.is_non_empty_string(v):
            msg = "Server URI cannot be empty"
            raise ValueError(msg)

        v = v.strip()

        # Use basic pattern validation for URI validation
        if not v.startswith(("ldap://", "ldaps://")):
            msg = "LDAP URI must start with 'ldap://' or 'ldaps://'"
            raise ValueError(msg)

        return v

    @field_validator("ca_cert_file", "client_cert_file", "client_key_file")
    @classmethod
    def validate_cert_files(cls, v: Path | None) -> Path | None:
        """Validate certificate files using FlextValidations - NO DUPLICATION."""
        if v is None:
            return v

        # Use FlextValidations for file path validation
        path_str = str(v)
        if not FlextValidations.is_non_empty_string(path_str):
            msg = "Certificate file path invalid"
            raise ValueError(msg)

        # File existence validation - could be extended with FlextValidations.Rules.FileRules if available
        if not v.exists():
            msg = f"Certificate file does not exist: {v}"
            raise ValueError(msg)

        return v

    def get_server_uri(self) -> str:
        """Get complete server URI including port if non-standard."""
        if ":" in self.server and not self.server.endswith(f":{self.port}"):
            # Server already includes port
            return self.server

        # Add port if non-standard
        standard_port = 636 if self.use_ssl else 389
        if self.port != standard_port:
            base_uri = self.server.rstrip("/")
            return f"{base_uri}:{self.port}"

        return self.server

    def validate_configuration(self) -> FlextResult[None]:
        """Validate the complete configuration.

        Returns:
            str:: Description of return value.

        """
        try:
            # Additional validation logic here
            if self.use_ssl and self.verify_ssl and not self.ca_cert_file:
                self._logger.warning(
                    "SSL verification enabled but no CA certificate file specified"
                )

            return FlextResult.ok(None)
        except Exception as e:
            return FlextResult.fail(f"Configuration validation failed: {e}")


__all__ = ["FlextLDAPConnectionConfig"]
