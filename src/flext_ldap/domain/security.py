"""LDAP Security Domain Types and Entities.

This module provides comprehensive security types for LDAP operations,
including certificate validation, SSL/TLS configuration, and security
contexts following enterprise security standards.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from flext_core.domain.pydantic_base import DomainEntity


class CertificateValidationResult(Enum):
    """Certificate validation result types."""

    VALID = "valid"
    EXPIRED = "expired"
    INVALID_HOSTNAME = "invalid_hostname"
    INVALID_SIGNATURE = "invalid_signature"
    MALFORMED = "malformed"
    REVOKED = "revoked"
    UNKNOWN_CA = "unknown_ca"


class CertificateInfo(DomainEntity):
    """Certificate information domain entity."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int
    fingerprint_sha256: str
    extensions: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        return datetime.now(UTC) > self.not_after

    def is_not_yet_valid(self) -> bool:
        """Check if certificate is not yet valid."""
        return datetime.now(UTC) < self.not_before

    def is_valid_for_hostname(self, hostname: str) -> bool:
        """Check if certificate is valid for given hostname."""
        # Extract common name from subject
        cn = None
        for part in self.subject.split(","):
            if part.strip().startswith("CN="):
                cn = part.strip()[3:]
                break

        if not cn:
            return False

        # Simple hostname validation - can be enhanced with SAN support
        if cn == hostname:
            return True

        # Wildcard support
        if cn.startswith("*."):
            domain = cn[2:]
            return hostname.endswith(f".{domain}")

        return False


class CertificateValidationContext(DomainEntity):
    """Context for certificate validation."""

    hostname: str
    port: int
    verify_hostname: bool = True
    verify_chain: bool = True
    ca_cert_path: str | None = None
    ca_cert_data: bytes | None = None
    allowed_ciphers: list[str] = field(default_factory=list)
    minimum_tls_version: str = "TLSv1.2"
    maximum_tls_version: str = "TLSv1.3"

    def model_post_init(self, __context: Any, /) -> None:
        """Post-initialization validation."""
        if self.port <= 0 or self.port > 65535:
            msg = "Port must be between 1 and 65535"
            raise ValueError(msg)

        if not self.hostname:
            msg = "Hostname cannot be empty"
            raise ValueError(msg)


class ValidationResult(DomainEntity):
    """Certificate validation result."""

    result_type: CertificateValidationResult | str
    message: str
    certificate_info: CertificateInfo | None = None
    chain_length: int = 0
    validation_errors: list[str] = field(default_factory=list)
    validation_warnings: list[str] = field(default_factory=list)
    validated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_valid(self) -> bool:
        """Check if validation result is valid."""
        return self.result_type == CertificateValidationResult.VALID.value

    @property
    def has_errors(self) -> bool:
        """Check if validation has errors."""
        return len(self.validation_errors) > 0

    @property
    def has_warnings(self) -> bool:
        """Check if validation has warnings."""
        return len(self.validation_warnings) > 0


class SSLContextConfig(DomainEntity):
    """SSL/TLS context configuration."""

    verify_mode: str = "CERT_REQUIRED"
    check_hostname: bool = True
    minimum_version: str = "TLSv1.2"
    maximum_version: str = "TLSv1.3"
    ca_cert_file: str | None = None
    ca_cert_data: bytes | None = None
    client_cert_file: str | None = None
    client_key_file: str | None = None
    ciphers: str | None = None
    options: list[str] = field(default_factory=list)

    def model_post_init(self, __context: Any, /) -> None:
        """Post-initialization validation."""
        valid_verify_modes = ["CERT_NONE", "CERT_OPTIONAL", "CERT_REQUIRED"]
        if self.verify_mode not in valid_verify_modes:
            msg = f"Invalid verify_mode: {self.verify_mode}. Must be one of {valid_verify_modes}"
            raise ValueError(msg)

        valid_versions = ["TLSv1.2", "TLSv1.3"]
        if self.minimum_version not in valid_versions:
            msg = f"Invalid minimum_version: {self.minimum_version}. Must be one of {valid_versions}"
            raise ValueError(msg)

        if self.maximum_version not in valid_versions:
            msg = f"Invalid maximum_version: {self.maximum_version}. Must be one of {valid_versions}"
            raise ValueError(msg)
