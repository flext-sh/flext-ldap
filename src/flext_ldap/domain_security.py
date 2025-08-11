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
from typing import TYPE_CHECKING

from flext_core import FlextEntity, FlextResult

if TYPE_CHECKING:
    from flext_core import FlextTypes

# Constants imported from centralized module


class FlextLdapCertificateValidationResult(Enum):
    """Certificate validation result types."""

    VALID = "valid"
    EXPIRED = "expired"
    INVALID_HOSTNAME = "invalid_hostname"
    INVALID_SIGNATURE = "invalid_signature"
    MALFORMED = "malformed"
    REVOKED = "revoked"
    UNKNOWN_CA = "unknown_ca"


class FlextLdapCertificateInfo(FlextEntity):
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
    extensions: FlextTypes.Core.JsonDict = field(default_factory=dict)

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

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for certificate information."""
        # Railway Oriented Programming - Consolidated validation pipeline
        return self._execute_certificate_validation_pipeline()

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for certificate information."""
        return self.validate_business_rules()

    def _execute_certificate_validation_pipeline(self) -> FlextResult[None]:
        """Execute certificate validation pipeline with consolidated error handling."""
        # Chain all validations - fail fast on first error
        validation_result = self._validate_required_fields()
        if validation_result.is_failure:
            return validation_result

        validation_result = self._validate_date_consistency()
        if validation_result.is_failure:
            return validation_result

        validation_result = self._validate_key_requirements()
        if validation_result.is_failure:
            return validation_result

        return FlextResult.ok(None)

    def _validate_required_fields(self) -> FlextResult[None]:
        """Validate required certificate fields - Single Responsibility."""
        if not self.subject:
            return FlextResult.fail("Certificate must have a subject")
        if not self.issuer:
            return FlextResult.fail("Certificate must have an issuer")
        if not self.serial_number:
            return FlextResult.fail("Certificate must have a serial number")
        return FlextResult.ok(None)

    def _validate_date_consistency(self) -> FlextResult[None]:
        """Validate certificate date consistency - Single Responsibility."""
        if self.not_after <= self.not_before:
            return FlextResult.fail("Certificate not_after must be after not_before")
        return FlextResult.ok(None)

    def _validate_key_requirements(self) -> FlextResult[None]:
        """Validate public key requirements - Single Responsibility."""
        if self.public_key_size <= 0:
            return FlextResult.fail("Public key size must be positive")
        return FlextResult.ok(None)


class FlextLdapCertificateValidationContext(FlextEntity):
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

    def model_post_init(self, __context: object, /) -> None:
        """Post-initialization validation."""
        max_tcp_port = 65535
        if self.port <= 0 or self.port > max_tcp_port:
            min_port = 1
            max_port = 65535
            msg = f"Port must be between {min_port} and {max_port}"
            raise ValueError(msg)

        if not self.hostname:
            msg = "Hostname cannot be empty"
            raise ValueError(msg)

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for certificate validation context."""
        if not self.hostname:
            return FlextResult.fail(
                "Certificate validation context must have a hostname",
            )
        max_tcp_port = 65535
        if self.port <= 0 or self.port > max_tcp_port:
            min_port = 1
            max_port = 65535
            return FlextResult.fail(f"Port must be between {min_port} and {max_port}")
        if self.minimum_tls_version not in {"TLSv1.2", "TLSv1.3"}:
            return FlextResult.fail("Minimum TLS version must be TLSv1.2 or TLSv1.3")
        if self.maximum_tls_version not in {"TLSv1.2", "TLSv1.3"}:
            return FlextResult.fail("Maximum TLS version must be TLSv1.2 or TLSv1.3")
        return FlextResult.ok(None)


class FlextLdapValidationResult(FlextEntity):
    """Certificate validation result."""

    result_type: FlextLdapCertificateValidationResult | str
    message: str
    certificate_info: FlextLdapCertificateInfo | None = None
    chain_length: int = 0
    validation_errors: list[str] = field(default_factory=list)
    validation_warnings: list[str] = field(default_factory=list)
    validated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_valid(self) -> bool:
        """Check if validation result is valid."""
        return self.result_type == FlextLdapCertificateValidationResult.VALID

    @property
    def has_errors(self) -> bool:
        """Check if validation has errors."""
        return len(self.validation_errors) > 0

    @property
    def has_warnings(self) -> bool:
        """Check if validation has warnings."""
        return len(self.validation_warnings) > 0

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for certificate validation result."""
        if not self.message:
            return FlextResult.fail("ValidationResult must have a message")
        if self.chain_length < 0:
            return FlextResult.fail("Chain length cannot be negative")
        return FlextResult.ok(None)

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for certificate validation result."""
        return self.validate_business_rules()


class FlextLdapSSLContextConfig(FlextEntity):
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

    def model_post_init(self, __context: object, /) -> None:
        """Post-initialization validation."""
        valid_verify_modes = ["CERT_NONE", "CERT_OPTIONAL", "CERT_REQUIRED"]
        if self.verify_mode not in valid_verify_modes:
            msg = (
                f"Invalid verify_mode: {self.verify_mode}. "
                f"Must be one of {valid_verify_modes}"
            )
            raise ValueError(msg)

        valid_versions = ["TLSv1.2", "TLSv1.3"]
        if self.minimum_version not in valid_versions:
            msg = (
                f"Invalid minimum_version: {self.minimum_version}. "
                f"Must be one of {valid_versions}"
            )
            raise ValueError(msg)

        if self.maximum_version not in valid_versions:
            msg = (
                f"Invalid maximum_version: {self.maximum_version}. "
                f"Must be one of {valid_versions}"
            )
            raise ValueError(msg)

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for SSL context configuration."""
        # Railway Oriented Programming - Consolidated SSL validation pipeline
        return self._execute_ssl_validation_pipeline()

    def _execute_ssl_validation_pipeline(self) -> FlextResult[None]:
        """Execute SSL validation pipeline with consolidated error handling."""
        # Chain all validations - fail fast on first error
        validation_result = self._validate_verify_mode()
        if validation_result.is_failure:
            return validation_result

        validation_result = self._validate_tls_versions()
        if validation_result.is_failure:
            return validation_result

        validation_result = self._validate_client_certificate_consistency()
        if validation_result.is_failure:
            return validation_result

        return FlextResult.ok(None)

    def _validate_verify_mode(self) -> FlextResult[None]:
        """Validate SSL verify mode - Single Responsibility."""
        valid_verify_modes = ["CERT_NONE", "CERT_OPTIONAL", "CERT_REQUIRED"]
        if self.verify_mode not in valid_verify_modes:
            return FlextResult.fail(f"Invalid verify_mode: {self.verify_mode}")
        return FlextResult.ok(None)

    def _validate_tls_versions(self) -> FlextResult[None]:
        """Validate TLS version configuration - Single Responsibility."""
        valid_versions = ["TLSv1.2", "TLSv1.3"]
        if self.minimum_version not in valid_versions:
            return FlextResult.fail(f"Invalid minimum_version: {self.minimum_version}")
        if self.maximum_version not in valid_versions:
            return FlextResult.fail(f"Invalid maximum_version: {self.maximum_version}")
        return FlextResult.ok(None)

    def _validate_client_certificate_consistency(self) -> FlextResult[None]:
        """Validate client certificate file consistency - Single Responsibility."""
        if self.client_cert_file and not self.client_key_file:
            return FlextResult.fail(
                "Client key file is required when client cert file is provided",
            )
        if self.client_key_file and not self.client_cert_file:
            return FlextResult.fail(
                "Client cert file is required when client key file is provided",
            )
        return FlextResult.ok(None)


# Backward compatibility aliases
CertificateValidationResult = FlextLdapCertificateValidationResult
CertificateInfo = FlextLdapCertificateInfo
CertificateValidationContext = FlextLdapCertificateValidationContext
ValidationResult = FlextLdapValidationResult
SSLContextConfig = FlextLdapSSLContextConfig
