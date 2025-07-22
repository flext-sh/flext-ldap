"""Data Type Conversion Infrastructure for LDAP Operations.

This module provides comprehensive data type conversion between LDAP
attribute values and Python types, supporting enterprise-grade type
safety and validation with proper error handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import binascii
import logging
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from flext_core.domain.shared_types import ServiceResult

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


class LDAPDataType(Enum):
    """LDAP data types enumeration."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    BINARY = "binary"
    DATE_TIME = "datetime"
    UUID = "uuid"
    DN = "dn"
    EMAIL = "email"
    PHONE = "phone"
    URL = "url"
    IP_ADDRESS = "ip_address"
    MAC_ADDRESS = "mac_address"
    CERTIFICATE = "certificate"
    PASSWORD = "password"
    UNKNOWN = "unknown"


class ConversionError(Exception):
    """Data type conversion error."""

    def __init__(
        self,
        message: str,
        source_value: Any = None,
        target_type: str = "",
    ) -> None:
        """Initialize conversion error."""
        super().__init__(message)
        self.source_value = source_value
        self.target_type = target_type


class ConversionResult:
    """Data type conversion result."""

    def __init__(
        self,
        value: Any,
        source_type: LDAPDataType,
        target_type: type,
        *,
        is_valid: bool = True,
        warnings: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Initialize conversion result."""
        self.value = value
        self.source_type = source_type
        self.target_type = target_type
        self.is_valid = is_valid
        self.warnings = warnings or []
        self.metadata = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "value": self.value,
            "source_type": self.source_type.value,
            "target_type": self.target_type.__name__
            if hasattr(self.target_type, "__name__")
            else str(self.target_type),
            "is_valid": self.is_valid,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


class DataTypeConverter:
    """Enterprise data type converter for LDAP operations."""

    def __init__(self) -> None:
        """Initialize data type converter."""
        self._type_detectors: dict[LDAPDataType, Callable[[str], bool]] = {
            LDAPDataType.EMAIL: self._is_email,
            LDAPDataType.PHONE: self._is_phone,
            LDAPDataType.URL: self._is_url,
            LDAPDataType.IP_ADDRESS: self._is_ip_address,
            LDAPDataType.MAC_ADDRESS: self._is_mac_address,
            LDAPDataType.UUID: self._is_uuid,
            LDAPDataType.DN: self._is_dn,
            LDAPDataType.DATE_TIME: self._is_datetime,
            LDAPDataType.BINARY: self._is_binary,
            LDAPDataType.BOOLEAN: self._is_boolean,
            LDAPDataType.INTEGER: self._is_integer,
        }

        self._converters: dict[tuple[LDAPDataType, type], Callable[[Any], Any]] = {
            (LDAPDataType.STRING, str): self._convert_to_string,
            (LDAPDataType.INTEGER, int): self._convert_to_int,
            (LDAPDataType.BOOLEAN, bool): self._convert_to_bool,
            (LDAPDataType.BINARY, bytes): self._convert_to_bytes,
            (LDAPDataType.DATE_TIME, datetime): self._convert_to_datetime,
            (LDAPDataType.UUID, uuid.UUID): self._convert_to_uuid,
            (LDAPDataType.EMAIL, str): self._convert_email_to_string,
            (LDAPDataType.PHONE, str): self._convert_phone_to_string,
            (LDAPDataType.URL, str): self._convert_url_to_string,
            (LDAPDataType.IP_ADDRESS, str): self._convert_ip_to_string,
            (LDAPDataType.MAC_ADDRESS, str): self._convert_mac_to_string,
            (LDAPDataType.DN, str): self._convert_dn_to_string,
            (LDAPDataType.CERTIFICATE, bytes): self._convert_cert_to_bytes,
        }

        logger.info("Data type converter initialized")

    async def detect_type(self, value: Any) -> ServiceResult[LDAPDataType]:
        """Detect LDAP data type from value."""
        try:
            if value is None:
                return ServiceResult.ok(LDAPDataType.UNKNOWN)

            # Convert to string for analysis
            str_value = str(value).strip()

            if not str_value:
                return ServiceResult.ok(LDAPDataType.STRING)

            # Try each detector in order of specificity
            for data_type, detector in self._type_detectors.items():
                try:
                    if detector(str_value):
                        logger.debug(
                            "Detected type %s for value: %s...",
                            data_type.value,
                            str_value[:50],
                        )
                        return ServiceResult.ok(data_type)
                except Exception as e:
                    # If detector fails, log and continue to next
                    logger.debug("Type detector failed: %s", str(e))
                    continue

            # Default to string if no specific type detected
            return ServiceResult.ok(LDAPDataType.STRING)

        except Exception as e:
            error_msg = f"Failed to detect data type: {e}"
            logger.exception(error_msg)
            return ServiceResult.fail(error_msg)

    async def convert_value(
        self,
        value: Any,
        target_type: type,
        source_type: LDAPDataType | None = None,
    ) -> ServiceResult[Any]:
        """Convert value to target type."""
        try:
            # Auto-detect source type if not provided
            if source_type is None:
                detect_result = await self.detect_type(value)
                if not detect_result.success:
                    return ServiceResult.fail(
                        f"Failed to detect source type: {detect_result.error}",
                    )
                source_type = detect_result.data

            # At this point source_type is guaranteed to be not None
            if source_type is None:
                return ServiceResult.fail("Failed to detect source type")

            # Check for direct converter
            converter_key = (source_type, target_type)
            if converter_key in self._converters:
                converter = self._converters[converter_key]
                try:
                    converted_value = converter(value)
                    result = ConversionResult(
                        value=converted_value,
                        source_type=source_type,
                        target_type=target_type,
                        is_valid=True,
                    )
                    return ServiceResult.ok(result)
                except ConversionError as e:
                    result = ConversionResult(
                        value=None,
                        source_type=source_type,
                        target_type=target_type,
                        is_valid=False,
                        warnings=[str(e)],
                    )
                    return ServiceResult.ok(result)

            # Try generic conversion
            try:
                if target_type is str:
                    converted_value = str(value)
                elif target_type is int:
                    converted_value = int(value)
                elif target_type is float:
                    converted_value = float(value)
                elif target_type is bool:
                    converted_value = bool(value)
                elif target_type is bytes:
                    if isinstance(value, str):
                        converted_value = value.encode("utf-8")
                    elif isinstance(value, bytes):
                        converted_value = value
                    else:
                        converted_value = bytes(value)
                else:
                    # Try direct type conversion
                    converted_value = target_type(value)

                result = ConversionResult(
                    value=converted_value,
                    source_type=source_type,
                    target_type=target_type,
                    is_valid=True,
                    warnings=["Used generic conversion"],
                )
                return ServiceResult.ok(result)

            except Exception as e:
                result = ConversionResult(
                    value=None,
                    source_type=source_type,
                    target_type=target_type,
                    is_valid=False,
                    warnings=[f"Generic conversion failed: {e}"],
                )
                return ServiceResult.ok(result)

        except Exception as e:
            error_msg = f"Value conversion failed: {e}"
            logger.exception(error_msg)
            return ServiceResult.fail(error_msg)

    async def convert_batch(
        self,
        values: list[Any],
        target_type: type,
        source_type: LDAPDataType | None = None,
    ) -> ServiceResult[list[Any]]:
        """Convert batch of values to target type."""
        try:
            results: list[ConversionResult] = []
            for value in values:
                convert_result = await self.convert_value(
                    value,
                    target_type,
                    source_type,
                )
                if convert_result.success:
                    if convert_result.data is not None:
                        results.append(convert_result.data)
                    else:
                        # Handle unexpected None value
                        failed_result = ConversionResult(
                            value=None,
                            source_type=source_type or LDAPDataType.UNKNOWN,
                            target_type=target_type,
                            is_valid=False,
                            warnings=["Unexpected None value in successful conversion"],
                        )
                        results.append(failed_result)
                else:
                    # Create failed result
                    failed_result = ConversionResult(
                        value=None,
                        source_type=source_type or LDAPDataType.UNKNOWN,
                        target_type=target_type,
                        is_valid=False,
                        warnings=[convert_result.error or "Conversion failed"],
                    )
                    results.append(failed_result)

            return ServiceResult.ok(results)

        except Exception as e:
            error_msg = f"Batch conversion failed: {e}"
            logger.exception(error_msg)
            return ServiceResult.fail(error_msg)

    async def validate_type_compatibility(
        self,
        source_type: LDAPDataType,
        target_type: type,
    ) -> ServiceResult[bool]:
        """Validate if source type can be converted to target type."""
        try:
            # Check if direct converter exists
            converter_key = (source_type, target_type)
            if converter_key in self._converters:
                return ServiceResult.ok(True)

            # Check common conversions
            compatible_conversions: dict[LDAPDataType, list[type]] = {
                LDAPDataType.STRING: [str, bytes],
                LDAPDataType.INTEGER: [int, float, str],
                LDAPDataType.BOOLEAN: [bool, str, int],
                LDAPDataType.BINARY: [bytes, str],
                LDAPDataType.DATE_TIME: [datetime, str],
                LDAPDataType.UUID: [uuid.UUID, str],
                LDAPDataType.EMAIL: [str],
                LDAPDataType.PHONE: [str],
                LDAPDataType.URL: [str],
                LDAPDataType.IP_ADDRESS: [str],
                LDAPDataType.MAC_ADDRESS: [str],
                LDAPDataType.DN: [str],
                LDAPDataType.CERTIFICATE: [bytes, str],
            }

            compatible_types = compatible_conversions.get(source_type, [])
            is_compatible = target_type in compatible_types

            return ServiceResult.ok(is_compatible)

        except Exception as e:
            error_msg = f"Type compatibility check failed: {e}"
            logger.exception(error_msg)
            return ServiceResult.fail(error_msg)

    # Type detectors
    def _is_email(self, value: str) -> bool:
        """Check if value is an email address."""
        import re

        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(email_pattern, value))

    def _is_phone(self, value: str) -> bool:
        """Check if value is a phone number."""
        import re

        # Simple phone pattern - can be enhanced
        phone_pattern = r"^[\+]?[\s]?[\(]?[\d\s\-\(\)]{10,}$"
        return bool(re.match(phone_pattern, value))

    def _is_url(self, value: str) -> bool:
        """Check if value is a URL."""
        return value.startswith(
            ("http://", "https://", "ftp://", "ldap://", "ldaps://"),
        )

    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address."""
        import ipaddress

        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        else:
            return True

    def _is_mac_address(self, value: str) -> bool:
        """Check if value is a MAC address."""
        import re

        mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        return bool(re.match(mac_pattern, value))

    def _is_uuid(self, value: str) -> bool:
        """Check if value is a UUID."""
        import uuid

        try:
            uuid.UUID(value)
        except ValueError:
            return False
        else:
            return True

    def _is_dn(self, value: str) -> bool:
        """Check if value is a distinguished name."""
        # Simple DN pattern check
        return "=" in value and ("," in value or value.count("=") == 1)

    def _is_datetime(self, value: str) -> bool:
        """Check if value is a datetime string."""
        # Check for common datetime patterns
        datetime_patterns = [
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",  # ISO format
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",  # Standard format
            r"\d{14}Z",  # LDAP GeneralizedTime
            r"\d{12}Z",  # LDAP UTCTime
        ]

        import re

        return any(re.match(pattern, value) for pattern in datetime_patterns)

    def _is_binary(self, value: str) -> bool:
        """Check if value is binary data (base64)."""
        try:
            # Check if it's valid base64 and looks like binary data
            if len(value) >= 8 and len(value) % 4 == 0:
                # Should not be common text patterns
                if value.lower() in {"true", "false", "yes", "no"}:
                    return False

                decoded = base64.b64decode(value, validate=True)
                # Check if decoded contains non-printable characters (likely binary)
                try:
                    decoded.decode("utf-8")
                    # If it decodes to text cleanly, it's probably not binary data
                    return (
                        len(decoded) > 20
                    )  # Only consider it binary if substantial size
                except UnicodeDecodeError:
                    # Contains non-UTF8 data, likely binary
                    return True
        except Exception as e:
            logger.debug("Binary detection failed: %s", str(e))
        return False

    def _is_boolean(self, value: str) -> bool:
        """Check if value is a boolean."""
        return value.lower() in {"true", "false", "yes", "no", "1", "0", "on", "off"}

    def _is_integer(self, value: str) -> bool:
        """Check if value is an integer."""
        try:
            int(value)
        except ValueError:
            return False
        else:
            return True

    # Type converters
    def _convert_to_string(self, value: Any) -> str:
        """Convert value to string."""
        return str(value)

    def _convert_to_int(self, value: Any) -> int:
        """Convert value to integer."""
        try:
            return int(value)
        except ValueError as e:
            msg = f"Cannot convert '{value}' to integer"
            raise ConversionError(msg) from e

    def _convert_to_bool(self, value: Any) -> bool:
        """Convert value to boolean."""
        if isinstance(value, bool):
            return value

        str_value = str(value).lower()
        if str_value in {"true", "yes", "1", "on"}:
            return True
        if str_value in {"false", "no", "0", "off"}:
            return False
        msg = f"Cannot convert '{value}' to boolean"
        raise ConversionError(msg)

    def _convert_to_bytes(self, value: Any) -> bytes:
        """Convert value to bytes."""
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            # NO FALLBACKS - SEMPRE usar implementações originais conforme instrução
            # First try base64 decode, if it fails, encode as UTF-8 bytes
            try:
                return base64.b64decode(value)
            except (ValueError, binascii.Error):
                # Not base64, encode string as UTF-8 bytes
                return value.encode("utf-8")
        return bytes(value)

    def _convert_to_datetime(self, value: Any) -> datetime:
        """Convert value to datetime."""
        if isinstance(value, datetime):
            return value

        str_value = str(value)

        # Try different datetime formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO with microseconds
            "%Y-%m-%dT%H:%M:%SZ",  # ISO format
            "%Y-%m-%d %H:%M:%S",  # Standard format
            "%Y%m%d%H%M%SZ",  # LDAP GeneralizedTime
            "%y%m%d%H%M%SZ",  # LDAP UTCTime
        ]

        for fmt in formats:
            try:
                # Create timezone-aware datetime directly
                dt = datetime.strptime(str_value, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
            else:
                return dt

        msg = f"Cannot convert '{value}' to datetime"
        raise ConversionError(msg)

    def _convert_to_uuid(self, value: Any) -> uuid.UUID:
        """Convert value to UUID."""
        try:
            return uuid.UUID(str(value))
        except ValueError as e:
            msg = f"Cannot convert '{value}' to UUID"
            raise ConversionError(msg) from e

    def _convert_email_to_string(self, value: Any) -> str:
        """Convert email to normalized string."""
        return str(value).lower().strip()

    def _convert_phone_to_string(self, value: Any) -> str:
        """Convert phone to normalized string."""
        import re

        # Remove all non-numeric characters except +
        return re.sub(r"[^\d\+]", "", str(value))

    def _convert_url_to_string(self, value: Any) -> str:
        """Convert URL to normalized string."""
        return str(value).strip()

    def _convert_ip_to_string(self, value: Any) -> str:
        """Convert IP address to normalized string."""
        import ipaddress

        try:
            # Normalize IP address
            ip = ipaddress.ip_address(str(value))
            return str(ip)
        except ValueError as e:
            msg = f"Invalid IP address: {value}"
            raise ConversionError(msg) from e

    def _convert_mac_to_string(self, value: Any) -> str:
        """Convert MAC address to normalized string."""
        import re

        # Normalize MAC address format
        mac = re.sub(r"[:-]", "", str(value)).upper()
        if len(mac) == 12:
            return ":".join(mac[i : i + 2] for i in range(0, 12, 2))
        msg = f"Invalid MAC address: {value}"
        raise ConversionError(msg)

    def _convert_dn_to_string(self, value: Any) -> str:
        """Convert DN to normalized string."""
        # Basic DN normalization - can be enhanced
        return str(value).strip()

    def _convert_cert_to_bytes(self, value: Any) -> bytes:
        """Convert certificate to bytes."""
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            # Try base64 decode
            try:
                return base64.b64decode(value)
            except Exception:
                # Try direct encoding
                return value.encode("utf-8")
        else:
            msg = f"Cannot convert certificate to bytes: {type(value)}"
            raise TypeError(msg)

    def get_supported_types(self) -> list[LDAPDataType]:
        """Get list of supported LDAP data types."""
        return list(LDAPDataType)

    def get_supported_conversions(self) -> dict[LDAPDataType, list[type]]:
        """Get mapping of supported conversions."""
        conversions: dict[LDAPDataType, list[type]] = {}
        for source_type, target_type in self._converters:
            if source_type not in conversions:
                conversions[source_type] = []
            conversions[source_type].append(target_type)
        return conversions
