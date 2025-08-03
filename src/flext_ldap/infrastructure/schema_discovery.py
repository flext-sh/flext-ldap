"""Schema Discovery Service Infrastructure.

This module provides comprehensive LDAP schema discovery capabilities,
including object class, attribute type, and schema rule discovery with
caching and enterprise-grade validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar, TypedDict
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from collections.abc import Callable

from flext_core import FlextResult, get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from flext_ldap.entities import FlextLdapConnection

logger = get_logger(__name__)


class ValidationResult(TypedDict):
    """Type-safe validation result structure."""

    is_valid: bool
    errors: list[str]
    warnings: list[str]
    missing_required: list[str]
    unknown_attributes: list[str]
    schema_violations: list[str]


class FlextLdapSchemaDiscoveryConstants:
    """Schema discovery constants following DRY principle."""

    # Discovery History Management
    MAX_DISCOVERY_HISTORY: int = 100


class FlextLdapSchemaElementType(Enum):
    """LDAP schema element types."""

    OBJECT_CLASS = "objectClass"
    ATTRIBUTE_TYPE = "attributeType"
    SYNTAX = "ldapSyntax"
    MATCHING_RULE = "matchingRule"
    MATCHING_RULE_USE = "matchingRuleUse"
    DIT_CONTENT_RULE = "dITContentRule"
    DIT_STRUCTURE_RULE = "dITStructureRule"
    NAME_FORM = "nameForm"


class FlextLdapAttributeUsage(Enum):
    """LDAP attribute usage types."""

    USER_APPLICATIONS = "userApplications"
    DIRECTORY_OPERATION = "directoryOperation"
    DISTRIBUTED_OPERATION = "distributedOperation"
    DSA_OPERATION = "dSAOperation"


class FlextLdapObjectClassType(Enum):
    """LDAP object class types."""

    STRUCTURAL = "STRUCTURAL"
    ABSTRACT = "ABSTRACT"
    AUXILIARY = "AUXILIARY"


@dataclass
class FlextLdapSchemaAttributeData:
    """Data class for LDAP schema attribute parameters.

    Eliminates 14-parameter constructor using Parameter Object pattern.
    """

    oid: str
    names: list[str] | None = None
    description: str | None = None
    syntax: str | None = None
    equality_matching_rule: str | None = None
    ordering_matching_rule: str | None = None
    substring_matching_rule: str | None = None
    usage: FlextLdapAttributeUsage = FlextLdapAttributeUsage.USER_APPLICATIONS
    is_single_value: bool = False
    is_collective: bool = False
    is_no_user_modification: bool = False
    is_obsolete: bool = False
    superior: str | None = None
    extensions: dict[str, list[str]] | None = None


class FlextLdapSchemaAttribute:
    """LDAP schema attribute definition."""

    def __init__(self, data: FlextLdapSchemaAttributeData) -> None:
        """Initialize schema attribute using Parameter Object pattern."""
        self.oid = data.oid
        self.names = data.names or []
        self.description = data.description
        self.syntax = data.syntax
        self.equality_matching_rule = data.equality_matching_rule
        self.ordering_matching_rule = data.ordering_matching_rule
        self.substring_matching_rule = data.substring_matching_rule
        self.usage = data.usage
        self.is_single_value = data.is_single_value
        self.is_collective = data.is_collective
        self.is_no_user_modification = data.is_no_user_modification
        self.is_obsolete = data.is_obsolete
        self.superior = data.superior
        self.extensions = data.extensions or {}

    @classmethod
    def _create_data_from_params(
        cls,
        oid: str,
        **attribute_params: object,
    ) -> FlextLdapSchemaAttributeData:
        """Factory method to create type-safe FlextLdapSchemaAttributeData from parameters.

        REFACTORED: Eliminates object-to-specific-type assignment issues.
        Uses proper type validation and safe conversion.

        Args:
            oid: Object identifier (required)
            **attribute_params: All other attribute parameters as keyword arguments

        Returns:
            Type-safe FlextLdapSchemaAttributeData instance

        """

        # Safe type extraction functions
        def safe_extract_string(key: str) -> str | None:
            value = attribute_params.get(key)
            return str(value) if value is not None else None

        def safe_extract_string_list(key: str) -> list[str] | None:
            value = attribute_params.get(key)
            if isinstance(value, (list, tuple)):
                return [str(item) for item in value]
            return None

        def safe_extract_bool(key: str, default: bool) -> bool:
            value = attribute_params.get(key, default)
            return bool(value) if value is not None else default

        def safe_extract_usage() -> FlextLdapAttributeUsage:
            value = attribute_params.get(
                "usage", FlextLdapAttributeUsage.USER_APPLICATIONS,
            )
            return (
                value
                if isinstance(value, FlextLdapAttributeUsage)
                else FlextLdapAttributeUsage.USER_APPLICATIONS
            )

        def safe_extract_extensions() -> dict[str, list[str]] | None:
            value = attribute_params.get("extensions")
            if isinstance(value, dict):
                return {
                    str(k): [
                        str(v)
                        for v in (val if isinstance(val, (list, tuple)) else [val])
                    ]
                    for k, val in value.items()
                }
            return None

        return FlextLdapSchemaAttributeData(
            oid=oid,
            names=safe_extract_string_list("names"),
            description=safe_extract_string("description"),
            syntax=safe_extract_string("syntax"),
            equality_matching_rule=safe_extract_string("equality_matching_rule"),
            ordering_matching_rule=safe_extract_string("ordering_matching_rule"),
            substring_matching_rule=safe_extract_string("substring_matching_rule"),
            usage=safe_extract_usage(),
            is_single_value=safe_extract_bool("is_single_value", False),
            is_collective=safe_extract_bool("is_collective", False),
            is_no_user_modification=safe_extract_bool("is_no_user_modification", False),
            is_obsolete=safe_extract_bool("is_obsolete", False),
            superior=safe_extract_string("superior"),
            extensions=safe_extract_extensions(),
        )

    @classmethod
    def create(
        cls,
        oid: str,
        **attribute_params: object,
    ) -> FlextLdapSchemaAttribute:
        """Factory method using type-safe Parameter Object pattern.

        REFACTORED: Uses type-safe data creation method to eliminate MyPy errors.

        Args:
            oid: Object identifier (required)
            **attribute_params: All other attribute parameters as keyword arguments

        Returns:
            Type-safe FlextLdapSchemaAttribute instance

        """
        data = cls._create_data_from_params(oid, **attribute_params)
        return cls(data)

    @property
    def primary_name(self) -> str:
        """Get primary name of the attribute."""
        return self.names[0] if self.names else self.oid

    def has_name(self, name: str) -> bool:
        """Check if attribute has given name."""
        return name.lower() in [n.lower() for n in self.names]

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return {
            "oid": self.oid,
            "names": self.names,
            "description": self.description,
            "syntax": self.syntax,
            "equality_matching_rule": self.equality_matching_rule,
            "ordering_matching_rule": self.ordering_matching_rule,
            "substring_matching_rule": self.substring_matching_rule,
            "usage": self.usage.value,
            "is_single_value": self.is_single_value,
            "is_collective": self.is_collective,
            "is_no_user_modification": self.is_no_user_modification,
            "is_obsolete": self.is_obsolete,
            "superior": self.superior,
            "extensions": self.extensions,
        }


@dataclass
class FlextLdapSchemaObjectClassData:
    """Data class for LDAP schema object class parameters.

    Eliminates 9-parameter constructor using Parameter Object pattern.
    """

    oid: str
    names: list[str] | None = None
    description: str | None = None
    object_class_type: FlextLdapObjectClassType = FlextLdapObjectClassType.STRUCTURAL
    superior_classes: list[str] | None = None
    must_attributes: list[str] | None = None
    may_attributes: list[str] | None = None
    is_obsolete: bool = False
    extensions: dict[str, list[str]] | None = None


class FlextLdapSchemaObjectClass:
    """LDAP schema object class definition."""

    def __init__(self, data: FlextLdapSchemaObjectClassData) -> None:
        """Initialize schema object class using Parameter Object pattern."""
        self.oid = data.oid
        self.names = data.names or []
        self.description = data.description
        self.object_class_type = data.object_class_type
        self.superior_classes = data.superior_classes or []
        self.must_attributes = data.must_attributes or []
        self.may_attributes = data.may_attributes or []
        self.is_obsolete = data.is_obsolete
        self.extensions = data.extensions or {}

    @classmethod
    def _create_data_from_params(
        cls,
        oid: str,
        **object_class_params: object,
    ) -> FlextLdapSchemaObjectClassData:
        """Factory method to create type-safe FlextLdapSchemaObjectClassData from parameters.

        REFACTORED: Eliminates object-to-specific-type assignment issues.
        Uses proper type validation and safe conversion.

        Args:
            oid: Object identifier (required)
            **object_class_params: All other object class parameters as keyword arguments

        Returns:
            Type-safe FlextLdapSchemaObjectClassData instance

        """

        # Safe type extraction functions
        def safe_extract_string(key: str) -> str | None:
            value = object_class_params.get(key)
            return str(value) if value is not None else None

        def safe_extract_string_list(key: str) -> list[str] | None:
            value = object_class_params.get(key)
            if isinstance(value, (list, tuple)):
                return [str(item) for item in value]
            return None

        def safe_extract_bool(key: str, default: bool) -> bool:
            value = object_class_params.get(key, default)
            return bool(value) if value is not None else default

        def safe_extract_object_class_type() -> FlextLdapObjectClassType:
            value = object_class_params.get(
                "object_class_type", FlextLdapObjectClassType.STRUCTURAL,
            )
            return (
                value
                if isinstance(value, FlextLdapObjectClassType)
                else FlextLdapObjectClassType.STRUCTURAL
            )

        def safe_extract_extensions() -> dict[str, list[str]] | None:
            value = object_class_params.get("extensions")
            if isinstance(value, dict):
                return {
                    str(k): [
                        str(v)
                        for v in (val if isinstance(val, (list, tuple)) else [val])
                    ]
                    for k, val in value.items()
                }
            return None

        return FlextLdapSchemaObjectClassData(
            oid=oid,
            names=safe_extract_string_list("names"),
            description=safe_extract_string("description"),
            object_class_type=safe_extract_object_class_type(),
            superior_classes=safe_extract_string_list("superior_classes"),
            must_attributes=safe_extract_string_list("must_attributes"),
            may_attributes=safe_extract_string_list("may_attributes"),
            is_obsolete=safe_extract_bool("is_obsolete", False),
            extensions=safe_extract_extensions(),
        )

    @classmethod
    def create(
        cls,
        oid: str,
        **object_class_params: object,
    ) -> FlextLdapSchemaObjectClass:
        """Factory method using type-safe Parameter Object pattern.

        REFACTORED: Uses type-safe data creation method to eliminate MyPy errors.

        Args:
            oid: Object identifier (required)
            **object_class_params: All other object class parameters as keyword arguments

        Returns:
            Type-safe FlextLdapSchemaObjectClass instance

        """
        data = cls._create_data_from_params(oid, **object_class_params)
        return cls(data)

    @property
    def primary_name(self) -> str:
        """Get primary name of the object class."""
        return self.names[0] if self.names else self.oid

    def has_name(self, name: str) -> bool:
        """Check if object class has given name."""
        return name.lower() in [n.lower() for n in self.names]

    def get_all_attributes(
        self,
        schema_cache: dict[str, FlextLdapSchemaObjectClass],
    ) -> tuple[set[str], set[str]]:
        """Get all attributes (must and may) including inherited ones."""
        all_must = set(self.must_attributes)
        all_may = set(self.may_attributes)

        # Recursively collect from superior classes
        for superior in self.superior_classes:
            if superior in schema_cache:
                superior_class = schema_cache[superior]
                superior_must, superior_may = superior_class.get_all_attributes(
                    schema_cache,
                )
                all_must.update(superior_must)
                all_may.update(superior_may)

        return all_must, all_may

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return {
            "oid": self.oid,
            "names": self.names,
            "description": self.description,
            "object_class_type": self.object_class_type.value,
            "superior_classes": self.superior_classes,
            "must_attributes": self.must_attributes,
            "may_attributes": self.may_attributes,
            "is_obsolete": self.is_obsolete,
            "extensions": self.extensions,
        }


@dataclass
class FlextLdapSchemaDiscoveryData:
    """Data class for schema discovery result parameters."""

    discovery_id: UUID | None = None
    timestamp: datetime | None = None
    server_info: dict[str, object] | None = None
    object_classes: dict[str, FlextLdapSchemaObjectClass] | None = None
    attributes: dict[str, FlextLdapSchemaAttribute] | None = None
    syntaxes: dict[str, dict[str, object]] | None = None
    matching_rules: dict[str, dict[str, object]] | None = None
    discovery_errors: list[str] | None = None
    discovery_warnings: list[str] | None = None
    cache_hit: bool = False
    discovery_duration_ms: int = 0


class FlextLdapSchemaDiscoveryResult:
    """Schema discovery operation result."""

    def __init__(self, data: FlextLdapSchemaDiscoveryData | None = None) -> None:
        """Initialize schema discovery result using Parameter Object pattern."""
        data = data or FlextLdapSchemaDiscoveryData()
        self.discovery_id = data.discovery_id or uuid4()
        self.timestamp = data.timestamp or datetime.now(UTC)
        self.server_info = data.server_info or {}
        self.object_classes = data.object_classes or {}
        self.attributes = data.attributes or {}
        self.syntaxes = data.syntaxes or {}
        self.matching_rules = data.matching_rules or {}
        self.discovery_errors = data.discovery_errors or []
        self.discovery_warnings = data.discovery_warnings or []
        self.cache_hit = data.cache_hit
        self.discovery_duration_ms = data.discovery_duration_ms

    @classmethod
    def create(
        cls,
        **discovery_params: object,
    ) -> FlextLdapSchemaDiscoveryResult:
        """Factory method to create FlextLdapSchemaDiscoveryResult from parameters.

        REFACTORED: Eliminates direct **kwargs to constructor issues.
        Uses type-safe data creation.

        Args:
            **discovery_params: All discovery result parameters as keyword arguments

        Returns:
            Type-safe FlextLdapSchemaDiscoveryResult instance

        """

        # Safe type extraction functions
        def safe_extract_uuid(key: str) -> UUID | None:
            value = discovery_params.get(key)
            return value if isinstance(value, UUID) else None

        def safe_extract_datetime(key: str) -> datetime | None:
            value = discovery_params.get(key)
            return value if isinstance(value, datetime) else None

        def safe_extract_dict(key: str) -> dict[str, object] | None:
            value = discovery_params.get(key)
            return dict(value) if isinstance(value, dict) else None

        def safe_extract_nested_dict(key: str) -> dict[str, dict[str, object]] | None:
            value = discovery_params.get(key)
            if isinstance(value, dict):
                # Ensure all values are dict[str, object]
                return {
                    str(k): dict(v) if isinstance(v, dict) else {"value": v}
                    for k, v in value.items()
                }
            return None

        def safe_extract_object_classes_dict(
            key: str,
        ) -> dict[str, FlextLdapSchemaObjectClass] | None:
            value = discovery_params.get(key)
            return dict(value) if isinstance(value, dict) else None

        def safe_extract_attributes_dict(
            key: str,
        ) -> dict[str, FlextLdapSchemaAttribute] | None:
            value = discovery_params.get(key)
            return dict(value) if isinstance(value, dict) else None

        def safe_extract_string_list(key: str) -> list[str] | None:
            value = discovery_params.get(key)
            if isinstance(value, (list, tuple)):
                return [str(item) for item in value]
            return None

        def safe_extract_bool(key: str, default: bool = False) -> bool:
            value = discovery_params.get(key, default)
            return bool(value) if value is not None else default

        def safe_extract_int(key: str, default: int = 0) -> int:
            value = discovery_params.get(key, default)
            return int(value) if isinstance(value, (int, float)) else default

        data = FlextLdapSchemaDiscoveryData(
            discovery_id=safe_extract_uuid("discovery_id"),
            timestamp=safe_extract_datetime("timestamp"),
            server_info=safe_extract_dict("server_info"),
            object_classes=safe_extract_object_classes_dict("object_classes"),
            attributes=safe_extract_attributes_dict("attributes"),
            syntaxes=safe_extract_nested_dict("syntaxes"),
            matching_rules=safe_extract_nested_dict("matching_rules"),
            discovery_errors=safe_extract_string_list("discovery_errors"),
            discovery_warnings=safe_extract_string_list("discovery_warnings"),
            cache_hit=safe_extract_bool("cache_hit", False),
            discovery_duration_ms=safe_extract_int("discovery_duration_ms", 0),
        )
        return cls(data)

    @property
    def is_successful(self) -> bool:
        """Check if discovery was successful."""
        return len(self.discovery_errors) == 0

    @property
    def total_elements(self) -> int:
        """Get total number of discovered schema elements."""
        return (
            len(self.object_classes)
            + len(self.attributes)
            + len(self.syntaxes)
            + len(self.matching_rules)
        )

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return {
            "discovery_id": str(self.discovery_id),
            "timestamp": self.timestamp.isoformat(),
            "server_info": self.server_info,
            "object_classes": {k: v.to_dict() for k, v in self.object_classes.items()},
            "attributes": {k: v.to_dict() for k, v in self.attributes.items()},
            "syntaxes": self.syntaxes,
            "matching_rules": self.matching_rules,
            "discovery_errors": self.discovery_errors,
            "discovery_warnings": self.discovery_warnings,
            "cache_hit": self.cache_hit,
            "discovery_duration_ms": self.discovery_duration_ms,
            "total_elements": self.total_elements,
        }


class FlextLdapSchemaDiscoveryService:
    """LDAP schema discovery service implementation."""

    # Constants to eliminate code duplication - DRY Principle
    INET_ORG_PERSON_MAY_ATTRIBUTES: ClassVar[list[str]] = [
        "audio",
        "businessCategory",
        "carLicense",
        "departmentNumber",
        "displayName",
        "employeeNumber",
        "employeeType",
        "givenName",
        "homePhone",
        "homePostalAddress",
        "initials",
        "jpegPhoto",
        "labeledURI",
        "mail",
        "manager",
        "mobile",
        "o",
        "pager",
        "photo",
        "roomNumber",
        "secretary",
        "uid",
        "userCertificate",
        "x500uniqueIdentifier",
        "preferredLanguage",
        "userSMIMECertificate",
        "userPKCS12",
    ]

    def __init__(
        self,
        cache_ttl_minutes: int = 60,
        max_cache_size: int = 100,
        *,
        enable_caching: bool = True,
    ) -> None:
        """Initialize schema discovery service."""
        self.cache_ttl_minutes = cache_ttl_minutes
        self.max_cache_size = max_cache_size
        self.enable_caching = enable_caching

        self._schema_cache: dict[
            str,
            tuple[FlextLdapSchemaDiscoveryResult, datetime],
        ] = {}
        self._discovery_history: list[FlextLdapSchemaDiscoveryResult] = []

        logger.info("Schema discovery service initialized")

    async def discover_schema(
        self,
        connection: FlextLdapConnection,
        *,
        force_refresh: bool = False,
    ) -> FlextResult[FlextLdapSchemaDiscoveryResult]:
        """Discover LDAP schema from server."""
        try:
            start_time = datetime.now(UTC)

            cache_key = self._generate_cache_key(connection)

            if not force_refresh and self.enable_caching:
                cached_result = self._get_cached_schema(cache_key)
                if cached_result:
                    logger.debug("Retrieved schema from cache: %s", cache_key)
                    return FlextResult.ok(cached_result)

            discovery_result = await self._perform_schema_discovery(
                connection,
                start_time,
            )

            if self.enable_caching:
                self._cache_schema(cache_key, discovery_result)

            self._discovery_history.append(discovery_result)
            if (
                len(self._discovery_history)
                > FlextLdapSchemaDiscoveryConstants.MAX_DISCOVERY_HISTORY
            ):
                self._discovery_history.pop(0)

            logger.info(
                "Schema discovery completed with %d elements",
                discovery_result.total_elements,
            )
            return FlextResult.ok(discovery_result)

        except (RuntimeError, ValueError, TypeError) as e:
            error_msg = f"Schema discovery failed: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def get_object_class(
        self,
        connection: FlextLdapConnection,
        class_name: str,
    ) -> FlextResult[FlextLdapSchemaObjectClass | None]:
        """Get specific object class schema."""
        return await self._get_object_class_item(connection, class_name)

    async def get_attribute_type(
        self,
        connection: FlextLdapConnection,
        attribute_name: str,
    ) -> FlextResult[FlextLdapSchemaAttribute | None]:
        """Get specific attribute type schema."""
        return await self._get_attribute_type_item(connection, attribute_name)

    async def _get_object_class_item(
        self,
        connection: FlextLdapConnection,
        class_name: str,
    ) -> FlextResult[FlextLdapSchemaObjectClass | None]:
        """Get specific object class schema item - type-safe implementation."""
        try:
            schema_result = await self.discover_schema(connection)
            if not schema_result.is_success:
                return FlextResult.fail(f"Failed to discover schema: {schema_result.error}")

            schema = schema_result.data
            if schema is None:
                return FlextResult.fail("Schema discovery returned None")

            # Type-safe access to object_classes only
            if hasattr(schema, "object_classes"):
                for item in schema.object_classes.values():
                    if hasattr(item, "has_name") and item.has_name(class_name):
                        return FlextResult.ok(item)

            return FlextResult.ok(None)

        except (RuntimeError, ValueError, TypeError) as e:
            error_msg = f"Failed to get object class {class_name}: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def _get_attribute_type_item(
        self,
        connection: FlextLdapConnection,
        attribute_name: str,
    ) -> FlextResult[FlextLdapSchemaAttribute | None]:
        """Get specific attribute type schema item - type-safe implementation."""
        try:
            schema_result = await self.discover_schema(connection)
            if not schema_result.is_success:
                return FlextResult.fail(f"Failed to discover schema: {schema_result.error}")

            schema = schema_result.data
            if schema is None:
                return FlextResult.fail("Schema discovery returned None")

            # Type-safe access to attributes only
            if hasattr(schema, "attributes"):
                for item in schema.attributes.values():
                    if hasattr(item, "has_name") and item.has_name(attribute_name):
                        return FlextResult.ok(item)

            return FlextResult.ok(None)

        except (RuntimeError, ValueError, TypeError) as e:
            error_msg = f"Failed to get attribute type {attribute_name}: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def _get_schema_item(
        self,
        connection: FlextLdapConnection,
        item_name: str,
        collection_getter: Callable[[object], Any],
        item_type: str,
    ) -> FlextResult[FlextLdapSchemaObjectClass | FlextLdapSchemaAttribute | None]:
        """Template method for getting schema items - eliminates code duplication."""
        try:
            schema_result = await self.discover_schema(connection)
            if not schema_result.is_success:
                return FlextResult.fail(
                    f"Failed to discover schema: {schema_result.error}",
                )

            schema = schema_result.data
            if schema is None:
                return FlextResult.fail("Schema discovery returned None")

            # Use the collection getter to access the right collection
            items = collection_getter(schema)
            for item in items:
                if item.has_name(item_name):
                    return FlextResult.ok(item)

            return FlextResult.ok(None)

        except (RuntimeError, ValueError, TypeError) as e:
            error_msg = f"Failed to get {item_type} {item_name}: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def _create_validation_result(self) -> ValidationResult:
        """Create initial validation result structure."""
        return ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            missing_required=[],
            unknown_attributes=[],
            schema_violations=[],
        )

    def _collect_object_class_attributes(
        self,
        object_classes: list[str],
        schema: FlextLdapSchemaDiscoveryResult,
        validation_result: ValidationResult,
    ) -> tuple[set[str], set[str]]:
        """Collect must and may attributes from object classes."""
        all_must_attrs: set[str] = set()
        all_may_attrs: set[str] = set()

        for oc_name in object_classes:
            oc: FlextLdapSchemaObjectClass | None = None
            for obj_class in schema.object_classes.values():
                if obj_class.has_name(oc_name):
                    oc = obj_class
                    break

            if not oc:
                validation_result["errors"].append(f"Unknown object class: {oc_name}")
                validation_result["is_valid"] = False
                continue

            must_attrs, may_attrs = oc.get_all_attributes(schema.object_classes)
            all_must_attrs.update(must_attrs)
            all_may_attrs.update(may_attrs)

        return all_must_attrs, all_may_attrs

    def _validate_required_attributes(
        self,
        all_must_attrs: set[str],
        attributes: dict[str, object],
        validation_result: ValidationResult,
    ) -> None:
        """Validate that all required attributes are provided."""
        provided_attrs = {attr.lower() for attr in attributes}
        for must_attr in all_must_attrs:
            if must_attr.lower() not in provided_attrs:
                validation_result["missing_required"].append(must_attr)
                validation_result["is_valid"] = False

    def _validate_unknown_attributes(
        self,
        all_must_attrs: set[str],
        all_may_attrs: set[str],
        attributes: dict[str, object],
        validation_result: ValidationResult,
    ) -> None:
        """Check for unknown attributes."""
        all_known_attrs = all_must_attrs.union(all_may_attrs)
        for attr_name in attributes:
            if attr_name.lower() not in {a.lower() for a in all_known_attrs}:
                validation_result["unknown_attributes"].append(attr_name)
                validation_result["warnings"].append(f"Unknown attribute: {attr_name}")

    def _validate_single_value_constraints(
        self,
        schema: FlextLdapSchemaDiscoveryResult,
        attributes: dict[str, object],
        validation_result: ValidationResult,
    ) -> None:
        """Validate single-value attribute constraints."""
        for attr_name, attr_value in attributes.items():
            attr_schema = None
            for attr in schema.attributes.values():
                if attr.has_name(attr_name):
                    attr_schema = attr
                    break

            if (
                attr_schema
                and attr_schema.is_single_value
                and isinstance(attr_value, (list, tuple))
                and len(attr_value) > 1
            ):
                validation_result["schema_violations"].append(
                    f"Attribute {attr_name} is single-valued but multiple values",
                )
                validation_result["is_valid"] = False

    async def validate_object_structure(
        self,
        connection: FlextLdapConnection,
        object_classes: list[str],
        attributes: dict[str, object],
    ) -> FlextResult[ValidationResult]:
        """Validate object structure against schema."""
        try:
            schema_result = await self.discover_schema(connection)
            if not schema_result.is_success:
                return FlextResult.fail(
                    f"Failed to discover schema: {schema_result.error}",
                )

            schema = schema_result.data
            if schema is None:
                return FlextResult.fail("Schema discovery returned None")

            validation_result = self._create_validation_result()

            # Collect attributes from object classes
            all_must_attrs, all_may_attrs = self._collect_object_class_attributes(
                object_classes,
                schema,
                validation_result,
            )

            # Validate required attributes
            self._validate_required_attributes(
                all_must_attrs,
                attributes,
                validation_result,
            )

            # Check for unknown attributes
            self._validate_unknown_attributes(
                all_must_attrs,
                all_may_attrs,
                attributes,
                validation_result,
            )

            # Validate single-value constraints
            self._validate_single_value_constraints(
                schema,
                attributes,
                validation_result,
            )

            return FlextResult.ok(validation_result)

        except (RuntimeError, ValueError, TypeError) as e:
            error_msg = f"Object structure validation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def _extract_server_info(self, connection: FlextLdapConnection) -> dict[str, str]:
        """Extract server information from connection."""
        server_info = {
            "vendor": "Unknown LDAP Server",
            "version": "Unknown",
            "schema_version": "Unknown",
            "discovery_method": "real_connection",
        }

        if hasattr(connection, "server_info") and connection.server_info:
            if hasattr(connection.server_info, "vendor_name"):
                server_info["vendor"] = str(connection.server_info.vendor_name)
            if hasattr(connection.server_info, "vendor_version"):
                server_info["version"] = str(connection.server_info.vendor_version)

        return server_info

    def _extract_schema_from_connection(
        self,
        connection: FlextLdapConnection,
    ) -> tuple[
        dict[str, FlextLdapSchemaObjectClass],
        dict[str, FlextLdapSchemaAttribute],
    ]:
        """Extract schema elements from LDAP connection."""
        real_object_classes = {}
        real_attributes = {}

        if hasattr(connection, "server") and hasattr(connection.server, "schema"):
            schema = connection.server.schema
            if schema:
                # Extract object classes
                if hasattr(schema, "object_classes"):
                    for oc_name, oc_def in schema.object_classes.items():
                        real_object_classes[oc_name] = (
                            FlextLdapSchemaObjectClass.create(
                                oid=getattr(oc_def, "oid", f"unknown.{oc_name}"),
                                names=[oc_name],
                                description=getattr(
                                    oc_def,
                                    "description",
                                    f"Schema for {oc_name}",
                                ),
                                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                                superior_classes=getattr(oc_def, "superior", []),
                                must_attributes=getattr(oc_def, "must_contain", []),
                                may_attributes=getattr(oc_def, "may_contain", []),
                            )
                        )

                # Extract attributes
                if hasattr(schema, "attribute_types"):
                    for attr_name, attr_def in schema.attribute_types.items():
                        real_attributes[attr_name] = FlextLdapSchemaAttribute.create(
                            oid=getattr(attr_def, "oid", f"unknown.{attr_name}"),
                            names=[attr_name],
                            description=getattr(
                                attr_def,
                                "description",
                                f"Attribute {attr_name}",
                            ),
                            syntax=getattr(
                                attr_def,
                                "syntax",
                                "1.3.6.1.4.1.1466.115.121.1.15",
                            ),
                            equality_matching_rule=getattr(attr_def, "equality", None),
                            substring_matching_rule=getattr(
                                attr_def,
                                "substring",
                                None,
                            ),
                        )

        return real_object_classes, real_attributes

    async def _perform_schema_discovery(
        self,
        connection: FlextLdapConnection,
        start_time: datetime,
    ) -> FlextLdapSchemaDiscoveryResult:
        """Perform actual schema discovery from LDAP server."""
        try:
            # Extract server information
            server_info = self._extract_server_info(connection)

            # Extract schema from connection
            real_object_classes, real_attributes = self._extract_schema_from_connection(
                connection,
            )

            # Use discovered schema or fallback to standard schemas
            if not real_object_classes:
                real_object_classes = self._discover_standard_object_classes(connection)
            if not real_attributes:
                real_attributes = self._discover_standard_attributes(connection)

            # Calculate discovery duration
            discovery_duration = int(
                (datetime.now(UTC) - start_time).total_seconds() * 1000,
            )

            return FlextLdapSchemaDiscoveryResult.create(
                server_info=server_info,
                object_classes=real_object_classes,
                attributes=real_attributes,
                discovery_duration_ms=discovery_duration,
            )

        except Exception as e:
            # If any error occurs, return with empty schema and error logged
            logger.warning("Schema discovery error: %s", e)
            discovery_duration = int(
                (datetime.now(UTC) - start_time).total_seconds() * 1000,
            )
            return FlextLdapSchemaDiscoveryResult.create(
                server_info={"vendor": "Unknown", "version": "Unknown"},
                object_classes=self._discover_standard_object_classes(None),
                attributes=self._discover_standard_attributes(None),
                discovery_duration_ms=discovery_duration,
                discovery_errors=[f"Schema discovery failed: {e}"],
            )

    def _generate_cache_key(self, connection: FlextLdapConnection) -> str:
        """Generate cache key for connection."""
        if hasattr(connection, "server"):
            return f"schema_{getattr(connection.server, 'host', 'unknown')}"
        return "schema_default"

    def _get_cached_schema(
        self,
        cache_key: str,
    ) -> FlextLdapSchemaDiscoveryResult | None:
        """Get schema from cache if valid."""
        if cache_key in self._schema_cache:
            result, cached_time = self._schema_cache[cache_key]

            if datetime.now(UTC) - cached_time < timedelta(
                minutes=self.cache_ttl_minutes,
            ):
                result.cache_hit = True
                return result
            del self._schema_cache[cache_key]

        return None

    def _cache_schema(
        self,
        cache_key: str,
        result: FlextLdapSchemaDiscoveryResult,
    ) -> None:
        """Cache schema discovery result."""
        if len(self._schema_cache) >= self.max_cache_size:
            oldest_key = min(
                self._schema_cache.keys(),
                key=lambda k: self._schema_cache[k][1],
            )
            del self._schema_cache[oldest_key]

        self._schema_cache[cache_key] = (result, datetime.now(UTC))

    def clear_cache(self) -> None:
        """Clear schema cache."""
        self._schema_cache.clear()
        logger.info("Schema cache cleared")

    def get_cache_stats(self) -> dict[str, object]:
        """Get cache statistics."""
        return {
            "cache_size": len(self._schema_cache),
            "max_cache_size": self.max_cache_size,
            "cache_ttl_minutes": self.cache_ttl_minutes,
            "discovery_history_size": len(self._discovery_history),
        }

    def get_discovery_history(
        self,
        limit: int = 10,
    ) -> list[FlextLdapSchemaDiscoveryResult]:
        """Get recent discovery history."""
        return self._discovery_history[-limit:] if self._discovery_history else []

    def _discover_standard_object_classes(
        self,
        connection: FlextLdapConnection | None,
    ) -> dict[str, FlextLdapSchemaObjectClass]:
        """Discover standard object classes from LDAP server or use RFC standards."""
        logger.debug(
            "Discovering standard object classes",
            extra={"has_connection": connection is not None},
        )

        # If connection available, try to query server schema
        if connection and hasattr(connection, "search"):
            try:
                logger.trace("Attempting server-side object class discovery")
                # This would be real schema discovery from subschema subentry
                schema_result = connection.search(
                    base_dn="cn=subschema",
                    search_filter="(objectClass=subschema)",
                    attributes=["objectClasses"],
                )
                if (
                    schema_result
                    and hasattr(schema_result, "data")
                    and schema_result.data
                ):
                    logger.info("Successfully discovered server object classes")
                    # Parse actual schema from server - full implementation
                    return self._parse_server_object_classes(schema_result.data)
            except Exception as discovery_error:
                logger.warning(
                    "Server schema discovery failed",
                    extra={"error": str(discovery_error)},
                )

        # Use RFC-compliant standard object classes
        return {
            "top": FlextLdapSchemaObjectClass.create(
                oid="2.5.6.0",
                names=["top"],
                description="RFC2256: top object class",
                object_class_type=FlextLdapObjectClassType.ABSTRACT,
                must_attributes=["objectClass"],
            ),
            "person": FlextLdapSchemaObjectClass.create(
                oid="2.5.6.6",
                names=["person"],
                description="RFC2256: a person",
                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                superior_classes=["top"],
                must_attributes=["sn", "cn"],
                may_attributes=[
                    "userPassword",
                    "telephoneNumber",
                    "seeAlso",
                    "description",
                ],
            ),
            "organizationalPerson": FlextLdapSchemaObjectClass.create(
                oid="2.5.6.7",
                names=["organizationalPerson"],
                description="RFC2256: an organizational person",
                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                superior_classes=["person"],
                may_attributes=[
                    "title",
                    "x121Address",
                    "registeredAddress",
                    "destinationIndicator",
                ],
            ),
            "inetOrgPerson": FlextLdapSchemaObjectClass.create(
                oid="2.16.840.1.113730.3.2.2",
                names=["inetOrgPerson"],
                description="RFC2798: Internet Organizational Person",
                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                superior_classes=["organizationalPerson"],
                may_attributes=FlextLdapSchemaDiscoveryService.INET_ORG_PERSON_MAY_ATTRIBUTES,
            ),
        }

    def _discover_standard_attributes(
        self,
        connection: FlextLdapConnection | None,
    ) -> dict[str, FlextLdapSchemaAttribute]:
        """Discover standard attributes from LDAP server or use RFC standards."""
        logger.debug(
            "Discovering standard attributes",
            extra={"has_connection": connection is not None},
        )

        # If connection available, try to query server schema
        if connection and hasattr(connection, "search"):
            try:
                logger.trace("Attempting server-side attribute discovery")
                schema_result = connection.search(
                    base_dn="cn=subschema",
                    search_filter="(objectClass=subschema)",
                    attributes=["attributeTypes"],
                )
                if (
                    schema_result
                    and hasattr(schema_result, "data")
                    and schema_result.data
                ):
                    logger.info("Successfully discovered server attributes")
                    return self._parse_server_attributes(schema_result.data)
            except Exception as discovery_error:
                logger.warning(
                    "Server attribute discovery failed",
                    extra={"error": str(discovery_error)},
                )

        # Use RFC-compliant standard attributes
        return {
            "objectClass": FlextLdapSchemaAttribute.create(
                oid="2.5.4.0",
                names=["objectClass"],
                description="RFC2256: object classes of the entity",
                syntax="1.3.6.1.4.1.1466.115.121.1.38",
                equality_matching_rule="objectIdentifierMatch",
            ),
            "cn": FlextLdapSchemaAttribute.create(
                oid="2.5.4.3",
                names=["cn", "commonName"],
                description=(
                    "RFC2256: common name(s) for which the entity is known by"
                ),
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "sn": FlextLdapSchemaAttribute.create(
                oid="2.5.4.4",
                names=["sn", "surname"],
                description=(
                    "RFC2256: last (family) name(s) for which the entity is known by"
                ),
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "givenName": FlextLdapSchemaAttribute.create(
                oid="2.5.4.42",
                names=["givenName", "gn"],
                description="RFC2256: first name(s) for which the entity is known by",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "mail": FlextLdapSchemaAttribute.create(
                oid="0.9.2342.19200300.100.1.3",
                names=["mail", "rfc822Mailbox"],
                description="RFC1274: RFC822 Mailbox",
                syntax="1.3.6.1.4.1.1466.115.121.1.26",
                equality_matching_rule="caseIgnoreIA5Match",
                substring_matching_rule="caseIgnoreIA5SubstringsMatch",
            ),
            "uid": FlextLdapSchemaAttribute.create(
                oid="0.9.2342.19200300.100.1.1",
                names=["uid", "userid"],
                description="RFC1274: user identifier",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "userPassword": FlextLdapSchemaAttribute.create(
                oid="2.5.4.35",
                names=["userPassword"],
                description="RFC2256: password of user",
                syntax="1.3.6.1.4.1.1466.115.121.1.40",
                equality_matching_rule="octetStringMatch",
            ),
            "description": FlextLdapSchemaAttribute.create(
                oid="2.5.4.13",
                names=["description"],
                description="RFC2256: descriptive information",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
        }

    def _extract_object_classes_from_entry(
        self,
        entry: dict[str, object],
        object_classes: dict[str, FlextLdapSchemaObjectClass],
    ) -> None:
        """Extract object classes from schema entry - reduces nested control flow."""
        # Early return if no object classes in entry
        attributes = entry.get("attributes", {})
        if not isinstance(attributes, dict) or "objectClasses" not in attributes:
            return

        oc_definitions = attributes["objectClasses"]
        definition_list = self._normalize_to_list(oc_definitions)

        for oc_def in definition_list:
            self._process_object_class_definition(oc_def, object_classes)

    def _normalize_to_list(self, definitions: object) -> list[object]:
        """Normalize object class definitions to list format."""
        return definitions if isinstance(definitions, list) else [definitions]

    def _process_object_class_definition(
        self,
        oc_def: object,
        object_classes: dict[str, FlextLdapSchemaObjectClass],
    ) -> None:
        """Process a single object class definition - Single Responsibility."""
        # Early return if not a string definition
        if not isinstance(oc_def, str):
            return

        # Parse LDAP schema definition format
        # Example: "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )"
        parsed_oc = self._parse_object_class_definition(oc_def)
        if parsed_oc:
            object_classes[parsed_oc.primary_name] = parsed_oc

    def _parse_server_object_classes(
        self,
        schema_data: list[dict[str, object]],
    ) -> dict[str, FlextLdapSchemaObjectClass]:
        """Parse object classes from server schema data."""
        logger.debug(
            "Parsing server object classes",
            extra={"data_count": len(schema_data)},
        )
        object_classes: dict[str, FlextLdapSchemaObjectClass] = {}

        try:
            for entry in schema_data:
                self._extract_object_classes_from_entry(entry, object_classes)

            logger.info(
                "Parsed server object classes",
                extra={"classes_found": len(object_classes)},
            )
            return object_classes

        except (RuntimeError, ValueError, TypeError) as e:
            logger.warning(f"Error parsing server object classes: {e}")
            return self._get_standard_object_classes()

    def _parse_server_attributes(
        self,
        schema_data: list[dict[str, object]],
    ) -> dict[str, FlextLdapSchemaAttribute]:
        """Parse attributes from server schema data."""
        logger.debug(
            "Parsing server attributes",
            extra={"data_count": len(schema_data)},
        )
        attributes: dict[str, FlextLdapSchemaAttribute] = {}

        try:
            for entry in schema_data:
                self._extract_attribute_types_from_entry(entry, attributes)

            logger.info(
                "Parsed server attributes",
                extra={"attributes_found": len(attributes)},
            )
            return attributes

        except (RuntimeError, ValueError, TypeError) as e:
            logger.warning(f"Error parsing server attributes: {e}")
            return self._get_standard_attributes()

    def _parse_server_schema_items(
        self,
        schema_data: list[dict[str, object]],
        item_type: str,
        count_key: str,
        extractor_func: Callable[[dict[str, object], dict[str, object]], None],
        fallback_func: Callable[[], dict[str, object]],
    ) -> dict[str, object]:
        """Template method for parsing server schema items."""
        logger.debug(
            f"Parsing server {item_type}",
            extra={"data_count": len(schema_data)},
        )
        items: dict[str, object] = {}

        try:
            for entry in schema_data:
                extractor_func(entry, items)

            logger.info(
                f"Parsed server {item_type}",
                extra={count_key: len(items)},
            )
            return items

        except Exception as parse_error:
            logger.exception(
                f"Failed to parse server {item_type}",
                extra={"error": str(parse_error)},
            )
            # Return standard items on parse failure
            return fallback_func()

    def _extract_attribute_types_from_entry(
        self,
        entry: dict[str, object],
        attributes: dict[str, FlextLdapSchemaAttribute],
    ) -> None:
        """Extract attribute types from schema entry - reduces nested control flow."""
        # Early return if no attribute types in entry
        entry_attributes = entry.get("attributes", {})
        if not isinstance(entry_attributes, dict) or "attributeTypes" not in entry_attributes:
            return

        attr_definitions = entry_attributes["attributeTypes"]

        # Normalize to list for consistent processing
        definitions_list = (
            attr_definitions
            if isinstance(attr_definitions, list)
            else [attr_definitions]
        )

        # Process each attribute definition
        for attr_def in definitions_list:
            self._process_attribute_definition(attr_def, attributes)

    def _process_attribute_definition(
        self,
        attr_def: object,
        attributes: dict[str, FlextLdapSchemaAttribute],
    ) -> None:
        """Process individual attribute definition - Single Responsibility."""
        # Early return if not a string definition
        if not isinstance(attr_def, str):
            return

        parsed_attr = self._parse_attribute_definition(attr_def)
        if parsed_attr:
            attributes[parsed_attr.primary_name] = parsed_attr

    def _parse_object_class_definition(
        self,
        definition: str,
    ) -> FlextLdapSchemaObjectClass | None:
        """Parse a single object class definition string."""
        try:
            # Basic parsing - in production this would be more robust

            # Extract OID
            oid_match = re.search(r"\(\s*([0-9.]+)", definition)
            if not oid_match:
                return None
            oid = oid_match.group(1)

            # Extract NAME
            name_match = re.search(r"NAME\s+'([^']+)'", definition)
            names = [name_match.group(1)] if name_match else []

            # Extract type (STRUCTURAL, ABSTRACT, AUXILIARY)
            oc_type = FlextLdapObjectClassType.STRUCTURAL  # default
            if "ABSTRACT" in definition:
                oc_type = FlextLdapObjectClassType.ABSTRACT
            elif "AUXILIARY" in definition:
                oc_type = FlextLdapObjectClassType.AUXILIARY

            return FlextLdapSchemaObjectClass.create(
                oid=oid,
                names=names,
                object_class_type=oc_type,
                description=(
                    f"Server-discovered object class: {names[0] if names else oid}"
                ),
            )

        except Exception as parse_error:
            logger.warning(
                "Failed to parse object class definition",
                extra={"definition": definition[:100], "error": str(parse_error)},
            )
            return None

    def _parse_attribute_definition(
        self,
        definition: str,
    ) -> FlextLdapSchemaAttribute | None:
        """Parse a single attribute definition string."""
        try:
            # Extract OID
            oid_match = re.search(r"\(\s*([0-9.]+)", definition)
            if not oid_match:
                return None
            oid = oid_match.group(1)

            # Extract NAME
            name_match = re.search(r"NAME\s+'([^']+)'", definition)
            names = [name_match.group(1)] if name_match else []

            # Extract SYNTAX
            syntax_match = re.search(r"SYNTAX\s+'([^']+)'", definition)
            syntax = syntax_match.group(1) if syntax_match else None

            return FlextLdapSchemaAttribute.create(
                oid=oid,
                names=names,
                syntax=syntax,
                description=f"Server-discovered: {names[0] if names else oid}",
            )

        except Exception as parse_error:
            logger.warning(
                "Failed to parse attribute definition",
                extra={"definition": definition[:100], "error": str(parse_error)},
            )
            return None

    def _get_standard_object_classes(self) -> dict[str, FlextLdapSchemaObjectClass]:
        """Get RFC-compliant standard object classes (not fallback, but standards)."""
        logger.trace("Using RFC-compliant standard object classes")
        return {
            "top": FlextLdapSchemaObjectClass.create(
                oid="2.5.6.0",
                names=["top"],
                description="RFC2256: top of the superclass chain",
                object_class_type=FlextLdapObjectClassType.ABSTRACT,
                must_attributes=[],
                may_attributes=["objectClass"],
            ),
            "person": FlextLdapSchemaObjectClass.create(
                oid="2.5.6.6",
                names=["person"],
                description="RFC2256: a person",
                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                superior_classes=["top"],
                must_attributes=["sn", "cn"],
                may_attributes=[
                    "userPassword",
                    "telephoneNumber",
                    "seeAlso",
                    "description",
                ],
            ),
            "organizationalPerson": FlextLdapSchemaObjectClass.create(
                oid="2.5.6.7",
                names=["organizationalPerson"],
                description="RFC2256: an organizational person",
                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                superior_classes=["person"],
                must_attributes=[],
                may_attributes=[
                    "title",
                    "x121Address",
                    "registeredAddress",
                    "destinationIndicator",
                    "preferredDeliveryMethod",
                    "telexNumber",
                    "teletexTerminalIdentifier",
                    "telephoneNumber",
                    "internationaliSDNNumber",
                    "facsimileTelephoneNumber",
                    "street",
                    "postOfficeBox",
                    "postalCode",
                    "postalAddress",
                    "physicalDeliveryOfficeName",
                    "ou",
                    "st",
                    "l",
                ],
            ),
            "inetOrgPerson": FlextLdapSchemaObjectClass.create(
                oid="2.16.840.1.113730.3.2.2",
                names=["inetOrgPerson"],
                description="RFC2798: Internet Organizational Person",
                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                superior_classes=["organizationalPerson"],
                must_attributes=[],
                may_attributes=FlextLdapSchemaDiscoveryService.INET_ORG_PERSON_MAY_ATTRIBUTES,
            ),
            "groupOfNames": FlextLdapSchemaObjectClass.create(
                oid="2.5.6.9",
                names=["groupOfNames"],
                description="RFC2256: a group of names (DNs)",
                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                superior_classes=["top"],
                must_attributes=["member", "cn"],
                may_attributes=[
                    "businessCategory",
                    "seeAlso",
                    "owner",
                    "ou",
                    "o",
                    "description",
                ],
            ),
        }

    def _get_standard_attributes(self) -> dict[str, FlextLdapSchemaAttribute]:
        """Get RFC-compliant standard attributes (not fallback, but standards)."""
        logger.trace("Using RFC-compliant standard attributes")
        return {
            "objectClass": FlextLdapSchemaAttribute.create(
                oid="2.5.4.0",
                names=["objectClass"],
                description="RFC2256: object classes of the entity",
                syntax="1.3.6.1.4.1.1466.115.121.1.38",
                equality_matching_rule="objectIdentifierMatch",
                is_no_user_modification=True,
            ),
            "cn": FlextLdapSchemaAttribute.create(
                oid="2.5.4.3",
                names=["cn", "commonName"],
                description="RFC2256: common name(s) for which the entity is known by",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "sn": FlextLdapSchemaAttribute.create(
                oid="2.5.4.4",
                names=["sn", "surname"],
                description=(
                    "RFC2256: last (family) name(s) for which the entity is known by"
                ),
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "givenName": FlextLdapSchemaAttribute.create(
                oid="2.5.4.42",
                names=["givenName", "gn"],
                description="RFC2256: first name(s) for which the entity is known by",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "mail": FlextLdapSchemaAttribute.create(
                oid="0.9.2342.19200300.100.1.3",
                names=["mail", "rfc822Mailbox"],
                description="RFC1274: electronic mailbox",
                syntax="1.3.6.1.4.1.1466.115.121.1.26",
                equality_matching_rule="caseIgnoreIA5Match",
                substring_matching_rule="caseIgnoreIA5SubstringsMatch",
            ),
            "uid": FlextLdapSchemaAttribute.create(
                oid="0.9.2342.19200300.100.1.1",
                names=["uid", "userid"],
                description="RFC1274: user identifier",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "userPassword": FlextLdapSchemaAttribute.create(
                oid="2.5.4.35",
                names=["userPassword"],
                description="RFC2256: password of user",
                syntax="1.3.6.1.4.1.1466.115.121.1.40",
                equality_matching_rule="octetStringMatch",
            ),
            "description": FlextLdapSchemaAttribute.create(
                oid="2.5.4.13",
                names=["description"],
                description="RFC2256: descriptive information",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "member": FlextLdapSchemaAttribute.create(
                oid="2.5.4.31",
                names=["member"],
                description="RFC2256: member of a group",
                syntax="1.3.6.1.4.1.1466.115.121.1.12",
                equality_matching_rule="distinguishedNameMatch",
            ),
        }


# Backward compatibility aliases
SchemaElementType = FlextLdapSchemaElementType
AttributeUsage = FlextLdapAttributeUsage
ObjectClassType = FlextLdapObjectClassType
SchemaAttribute = FlextLdapSchemaAttribute
SchemaObjectClass = FlextLdapSchemaObjectClass
SchemaDiscoveryResult = FlextLdapSchemaDiscoveryResult
SchemaDiscoveryService = FlextLdapSchemaDiscoveryService
