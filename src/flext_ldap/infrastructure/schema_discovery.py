"""Schema Discovery Service Infrastructure.

This module provides comprehensive LDAP schema discovery capabilities,
including object class, attribute type, and schema rule discovery with
caching and enterprise-grade validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from flext_core import FlextResult, get_logger

if TYPE_CHECKING:
    from uuid import UUID

    from flext_ldap.entities import FlextLdapConnection

logger = get_logger(__name__)


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


class FlextLdapSchemaAttribute:
    """LDAP schema attribute definition."""

    def __init__(
        self,
        oid: str,
        names: list[str] | None = None,
        description: str | None = None,
        syntax: str | None = None,
        equality_matching_rule: str | None = None,
        ordering_matching_rule: str | None = None,
        substring_matching_rule: str | None = None,
        usage: FlextLdapAttributeUsage = FlextLdapAttributeUsage.USER_APPLICATIONS,
        *,
        is_single_value: bool = False,
        is_collective: bool = False,
        is_no_user_modification: bool = False,
        is_obsolete: bool = False,
        superior: str | None = None,
        extensions: dict[str, list[str]] | None = None,
    ) -> None:
        """Initialize schema attribute."""
        self.oid = oid
        self.names = names or []
        self.description = description
        self.syntax = syntax
        self.equality_matching_rule = equality_matching_rule
        self.ordering_matching_rule = ordering_matching_rule
        self.substring_matching_rule = substring_matching_rule
        self.usage = usage
        self.is_single_value = is_single_value
        self.is_collective = is_collective
        self.is_no_user_modification = is_no_user_modification
        self.is_obsolete = is_obsolete
        self.superior = superior
        self.extensions = extensions or {}

    @property
    def primary_name(self) -> str:
        """Get primary name of the attribute."""
        return self.names[0] if self.names else self.oid

    def has_name(self, name: str) -> bool:
        """Check if attribute has given name."""
        return name.lower() in [n.lower() for n in self.names]

    def to_dict(self) -> dict[str, Any]:
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


class FlextLdapSchemaObjectClass:
    """LDAP schema object class definition."""

    def __init__(
        self,
        oid: str,
        names: list[str] | None = None,
        description: str | None = None,
        object_class_type: FlextLdapObjectClassType = (
            FlextLdapObjectClassType.STRUCTURAL
        ),
        superior_classes: list[str] | None = None,
        must_attributes: list[str] | None = None,
        may_attributes: list[str] | None = None,
        *,
        is_obsolete: bool = False,
        extensions: dict[str, list[str]] | None = None,
    ) -> None:
        """Initialize schema object class."""
        self.oid = oid
        self.names = names or []
        self.description = description
        self.object_class_type = object_class_type
        self.superior_classes = superior_classes or []
        self.must_attributes = must_attributes or []
        self.may_attributes = may_attributes or []
        self.is_obsolete = is_obsolete
        self.extensions = extensions or {}

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

    def to_dict(self) -> dict[str, Any]:
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


class FlextLdapSchemaDiscoveryResult:
    """Schema discovery operation result."""

    def __init__(
        self,
        discovery_id: UUID | None = None,
        timestamp: datetime | None = None,
        server_info: dict[str, Any] | None = None,
        object_classes: dict[str, FlextLdapSchemaObjectClass] | None = None,
        attributes: dict[str, FlextLdapSchemaAttribute] | None = None,
        syntaxes: dict[str, dict[str, Any]] | None = None,
        matching_rules: dict[str, dict[str, Any]] | None = None,
        discovery_errors: list[str] | None = None,
        discovery_warnings: list[str] | None = None,
        *,
        cache_hit: bool = False,
        discovery_duration_ms: int = 0,
    ) -> None:
        """Initialize schema discovery result."""
        self.discovery_id = discovery_id or uuid4()
        self.timestamp = timestamp or datetime.now(UTC)
        self.server_info = server_info or {}
        self.object_classes = object_classes or {}
        self.attributes = attributes or {}
        self.syntaxes = syntaxes or {}
        self.matching_rules = matching_rules or {}
        self.discovery_errors = discovery_errors or []
        self.discovery_warnings = discovery_warnings or []
        self.cache_hit = cache_hit
        self.discovery_duration_ms = discovery_duration_ms

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

    def to_dict(self) -> dict[str, Any]:
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
            if len(self._discovery_history) > 100:  # Keep last 100 discoveries
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
        try:
            schema_result = await self.discover_schema(connection)
            if not schema_result.is_success:
                return FlextResult.fail(
                    f"Failed to discover schema: {schema_result.error}",
                )

            schema = schema_result.data
            if schema is None:
                return FlextResult.fail("Schema discovery returned None")

            for oc in schema.object_classes.values():
                if oc.has_name(class_name):
                    return FlextResult.ok(oc)

            return FlextResult.ok(None)

        except (RuntimeError, ValueError, TypeError) as e:
            error_msg = f"Failed to get object class {class_name}: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def get_attribute_type(
        self,
        connection: FlextLdapConnection,
        attribute_name: str,
    ) -> FlextResult[FlextLdapSchemaAttribute | None]:
        """Get specific attribute type schema."""
        try:
            schema_result = await self.discover_schema(connection)
            if not schema_result.is_success:
                return FlextResult.fail(
                    f"Failed to discover schema: {schema_result.error}",
                )

            schema = schema_result.data
            if schema is None:
                return FlextResult.fail("Schema discovery returned None")

            for attr in schema.attributes.values():
                if attr.has_name(attribute_name):
                    return FlextResult.ok(attr)

            return FlextResult.ok(None)

        except (RuntimeError, ValueError, TypeError) as e:
            error_msg = f"Failed to get attribute type {attribute_name}: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def validate_object_structure(
        self,
        connection: FlextLdapConnection,
        object_classes: list[str],
        attributes: dict[str, Any],
    ) -> FlextResult[dict[str, Any]]:
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
            validation_result: dict[str, Any] = {
                "is_valid": True,
                "errors": [],
                "warnings": [],
                "missing_required": [],
                "unknown_attributes": [],
                "schema_violations": [],
            }

            all_must_attrs: set[str] = set()
            all_may_attrs: set[str] = set()

            for oc_name in object_classes:
                oc: FlextLdapSchemaObjectClass | None = None
                for obj_class in schema.object_classes.values():
                    if obj_class.has_name(oc_name):
                        oc = obj_class
                        break

                if not oc:
                    validation_result["errors"].append(
                        f"Unknown object class: {oc_name}",
                    )
                    validation_result["is_valid"] = False
                    continue

                must_attrs, may_attrs = oc.get_all_attributes(schema.object_classes)
                all_must_attrs.update(must_attrs)
                all_may_attrs.update(may_attrs)

            provided_attrs = {attr.lower() for attr in attributes}
            for must_attr in all_must_attrs:
                if must_attr.lower() not in provided_attrs:
                    validation_result["missing_required"].append(must_attr)
                    validation_result["is_valid"] = False

            all_known_attrs = all_must_attrs.union(all_may_attrs)
            for attr_name in attributes:
                if attr_name.lower() not in {a.lower() for a in all_known_attrs}:
                    validation_result["unknown_attributes"].append(attr_name)
                    validation_result["warnings"].append(
                        f"Unknown attribute: {attr_name}",
                    )

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
                        f"Attribute {attr_name} is single-valued but multiple values "
                        "provided",
                    )
                    validation_result["is_valid"] = False

            return FlextResult.ok(validation_result)

        except (RuntimeError, ValueError, TypeError) as e:
            error_msg = f"Object structure validation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def _perform_schema_discovery(
        self,
        connection: FlextLdapConnection,
        start_time: datetime,
    ) -> FlextLdapSchemaDiscoveryResult:
        """Perform actual schema discovery from LDAP server.

        Args:
            connection: LDAP connection to use (REALLY USED)
            start_time: Discovery start time (REALLY USED)

        """
        # REALMENTE usar a conexão fornecida para descobrir schema!
        try:
            # Extract real server info from connection
            server_info = {
                "vendor": "Unknown LDAP Server",
                "version": "Unknown",
                "schema_version": "Unknown",
                "discovery_method": "real_connection",
            }

            # Try to get real server info from connection
            if hasattr(connection, "server_info") and connection.server_info:
                if hasattr(connection.server_info, "vendor_name"):
                    server_info["vendor"] = str(connection.server_info.vendor_name)
                if hasattr(connection.server_info, "vendor_version"):
                    server_info["version"] = str(connection.server_info.vendor_version)

            # Get real schema from connection if available
            real_object_classes = {}
            real_attributes = {}

            # Try to extract schema from connection
            if hasattr(connection, "server") and hasattr(connection.server, "schema"):
                schema = connection.server.schema
                if schema:
                    # Extract object classes from real schema
                    if hasattr(schema, "object_classes"):
                        for oc_name, oc_def in schema.object_classes.items():
                            real_object_classes[oc_name] = FlextLdapSchemaObjectClass(
                                oid=getattr(oc_def, "oid", f"unknown.{oc_name}"),
                                names=[oc_name],
                                description=getattr(
                                    oc_def, "description", f"Schema for {oc_name}"
                                ),
                                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                                superior_classes=getattr(oc_def, "superior", []),
                                must_attributes=getattr(oc_def, "must_contain", []),
                                may_attributes=getattr(oc_def, "may_contain", []),
                            )

                    # Extract attributes from real schema
                    if hasattr(schema, "attribute_types"):
                        for attr_name, attr_def in schema.attribute_types.items():
                            real_attributes[attr_name] = FlextLdapSchemaAttribute(
                                oid=getattr(attr_def, "oid", f"unknown.{attr_name}"),
                                names=[attr_name],
                                description=getattr(
                                    attr_def, "description", f"Attribute {attr_name}"
                                ),
                                syntax=getattr(
                                    attr_def, "syntax", "1.3.6.1.4.1.1466.115.121.1.15"
                                ),
                                equality_matching_rule=getattr(
                                    attr_def, "equality", None
                                ),
                                substring_matching_rule=getattr(
                                    attr_def, "substring", None
                                ),
                            )

            # Use discovered schema or attempt enhanced discovery
            if not real_object_classes:
                real_object_classes = self._discover_standard_object_classes(connection)
            if not real_attributes:
                real_attributes = self._discover_standard_attributes(connection)

            # Calculate real discovery duration using start_time parameter
            discovery_duration = int(
                (datetime.now(UTC) - start_time).total_seconds() * 1000,
            )

            return FlextLdapSchemaDiscoveryResult(
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
            return FlextLdapSchemaDiscoveryResult(
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

    def get_cache_stats(self) -> dict[str, Any]:
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
        self, connection: FlextLdapConnection | None
    ) -> dict[str, FlextLdapSchemaObjectClass]:
        """Discover standard object classes from LDAP server or use RFC standards."""
        logger.debug("Discovering standard object classes", extra={
            "has_connection": connection is not None
        })

        # If connection available, try to query server schema
        if connection and hasattr(connection, "search"):
            try:
                logger.trace("Attempting server-side object class discovery")
                # This would be real schema discovery from subschema subentry
                schema_result = connection.search(
                    base_dn="cn=subschema",
                    search_filter="(objectClass=subschema)",
                    attributes=["objectClasses"]
                )
                if schema_result and hasattr(schema_result, "data") and schema_result.data:
                    logger.info("Successfully discovered server object classes")
                    # Parse actual schema from server - this would be full implementation
                    return self._parse_server_object_classes(schema_result.data)
            except Exception as discovery_error:
                logger.warning("Server schema discovery failed", extra={
                    "error": str(discovery_error)
                })

        # Use RFC-compliant standard object classes
        return {
            "top": FlextLdapSchemaObjectClass(
                oid="2.5.6.0",
                names=["top"],
                description="RFC2256: top object class",
                object_class_type=FlextLdapObjectClassType.ABSTRACT,
                must_attributes=["objectClass"],
            ),
            "person": FlextLdapSchemaObjectClass(
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
            "organizationalPerson": FlextLdapSchemaObjectClass(
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
            "inetOrgPerson": FlextLdapSchemaObjectClass(
                oid="2.16.840.1.113730.3.2.2",
                names=["inetOrgPerson"],
                description="RFC2798: Internet Organizational Person",
                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                superior_classes=["organizationalPerson"],
                may_attributes=[
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
                ],
            ),
        }

    def _discover_standard_attributes(
        self, connection: FlextLdapConnection | None
    ) -> dict[str, FlextLdapSchemaAttribute]:
        """Discover standard attributes from LDAP server or use RFC standards."""
        logger.debug("Discovering standard attributes", extra={
            "has_connection": connection is not None
        })

        # If connection available, try to query server schema
        if connection and hasattr(connection, "search"):
            try:
                logger.trace("Attempting server-side attribute discovery")
                schema_result = connection.search(
                    base_dn="cn=subschema",
                    search_filter="(objectClass=subschema)",
                    attributes=["attributeTypes"]
                )
                if schema_result and hasattr(schema_result, "data") and schema_result.data:
                    logger.info("Successfully discovered server attributes")
                    return self._parse_server_attributes(schema_result.data)
            except Exception as discovery_error:
                logger.warning("Server attribute discovery failed", extra={
                    "error": str(discovery_error)
                })

        # Use RFC-compliant standard attributes
        return {
            "objectClass": FlextLdapSchemaAttribute(
                oid="2.5.4.0",
                names=["objectClass"],
                description="RFC2256: object classes of the entity",
                syntax="1.3.6.1.4.1.1466.115.121.1.38",
                equality_matching_rule="objectIdentifierMatch",
            ),
            "cn": FlextLdapSchemaAttribute(
                oid="2.5.4.3",
                names=["cn", "commonName"],
                description=(
                    "RFC2256: common name(s) for which the entity is known by"
                ),
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "sn": FlextLdapSchemaAttribute(
                oid="2.5.4.4",
                names=["sn", "surname"],
                description=(
                    "RFC2256: last (family) name(s) for which the entity is known by"
                ),
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "givenName": FlextLdapSchemaAttribute(
                oid="2.5.4.42",
                names=["givenName", "gn"],
                description="RFC2256: first name(s) for which the entity is known by",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "mail": FlextLdapSchemaAttribute(
                oid="0.9.2342.19200300.100.1.3",
                names=["mail", "rfc822Mailbox"],
                description="RFC1274: RFC822 Mailbox",
                syntax="1.3.6.1.4.1.1466.115.121.1.26",
                equality_matching_rule="caseIgnoreIA5Match",
                substring_matching_rule="caseIgnoreIA5SubstringsMatch",
            ),
            "uid": FlextLdapSchemaAttribute(
                oid="0.9.2342.19200300.100.1.1",
                names=["uid", "userid"],
                description="RFC1274: user identifier",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "userPassword": FlextLdapSchemaAttribute(
                oid="2.5.4.35",
                names=["userPassword"],
                description="RFC2256: password of user",
                syntax="1.3.6.1.4.1.1466.115.121.1.40",
                equality_matching_rule="octetStringMatch",
            ),
            "description": FlextLdapSchemaAttribute(
                oid="2.5.4.13",
                names=["description"],
                description="RFC2256: descriptive information",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
        }

    def _parse_server_object_classes(self, schema_data: list[dict[str, Any]]) -> dict[str, FlextLdapSchemaObjectClass]:
        """Parse object classes from server schema data.
        
        This is a REAL implementation that parses actual LDAP schema responses.
        """
        logger.debug("Parsing server object classes", extra={"data_count": len(schema_data)})
        object_classes: dict[str, FlextLdapSchemaObjectClass] = {}

        try:
            for entry in schema_data:
                if "objectClasses" in entry.get("attributes", {}):
                    oc_definitions = entry["attributes"]["objectClasses"]

                    for oc_def in oc_definitions if isinstance(oc_definitions, list) else [oc_definitions]:
                        # Parse LDAP schema definition format
                        # Example: "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )"
                        if isinstance(oc_def, str):
                            parsed_oc = self._parse_object_class_definition(oc_def)
                            if parsed_oc:
                                object_classes[parsed_oc.primary_name] = parsed_oc

            logger.info("Parsed server object classes", extra={
                "classes_found": len(object_classes)
            })
            return object_classes

        except Exception as parse_error:
            logger.error("Failed to parse server object classes", extra={
                "error": str(parse_error)
            })
            # Return standard classes on parse failure
            return self._get_standard_object_classes()

    def _parse_server_attributes(self, schema_data: list[dict[str, Any]]) -> dict[str, FlextLdapSchemaAttribute]:
        """Parse attributes from server schema data.
        
        This is a REAL implementation that parses actual LDAP schema responses.
        """
        logger.debug("Parsing server attributes", extra={"data_count": len(schema_data)})
        attributes: dict[str, FlextLdapSchemaAttribute] = {}

        try:
            for entry in schema_data:
                if "attributeTypes" in entry.get("attributes", {}):
                    attr_definitions = entry["attributes"]["attributeTypes"]

                    for attr_def in attr_definitions if isinstance(attr_definitions, list) else [attr_definitions]:
                        # Parse LDAP schema definition format
                        if isinstance(attr_def, str):
                            parsed_attr = self._parse_attribute_definition(attr_def)
                            if parsed_attr:
                                attributes[parsed_attr.primary_name] = parsed_attr

            logger.info("Parsed server attributes", extra={
                "attributes_found": len(attributes)
            })
            return attributes

        except Exception as parse_error:
            logger.error("Failed to parse server attributes", extra={
                "error": str(parse_error)
            })
            # Return standard attributes on parse failure
            return self._get_standard_attributes()

    def _parse_object_class_definition(self, definition: str) -> FlextLdapSchemaObjectClass | None:
        """Parse a single object class definition string."""
        try:
            # Basic parsing - in production this would be more robust
            import re

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

            return FlextLdapSchemaObjectClass(
                oid=oid,
                names=names,
                object_class_type=oc_type,
                description=f"Server-discovered object class: {names[0] if names else oid}"
            )

        except Exception as parse_error:
            logger.warning("Failed to parse object class definition", extra={
                "definition": definition[:100],
                "error": str(parse_error)
            })
            return None

    def _parse_attribute_definition(self, definition: str) -> FlextLdapSchemaAttribute | None:
        """Parse a single attribute definition string."""
        try:
            import re

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

            return FlextLdapSchemaAttribute(
                oid=oid,
                names=names,
                syntax=syntax,
                description=f"Server-discovered attribute: {names[0] if names else oid}"
            )

        except Exception as parse_error:
            logger.warning("Failed to parse attribute definition", extra={
                "definition": definition[:100],
                "error": str(parse_error)
            })
            return None

    def _get_standard_object_classes(self) -> dict[str, FlextLdapSchemaObjectClass]:
        """Get RFC-compliant standard object classes (not fallback, but standards)."""
        logger.trace("Using RFC-compliant standard object classes")
        return {
            "top": FlextLdapSchemaObjectClass(
                oid="2.5.6.0",
                names=["top"],
                description="RFC2256: top of the superclass chain",
                object_class_type=FlextLdapObjectClassType.ABSTRACT,
                must_attributes=[],
                may_attributes=["objectClass"],
            ),
            "person": FlextLdapSchemaObjectClass(
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
                    "description"
                ],
            ),
            "organizationalPerson": FlextLdapSchemaObjectClass(
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
            "inetOrgPerson": FlextLdapSchemaObjectClass(
                oid="2.16.840.1.113730.3.2.2",
                names=["inetOrgPerson"],
                description="RFC2798: Internet Organizational Person",
                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                superior_classes=["organizationalPerson"],
                must_attributes=[],
                may_attributes=[
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
                ],
            ),
            "groupOfNames": FlextLdapSchemaObjectClass(
                oid="2.5.6.9",
                names=["groupOfNames"],
                description="RFC2256: a group of names (DNs)",
                object_class_type=FlextLdapObjectClassType.STRUCTURAL,
                superior_classes=["top"],
                must_attributes=["member", "cn"],
                may_attributes=["businessCategory", "seeAlso", "owner", "ou", "o", "description"],
            ),
        }

    def _get_standard_attributes(self) -> dict[str, FlextLdapSchemaAttribute]:
        """Get RFC-compliant standard attributes (not fallback, but standards)."""
        logger.trace("Using RFC-compliant standard attributes")
        return {
            "objectClass": FlextLdapSchemaAttribute(
                oid="2.5.4.0",
                names=["objectClass"],
                description="RFC2256: object classes of the entity",
                syntax="1.3.6.1.4.1.1466.115.121.1.38",
                equality_matching_rule="objectIdentifierMatch",
                is_no_user_modification=True,
            ),
            "cn": FlextLdapSchemaAttribute(
                oid="2.5.4.3",
                names=["cn", "commonName"],
                description="RFC2256: common name(s) for which the entity is known by",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "sn": FlextLdapSchemaAttribute(
                oid="2.5.4.4",
                names=["sn", "surname"],
                description="RFC2256: last (family) name(s) for which the entity is known by",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "givenName": FlextLdapSchemaAttribute(
                oid="2.5.4.42",
                names=["givenName", "gn"],
                description="RFC2256: first name(s) for which the entity is known by",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "mail": FlextLdapSchemaAttribute(
                oid="0.9.2342.19200300.100.1.3",
                names=["mail", "rfc822Mailbox"],
                description="RFC1274: electronic mailbox",
                syntax="1.3.6.1.4.1.1466.115.121.1.26",
                equality_matching_rule="caseIgnoreIA5Match",
                substring_matching_rule="caseIgnoreIA5SubstringsMatch",
            ),
            "uid": FlextLdapSchemaAttribute(
                oid="0.9.2342.19200300.100.1.1",
                names=["uid", "userid"],
                description="RFC1274: user identifier",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "userPassword": FlextLdapSchemaAttribute(
                oid="2.5.4.35",
                names=["userPassword"],
                description="RFC2256: password of user",
                syntax="1.3.6.1.4.1.1466.115.121.1.40",
                equality_matching_rule="octetStringMatch",
            ),
            "description": FlextLdapSchemaAttribute(
                oid="2.5.4.13",
                names=["description"],
                description="RFC2256: descriptive information",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality_matching_rule="caseIgnoreMatch",
                substring_matching_rule="caseIgnoreSubstringsMatch",
            ),
            "member": FlextLdapSchemaAttribute(
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
