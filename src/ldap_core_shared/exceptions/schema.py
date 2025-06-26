"""📋 Schema-related LDAP Exceptions.

Exception classes for LDAP schema discovery, validation, and migration errors.
"""

from __future__ import annotations

from typing import Any, Optional

from ldap_core_shared.exceptions.base import LDAPError


class SchemaError(LDAPError):
    """📋 Exception for LDAP schema-related errors.

    Base class for all schema discovery, comparison, and migration errors.
    """

    def __init__(
        self,
        message: str,
        *,
        schema_element: Optional[str] = None,
        element_type: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize schema error.

        Args:
            message: Error description
            schema_element: Name of schema element (attribute, object class, etc.)
            element_type: Type of schema element (attributeType, objectClass, etc.)
            **kwargs: Additional arguments for LDAPError
        """
        context = kwargs.get("context", {})
        if schema_element:
            context["schema_element"] = schema_element
        if element_type:
            context["element_type"] = element_type

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class SchemaDiscoveryError(SchemaError):
    """🔍 Exception for schema discovery failures."""

    def __init__(
        self,
        message: str,
        *,
        server_type: Optional[str] = None,
        discovery_method: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize schema discovery error.

        Args:
            message: Error description
            server_type: Type of LDAP server (OID, OUD, AD, etc.)
            discovery_method: Method used for discovery
            **kwargs: Additional arguments for SchemaError
        """
        context = kwargs.get("context", {})
        if server_type:
            context["server_type"] = server_type
        if discovery_method:
            context["discovery_method"] = discovery_method

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class SchemaComparisonError(SchemaError):
    """⚖️ Exception for schema comparison failures."""

    def __init__(
        self,
        message: str,
        *,
        source_schema: Optional[str] = None,
        target_schema: Optional[str] = None,
        comparison_type: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize schema comparison error.

        Args:
            message: Error description
            source_schema: Source schema identifier
            target_schema: Target schema identifier
            comparison_type: Type of comparison being performed
            **kwargs: Additional arguments for SchemaError
        """
        context = kwargs.get("context", {})
        if source_schema:
            context["source_schema"] = source_schema
        if target_schema:
            context["target_schema"] = target_schema
        if comparison_type:
            context["comparison_type"] = comparison_type

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class SchemaMappingError(SchemaError):
    """🗺️ Exception for schema mapping failures."""

    def __init__(
        self,
        message: str,
        *,
        source_element: Optional[str] = None,
        target_element: Optional[str] = None,
        mapping_rule: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize schema mapping error.

        Args:
            message: Error description
            source_element: Source schema element
            target_element: Target schema element
            mapping_rule: Mapping rule that failed
            **kwargs: Additional arguments for SchemaError
        """
        context = kwargs.get("context", {})
        if source_element:
            context["source_element"] = source_element
        if target_element:
            context["target_element"] = target_element
        if mapping_rule:
            context["mapping_rule"] = mapping_rule

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class SchemaCompatibilityError(SchemaError):
    """🔄 Exception for schema compatibility failures during migration."""

    def __init__(
        self,
        message: str,
        *,
        source_schema: Optional[str] = None,
        target_schema: Optional[str] = None,
        compatibility_issue: Optional[str] = None,
        resolution_suggestion: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize schema compatibility error.

        Args:
            message: Error description
            source_schema: Source schema identifier
            target_schema: Target schema identifier
            compatibility_issue: Specific compatibility issue
            resolution_suggestion: Suggested resolution
            **kwargs: Additional arguments for SchemaError
        """
        context = kwargs.get("context", {})
        if source_schema:
            context["source_schema"] = source_schema
        if target_schema:
            context["target_schema"] = target_schema
        if compatibility_issue:
            context["compatibility_issue"] = compatibility_issue
        if resolution_suggestion:
            context["resolution_suggestion"] = resolution_suggestion

        kwargs["context"] = context
        super().__init__(message, **kwargs)


class SchemaConflictError(SchemaError):
    """⚠️ Exception for schema conflicts during migration."""

    def __init__(
        self,
        message: str,
        *,
        conflicting_elements: Optional[list[str]] = None,
        conflict_type: Optional[str] = None,
        resolution_suggestion: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize schema conflict error.

        Args:
            message: Error description
            conflicting_elements: List of conflicting schema elements
            conflict_type: Type of conflict (name, OID, syntax, etc.)
            resolution_suggestion: Suggested resolution
            **kwargs: Additional arguments for SchemaError
        """
        context = kwargs.get("context", {})
        if conflicting_elements:
            context["conflicting_elements"] = conflicting_elements
        if conflict_type:
            context["conflict_type"] = conflict_type
        if resolution_suggestion:
            context["resolution_suggestion"] = resolution_suggestion

        kwargs["context"] = context
        super().__init__(message, **kwargs)
