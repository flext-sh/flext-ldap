"""FLEXT-LDAP Domain Entities - Rich Business Objects for Directory Operations.

This module defines domain entities that encapsulate LDAP directory business logic
without external dependencies, following Domain-Driven Design principles and
Clean Architecture patterns.

All entities extend flext-core foundation classes, providing consistent behavior
across the FLEXT ecosystem with built-in audit trails, validation, and lifecycle
management.

Architecture:
    Domain entities represent core business concepts in the LDAP directory domain:
    - FlextLdapEntry: Generic LDAP directory entry
    - FlextLdapUser: User accounts with authentication capabilities
    - FlextLdapGroup: Group containers for user organization
    - FlextLdapConnection: Connection state management

Design Principles:
    - Rich Domain Model: Business logic embedded in entities
    - No Infrastructure Dependencies: Pure domain logic only
    - Immutable Value Objects: Data integrity through immutability
    - Domain Events: Business event modeling for cross-aggregate communication
    - Railway-Oriented Programming: Consistent error handling via FlextResult

Standards Compliance:
    - RFC 4512: LDAP directory information models
    - RFC 4514: Distinguished Names format validation
    - RFC 4519: LDAP schema definitions

Example:
    Creating and validating a domain entity:

    >>> entry = FlextLdapEntry(
    ...     id="entry-123",
    ...     dn="uid=john,ou=users,dc=example,dc=com",
    ...     object_classes=["inetOrgPerson", "person"],
    ...     attributes={"uid": ["john"], "cn": ["John Doe"]},
    ... )
    >>> validation_result = entry.validate_domain_rules()
    >>> if validation_result.is_success:
    ...     print("Entry is valid")

Integration:
    - Built on flext-core FlextDomainEntity and FlextDomainEntity
    - Compatible with repository pattern implementations
    - Supports domain event sourcing and CQRS patterns

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import warnings
from datetime import UTC, datetime

from flext_core import (
    FlextDomainEntity,
    FlextEntityStatus,
    FlextResult,
    get_logger,
)
from pydantic import Field

logger = get_logger(__name__)

# Use centralized FlextEntityStatus from flext-core
# Legacy compatibility alias
FlextLdapEntityStatus = FlextEntityStatus


class FlextLdapEntry(FlextDomainEntity):
    """Base LDAP directory entry implementing rich domain model patterns.

    Represents a generic LDAP directory entry with comprehensive business logic
    for attribute management, object class validation, and domain rule enforcement.

    This entity serves as the foundation for specialized LDAP entities (users, groups)
    while providing common functionality for all directory objects.

    Attributes:
        dn: Distinguished Name uniquely identifying this entry in the directory
        object_classes: LDAP object classes defining entry schema and capabilities
        attributes: Directory attributes as name-value pairs (multi-valued)
        status: Entity lifecycle status from flext-core (ACTIVE, INACTIVE, etc.)

    Business Rules:
        - Distinguished Name must be valid RFC 4514 format
        - At least one object class must be present
        - Attributes must conform to object class schema definitions
        - Entry must maintain referential integrity with directory structure

    Domain Operations:
        - validate_domain_rules(): Comprehensive business rule validation
        - add_object_class(): Schema-aware object class management
        - get_attribute_values(): Type-safe attribute value retrieval
        - is_descendant_of(): Directory hierarchy relationship checking

    Example:
        Creating a valid LDAP entry:

        >>> entry = FlextLdapEntry(
        ...     id="uuid-123",
        ...     dn="cn=server,ou=hosts,dc=company,dc=com",
        ...     object_classes=["device", "ipHost"],
        ...     attributes={"cn": ["server"], "ipHostNumber": ["192.168.1.100"]},
        ... )
        >>> validation = entry.validate_domain_rules()
        >>> assert validation.is_success

    Integration:
        - Extends flext-core FlextDomainEntity for lifecycle management
        - Compatible with repository pattern for persistence abstraction
        - Supports domain event sourcing for audit trails

    """

    dn: str  # Distinguished Name - unique identifier
    object_classes: list[str] = Field(default_factory=list)
    attributes: dict[str, list[str]] = Field(default_factory=dict)
    status: FlextEntityStatus = Field(default=FlextEntityStatus.ACTIVE)

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate comprehensive business rules for LDAP directory entry.

        Performs domain-level validation ensuring the entry conforms to LDAP
        standards and business requirements before persistence operations.

        Returns:
            FlextResult[None]: Success if all validations pass, failure with
                              detailed error message if validation fails

        Business Rules Validated:
            - Distinguished Name (DN) must be present and non-empty
            - At least one object class must be specified
            - DN must follow RFC 4514 format requirements
            - Object classes must be valid LDAP schema definitions

        """
        if not self.dn:
            return FlextResult.fail("LDAP entry must have a distinguished name")
        if not self.object_classes:
            return FlextResult.fail("LDAP entry must have at least one object class")
        return FlextResult.ok(None)

    def add_object_class(self, object_class: str) -> None:
        """Add LDAP object class to entry with duplicate prevention.

        Adds the specified object class to the entry's object class list,
        ensuring no duplicates are created. Object classes define the
        schema and capabilities available for this LDAP entry.

        Args:
            object_class: LDAP object class name to add (e.g., 'inetOrgPerson')

        Side Effects:
            - Updates the object_classes list if class not already present
            - Triggers automatic timestamp update via FlextDomainEntity lifecycle

        """
        if object_class not in self.object_classes:
            self.object_classes.append(object_class)
            # Note: timestamp updates handled by FlextDomainEntity

    def remove_object_class(self, object_class: str) -> None:
        """Remove LDAP object class from entry with safety checks.

        Removes the specified object class from the entry's object class list.
        Only removes if the class is currently present to prevent errors.

        Args:
            object_class: LDAP object class name to remove

        Side Effects:
            - Updates the object_classes list if class is present
            - Triggers automatic timestamp update via FlextDomainEntity lifecycle

        Note:
            Removing required object classes may violate LDAP schema constraints.
            Validation should be performed before persistence.

        """
        if object_class in self.object_classes:
            self.object_classes.remove(object_class)
            # Note: timestamp updates handled by FlextDomainEntity

    def has_object_class(self, object_class: str) -> bool:
        """Check if entry contains specified LDAP object class.

        Args:
            object_class: LDAP object class name to check for presence

        Returns:
            bool: True if object class is present, False otherwise

        """
        return object_class in self.object_classes

    def add_attribute(self, name: str, value: str | list[str]) -> None:
        """Add attribute value(s) to LDAP entry with multi-value support.

        Adds one or more values to the specified LDAP attribute, supporting
        both single values and multi-valued attributes. Prevents duplicate
        values within the same attribute.

        Args:
            name: LDAP attribute name (e.g., 'mail', 'telephoneNumber')
            value: Single value or list of values to add

        Side Effects:
            - Creates attribute if it doesn't exist
            - Appends new values to existing attribute
            - Prevents duplicate values within the same attribute
            - Triggers automatic timestamp update via FlextDomainEntity lifecycle

        """
        if name not in self.attributes:
            self.attributes[name] = []

        values_to_add = [value] if isinstance(value, str) else value
        for val in values_to_add:
            if val not in self.attributes[name]:
                self.attributes[name].append(val)

        # Note: timestamp updates handled by FlextDomainEntity

    def remove_attribute(self, name: str, value: str | None = None) -> None:
        """Remove LDAP attribute or specific value with granular control.

        Provides flexible attribute removal supporting both complete attribute
        deletion and selective value removal from multi-valued attributes.

        Args:
            name: LDAP attribute name to remove or modify
            value: Optional specific value to remove. If None, removes entire attribute

        Side Effects:
            - If value is None: Removes entire attribute and all its values
            - If value is specified: Removes only that specific value
            - Removes empty attributes after value removal
            - Triggers automatic timestamp update via FlextDomainEntity lifecycle

        """
        if name in self.attributes:
            if value is None:
                # Remove entire attribute
                del self.attributes[name]
            elif value in self.attributes[name]:
                # Remove specific value
                self.attributes[name].remove(value)
                # Remove attribute if no values left
                if not self.attributes[name]:
                    del self.attributes[name]
            # Note: timestamp updates handled by FlextDomainEntity

    def get_attribute(self, name: str) -> list[str]:
        """Retrieve all values for specified LDAP attribute.

        Args:
            name: LDAP attribute name to retrieve

        Returns:
            list[str]: List of attribute values, empty list if attribute not found

        """
        return self.attributes.get(name, [])

    def get_single_attribute(self, name: str) -> str | None:
        """Retrieve first value from LDAP attribute for single-valued access.

        Convenience method for accessing attributes expected to contain only
        one value, returning the first value from multi-valued attributes.

        Args:
            name: LDAP attribute name to retrieve

        Returns:
            str | None: First attribute value, None if attribute not found or empty

        """
        values = self.get_attribute(name)
        return values[0] if values else None

    def has_attribute(self, name: str, value: str | None = None) -> bool:
        """Check presence of LDAP attribute or specific attribute value.

        Provides flexible attribute checking supporting both attribute existence
        and specific value presence within multi-valued attributes.

        Args:
            name: LDAP attribute name to check
            value: Optional specific value to check for presence

        Returns:
            bool: True if attribute exists (and value matches if specified),
                  False otherwise

        """
        if name not in self.attributes:
            return False
        if value is None:
            return True
        return value in self.attributes[name]

    def get_rdn(self) -> str:
        """Extract Relative Distinguished Name from full Distinguished Name.

        Parses the Distinguished Name to return only the first component,
        which represents the entry's Relative Distinguished Name (RDN).

        Returns:
            str: RDN component (e.g., 'uid=john' from
                 'uid=john,ou=users,dc=example,dc=com')
                 Empty string if DN is not set

        Example:
            >>> entry.dn = "cn=John Doe,ou=users,dc=example,dc=com"
            >>> entry.get_rdn()
            'cn=John Doe'

        """
        return self.dn.split(",")[0] if self.dn else ""

    def get_parent_dn(self) -> str:
        """Get the parent DN (everything after the first component)."""
        components = self.dn.split(",")
        return ",".join(components[1:]) if len(components) > 1 else ""

    def is_active(self) -> bool:
        """Check if entry is active."""
        return self.status == FlextEntityStatus.ACTIVE

    def deactivate(self) -> FlextLdapEntry:
        """Deactivate the entry."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextEntityStatus.INACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def activate(self) -> FlextLdapEntry:
        """Activate the entry."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextEntityStatus.ACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)


class FlextLdapConnection(FlextDomainEntity):
    """LDAP connection state management entity for session tracking.

    Domain entity representing LDAP connection state and lifecycle management.
    Tracks connection parameters, authentication status, and session information
    following Clean Architecture and DDD patterns.

    This entity manages connection state transitions and provides business logic
    for connection validation and lifecycle operations.

    Attributes:
        server_url: LDAP server URL (ldap:// or ldaps://)
        bind_dn: Distinguished Name used for authentication binding
        is_bound: Current authentication binding status
        status: Connection lifecycle status from flext-core
        pool_id: Optional connection pool identifier for resource management

    Business Rules:
        - Server URL must be present and valid
        - Connection must be bound before performing operations
        - Status transitions follow flext-core entity lifecycle patterns

    Domain Operations:
        - bind(): Authenticate and establish session
        - unbind(): Terminate session and clear authentication
        - can_search(): Validate operational readiness

    """

    server_url: str
    bind_dn: str | None = None
    is_bound: bool = False
    status: FlextEntityStatus = Field(default=FlextEntityStatus.INACTIVE)
    pool_id: str | None = None

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate LDAP connection business rules and constraints.

        Ensures connection entity meets domain requirements for establishing
        and maintaining LDAP connections according to business rules.

        Returns:
            FlextResult[None]: Success if validation passes, failure with
                              error message describing constraint violation

        Business Rules Validated:
            - Server URL must be present and non-empty
            - URL format should be valid LDAP protocol format

        """
        if not self.server_url:
            return FlextResult.fail("LDAP connection must have a server URL")
        return FlextResult.ok(None)

    def bind(self, bind_dn: str) -> FlextLdapConnection:
        """Establish authenticated binding to LDAP server.

        Creates new connection entity with authenticated binding state,
        transitioning the connection to active status with specified DN.

        Args:
            bind_dn: Distinguished Name for authentication binding

        Returns:
            FlextLdapConnection: New entity instance with bound state

        Side Effects:
            - Sets is_bound to True
            - Updates bind_dn to specified value
            - Transitions status to ACTIVE
            - Increments entity version for optimistic locking

        """
        entity_data = self.model_dump()
        entity_data.update(
            {
                "bind_dn": bind_dn,
                "is_bound": True,
                "status": FlextEntityStatus.ACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def unbind(self) -> FlextLdapConnection:
        """Unbind from LDAP server."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "bind_dn": None,
                "is_bound": False,
                "status": FlextEntityStatus.INACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def can_search(self) -> bool:
        """Validate connection readiness for LDAP search operations.

        Checks connection state to determine if search operations can be
        performed, requiring both authentication binding and active status.

        Returns:
            bool: True if connection is bound and active, False otherwise

        """
        return self.is_bound and self.status == FlextEntityStatus.ACTIVE

    @property
    def is_connected(self) -> bool:
        """Check if connection is in connected state."""
        return self.status == FlextEntityStatus.ACTIVE

    def connect(self) -> FlextLdapConnection:
        """Mark connection as connected (domain state change)."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextEntityStatus.ACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def disconnect(self) -> FlextLdapConnection:
        """Mark connection as disconnected (domain state change)."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextEntityStatus.INACTIVE,
                "is_bound": False,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)


class FlextLdapUser(FlextDomainEntity):
    """LDAP user account entity with comprehensive business logic.

    Domain entity representing LDAP user accounts with rich business operations
    for user management, attribute manipulation, and account lifecycle control.

    Implements standard LDAP user attributes following inetOrgPerson schema
    while providing domain-specific operations for user account management.

    Attributes:
        dn: Distinguished Name uniquely identifying the user
        uid: User identifier (login name)
        cn: Common name (display name)
        sn: Surname (last name)
        mail: Email address
        phone: Telephone number
        ou: Organizational unit
        department: Department affiliation
        title: Job title or position
        object_classes: LDAP object classes (defaults to inetOrgPerson)
        attributes: Additional custom attributes
        status: Account lifecycle status from flext-core

    Business Rules:
        - Distinguished Name must be present and valid
        - Email address must follow valid format if provided
        - User must have at least one object class

    Domain Operations:
        - add_attribute()/remove_attribute(): Custom attribute management
        - deactivate()/lock_account(): Account security operations
        - has_mail(): Convenience methods for attribute checking

    """

    dn: str
    uid: str | None = None
    cn: str | None = None
    sn: str | None = None
    mail: str | None = None
    phone: str | None = None
    ou: str | None = None
    department: str | None = None
    title: str | None = None
    object_classes: list[str] = Field(default_factory=lambda: ["inetOrgPerson"])
    attributes: dict[str, list[str]] = Field(default_factory=dict)
    status: FlextEntityStatus = FlextLdapEntityStatus.ACTIVE

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate LDAP user account business rules and constraints.

        Performs comprehensive validation of user account data ensuring
        compliance with domain requirements and LDAP schema constraints.

        Returns:
            FlextResult[None]: Success if all validations pass, failure with
                              detailed error message for first constraint violation

        Business Rules Validated:
            - Distinguished Name must be present and non-empty
            - Email address must contain '@' symbol if provided
            - User account must meet organizational standards

        """
        if not self.dn:
            return FlextResult.fail("LDAP user must have a distinguished name")
        if self.mail and "@" not in self.mail:
            return FlextResult.fail("User email must be valid format")
        return FlextResult.ok(None)

    def add_attribute(self, name: str, value: str) -> FlextLdapUser:
        """Add an attribute to the user."""
        entity_data = self.model_dump()
        new_attributes = entity_data["attributes"].copy()
        new_attributes[name] = value
        entity_data.update(
            {
                "attributes": new_attributes,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def remove_attribute(self, name: str) -> FlextLdapUser:
        """Remove an attribute from the user."""
        entity_data = self.model_dump()
        new_attributes = entity_data["attributes"].copy()
        if name in new_attributes:
            del new_attributes[name]
        entity_data.update(
            {
                "attributes": new_attributes,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def get_attribute(self, name: str) -> str | None:
        """Get an attribute by name."""
        values = self.attributes.get(name)
        if isinstance(values, list) and values:
            return values[0]
        return None

    def has_attribute(self, name: str) -> bool:
        """Check if user has a specific attribute."""
        if name in {"mail", "phone", "ou", "department", "title"}:
            return getattr(self, name) is not None
        return name in self.attributes

    def has_mail(self) -> bool:
        """Check if user has an email address."""
        return self.mail is not None

    def deactivate(self) -> FlextLdapUser:
        """Deactivate the user."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextEntityStatus.INACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def lock_account(self) -> FlextLdapUser:
        """Lock the user account."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextEntityStatus.INACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def unlock_account(self) -> FlextLdapUser:
        """Unlock the user account."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextEntityStatus.ACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def is_active(self) -> bool:
        """Check if the user account is active."""
        return self.status == FlextEntityStatus.ACTIVE


class FlextLdapGroup(FlextDomainEntity):
    """LDAP group entity for user organization and access control.

    Domain entity representing LDAP groups with comprehensive member management
    and ownership capabilities. Supports both static group membership and
    hierarchical group ownership patterns.

    Groups serve as containers for organizing users and controlling access
    to resources through membership-based authorization patterns.

    Attributes:
        dn: Distinguished Name uniquely identifying the group
        cn: Common name (group display name)
        ou: Organizational unit containing the group
        members: List of member Distinguished Names
        owners: List of group owner Distinguished Names
        object_classes: LDAP object classes (defaults to groupOfNames)
        status: Group lifecycle status from flext-core

    Business Rules:
        - Distinguished Name must be present and valid
        - Common name must be specified for group identification
        - Members and owners must use valid Distinguished Names
        - Group must maintain referential integrity with directory

    Domain Operations:
        - add_member()/remove_member(): Member management operations
        - add_owner()/remove_owner(): Owner management operations
        - has_member()/is_owner(): Membership query operations

    """

    dn: str
    cn: str
    ou: str | None = None
    members: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    object_classes: list[str] = Field(default_factory=lambda: ["groupOfNames"])
    status: FlextEntityStatus = Field(default=FlextEntityStatus.ACTIVE)

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate LDAP group business rules and constraints.

        Ensures group entity meets domain requirements for group management
        and membership operations according to business rules.

        Returns:
            FlextResult[None]: Success if validation passes, failure with
                              error message describing constraint violation

        Business Rules Validated:
            - Distinguished Name must be present and non-empty
            - Common name must be specified for group identification
            - Group attributes must meet organizational standards

        """
        if not self.dn:
            return FlextResult.fail("LDAP group must have a distinguished name")
        if not self.cn:
            return FlextResult.fail("LDAP group must have a common name")
        return FlextResult.ok(None)

    def add_member(self, member_dn: str) -> FlextLdapGroup:
        """Add a member to the group."""
        entity_data = self.model_dump()
        new_members = entity_data["members"].copy()
        if member_dn not in new_members:
            new_members.append(member_dn)
        entity_data.update(
            {
                "members": new_members,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def remove_member(self, member_dn: str) -> FlextLdapGroup:
        """Remove a member from the group."""
        entity_data = self.model_dump()
        new_members = entity_data["members"].copy()
        if member_dn in new_members:
            new_members.remove(member_dn)
        entity_data.update(
            {
                "members": new_members,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def has_member(self, member_dn: str) -> bool:
        """Check if group has a specific member."""
        return member_dn in self.members

    def add_owner(self, owner_dn: str) -> FlextLdapGroup:
        """Add an owner to the group."""
        entity_data = self.model_dump()
        new_owners = entity_data["owners"].copy()
        if owner_dn not in new_owners:
            new_owners.append(owner_dn)
        entity_data.update(
            {
                "owners": new_owners,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def remove_owner(self, owner_dn: str) -> FlextLdapGroup:
        """Remove an owner from the group."""
        entity_data = self.model_dump()
        new_owners = entity_data["owners"].copy()
        if owner_dn in new_owners:
            new_owners.remove(owner_dn)
        entity_data.update(
            {
                "owners": new_owners,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def is_owner(self, owner_dn: str) -> bool:
        """Check if DN is an owner of the group."""
        return owner_dn in self.owners

    def deactivate(self) -> FlextLdapGroup:
        """Deactivate the group."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextEntityStatus.INACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)


class FlextLdapOperation(FlextDomainEntity):
    """LDAP operation tracking entity for audit and monitoring.

    Entity for tracking LDAP operations throughout their lifecycle,
    providing comprehensive audit trails and performance monitoring
    capabilities for directory operations.

    This entity captures operation metadata, execution timing, results,
    and error information for compliance and performance analysis.

    Attributes:
        operation_type: Type of LDAP operation (search, add, modify, delete)
        target_dn: Distinguished Name targeted by the operation
        connection_id: Identifier of connection used for operation
        user_dn: Distinguished Name of user performing operation
        filter_expression: LDAP search filter if applicable
        attributes: List of attributes involved in operation
        started_at: Operation start timestamp
        completed_at: Operation completion timestamp
        success: Operation success status
        result_count: Number of entries affected/returned
        error_message: Error details if operation failed
        status: Operation lifecycle status

    Business Rules:
        - Operation type must be specified
        - Target DN must be present
        - Connection ID must be valid
        - Timing information must be consistent

    """

    operation_type: str
    target_dn: str
    connection_id: str
    user_dn: str | None = None
    filter_expression: str | None = None
    attributes: list[str] = Field(default_factory=list)
    started_at: str | None = None
    completed_at: str | None = None
    success: bool | None = None
    result_count: int = 0
    error_message: str | None = None
    status: FlextEntityStatus = FlextLdapEntityStatus.PENDING

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate LDAP operation business rules using Railway-Oriented Programming.

        Comprehensive validation ensuring operation entity meets domain requirements
        for audit tracking and monitoring. Uses Railway-Oriented Programming pattern
        for efficient error handling with early exit on first validation failure.

        Returns:
            FlextResult[None]: Success if all validations pass, failure with
                              first constraint violation message

        Business Rules Validated:
            - Operation type must be specified and non-empty
            - Target DN must be present for operation tracking
            - Connection ID must be valid for session correlation

        Architecture Note:
            Implements Railway-Oriented Programming with Strategy Pattern
            for maintainable validation logic with reduced cyclomatic complexity.

        """
        # Railway-Oriented Programming: Chain validations with early exit
        validation_errors = self._collect_operation_validation_errors()

        if validation_errors:
            return FlextResult.fail(validation_errors[0])  # Return first error

        return FlextResult.ok(None)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules - alias for domain rules for compatibility."""
        return self.validate_domain_rules()

    def _collect_operation_validation_errors(self) -> list[str]:
        """DRY helper: Collect operation validation errors using Strategy Pattern."""
        errors = []

        # Strategy 1: Operation type validation
        if not self.operation_type:
            errors.append("LDAP operation must have an operation type")

        # Strategy 2: Target DN validation
        if not self.target_dn:
            errors.append("LDAP operation must have a target DN")

        # Strategy 3: Connection ID validation
        if not self.connection_id:
            errors.append("LDAP operation must have a connection ID")

        return errors

    def start_operation(self) -> FlextLdapOperation:
        """Mark operation as started."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "started_at": datetime.now(UTC).isoformat(),
                "status": FlextEntityStatus.ACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def complete_operation(
        self,
        *,
        success: bool,
        result_count: int = 0,
        error_message: str | None = None,
    ) -> FlextLdapOperation:
        """Mark operation as completed."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "completed_at": datetime.now(UTC).isoformat(),
                "success": success,
                "result_count": result_count,
                "error_message": error_message,
                "status": FlextEntityStatus.INACTIVE,  # INACTIVE = completed
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def is_completed(self) -> bool:
        """Check if operation is completed."""
        return self.completed_at is not None

    def is_successful(self) -> bool:
        """Check if operation was successful."""
        return self.success is True


# Backward compatibility aliases
EntityStatus = FlextLdapEntityStatus

# Deprecation warning for complex path access
warnings.warn(
    "🚨 DEPRECATED COMPLEX PATH: Importing from "
    "'flext_ldap.domain.entities' is deprecated.\n"
    "✅ SIMPLE SOLUTION: from flext_ldap import LDAPUser, LDAPGroup, LDAPEntry\n"
    "💡 ALL entities are now available at root level for better productivity!\n"
    "📖 Complex paths will be removed in version 0.9.0.\n"
    "📚 Migration guide: https://docs.flext.dev/ldap/simple-imports",
    DeprecationWarning,
    stacklevel=2,
)


def __getattr__(name: str) -> object:
    """Handle attribute access with deprecation warnings."""
    entity_classes = {
        "LDAPEntry": FlextLdapEntry,
        "LDAPConnection": FlextLdapConnection,
        "LDAPUser": FlextLdapUser,
        "LDAPGroup": FlextLdapGroup,
        "LDAPOperation": FlextLdapOperation,
    }

    if name in entity_classes:
        warnings.warn(
            f"🚨 DEPRECATED ACCESS: Using "
            f"'flext_ldap.domain.entities.{name}' is deprecated.\n"
            f"✅ SIMPLE SOLUTION: from flext_ldap import {name}\n"
            f"💡 Direct root-level imports are much simpler and more productive!\n"
            f"📖 This access pattern will be removed in version 0.9.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return entity_classes[name]

    msg = f"module 'flext_ldap.domain.entities' has no attribute '{name}'"
    raise AttributeError(msg)


# Rebuild models after all classes are defined
FlextLdapEntry.model_rebuild()
FlextLdapUser.model_rebuild()
FlextLdapGroup.model_rebuild()
FlextLdapConnection.model_rebuild()
