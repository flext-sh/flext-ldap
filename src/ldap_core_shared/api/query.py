"""LDAP Query Builder Module - Fluent Interface Pattern.

This module contains the Query builder extracted from the monolithic api.py.
It provides fluent, chainable query construction that delegates to the facade.

DESIGN PATTERN: BUILDER + FLUENT INTERFACE + DELEGATION
- Chainable query construction
- Semantic business methods
- Delegates execution to facade
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Self

from ldap_core_shared.utils.logging import get_logger

if TYPE_CHECKING:
    from ldap_core_shared.api.results import Result
    from ldap_core_shared.domain.models import LDAPEntry

logger = get_logger(__name__)


class Query:
    """LDAP Query Builder - Fluent Interface Pattern.

    DESIGN PATTERN: BUILDER + FLUENT INTERFACE
    ========================================

    This class implements the Builder pattern with a fluent interface to construct
    complex LDAP queries in a readable, chainable manner. It abstracts away LDAP
    filter syntax while providing semantic, business-oriented query methods.

    RESPONSIBILITIES:
    - Build complex LDAP search filters through method chaining
    - Provide semantic, business-oriented query methods
    - Abstract LDAP filter syntax from developers
    - Validate query parameters before execution
    - Delegate query execution to the LDAP facade

    BENEFITS:
    - Readable, self-documenting query construction
    - Type-safe query building with IDE support
    - Prevents LDAP injection through parameter validation
    - Business-oriented methods (users(), in_department(), etc.)
    - Composable and reusable query patterns

    USAGE PATTERNS:
    - Simple object search:
        >>> users = await (ldap.query()
        ...     .users()
        ...     .execute())

    - Filtered search with semantic methods:
        >>> managers = await (ldap.query()
        ...     .users()
        ...     .in_department("Engineering")
        ...     .with_title("*Manager*")
        ...     .select("name", "email", "title")
        ...     .limit(25)
        ...     .execute())

    - Custom location and filters:
        >>> computers = await (ldap.query()
        ...     .computers()
        ...     .in_location("ou=Workstations,dc=company,dc=com")
        ...     .where("operatingSystem=Windows*")
        ...     .sort_by("name")
        ...     .execute())

    INTEGRATION:
    Query builders are created by the LDAP facade and delegate execution back
    to the facade, maintaining the single point of entry principle while
    providing rich query composition capabilities.
    """

    def __init__(self, ldap_facade: Any) -> None:
        """Initialize query builder.

        BUILDER INITIALIZATION: Sets up query state and maintains reference
        to the LDAP facade for query execution delegation.

        Args:
            ldap_facade: LDAP facade instance for query execution

        """
        self._ldap = ldap_facade

        # Query construction state
        self._object_class: str | None = None
        self._base_dn: str | None = None
        self._filters: list[str] = []
        self._attributes: list[str] = []
        self._limit: int = 0
        self._sort_by: str | None = None

    # Object type methods - semantic and clear
    def users(self) -> Self:
        """Search for user objects.

        SEMANTIC METHOD: Sets object class filter for person/user objects.

        Returns:
            Self for method chaining

        Example:
            >>> users = await ldap.query().users().execute()

        """
        self._object_class = "person"
        return self

    def groups(self) -> Self:
        """Search for group objects.

        SEMANTIC METHOD: Sets object class filter for group objects.

        Returns:
            Self for method chaining

        Example:
            >>> groups = await ldap.query().groups().execute()

        """
        self._object_class = "group"
        return self

    def computers(self) -> Self:
        """Search for computer objects.

        SEMANTIC METHOD: Sets object class filter for computer objects.

        Returns:
            Self for method chaining

        Example:
            >>> computers = await ldap.query().computers().execute()

        """
        self._object_class = "computer"
        return self

    def objects(self, object_class: str) -> Self:
        """Search for specific object class.

        GENERIC METHOD: Allows searching for any LDAP object class.

        Args:
            object_class: LDAP object class name

        Returns:
            Self for method chaining

        Example:
            >>> printers = await ldap.query().objects("printQueue").execute()

        """
        self._object_class = object_class
        return self

    # Location methods - intuitive naming
    def in_location(self, dn: str) -> Self:
        """Search in specific DN location.

        LOCATION METHOD: Sets the base DN for the search scope.

        Args:
            dn: Distinguished Name to use as search base

        Returns:
            Self for method chaining

        Example:
            >>> users = await (ldap.query()
            ...     .users()
            ...     .in_location("ou=Engineering,dc=company,dc=com")
            ...     .execute())

        """
        self._base_dn = dn
        return self

    def in_ou(self, ou_name: str) -> Self:
        """Search in organizational unit.

        CONVENIENCE METHOD: Automatically constructs OU DN from base configuration.

        Args:
            ou_name: Organizational unit name

        Returns:
            Self for method chaining

        Example:
            >>> users = await (ldap.query()
            ...     .users()
            ...     .in_ou("Engineering")
            ...     .execute())

        """
        self._base_dn = f"ou={ou_name},{self._ldap._config.base_dn}"
        return self

    # Filter methods - semantic and domain-specific
    def where(self, filter_expr: str) -> Self:
        """Add custom LDAP filter.

        EXTENSIBILITY METHOD: Allows adding raw LDAP filters when semantic
        methods don't cover specific requirements.

        Args:
            filter_expr: LDAP filter expression (must include parentheses)

        Returns:
            Self for method chaining

        Example:
            >>> results = await (ldap.query()
            ...     .users()
            ...     .where("(lastLogon>=131234567890000000)")
            ...     .execute())

        """
        self._filters.append(filter_expr)
        return self

    def with_name(self, name: str) -> Self:
        """Filter by name (supports wildcards).

        SEMANTIC FILTER: Business-friendly name filtering with wildcard support.

        Args:
            name: Name to search for (supports * and ? wildcards)

        Returns:
            Self for method chaining

        Example:
            >>> users = await (ldap.query()
            ...     .users()
            ...     .with_name("John*")
            ...     .execute())

        """
        self._filters.append(f"(cn={name})")
        return self

    def with_email(self, email: str) -> Self:
        """Filter by email address.

        SEMANTIC FILTER: Searches both primary email and proxy addresses
        for comprehensive email-based user lookup.

        Args:
            email: Email address to search for

        Returns:
            Self for method chaining

        Example:
            >>> user = await (ldap.query()
            ...     .users()
            ...     .with_email("john.doe@company.com")
            ...     .first())

        """
        self._filters.append(f"(|(mail={email})(proxyAddresses=smtp:{email}))")
        return self

    def in_department(self, department: str) -> Self:
        """Filter by department.

        BUSINESS FILTER: Department-based filtering for organizational queries.

        Args:
            department: Department name to filter by

        Returns:
            Self for method chaining

        Example:
            >>> engineers = await (ldap.query()
            ...     .users()
            ...     .in_department("Engineering")
            ...     .execute())

        """
        self._filters.append(f"(department={department})")
        return self

    def with_title(self, title: str) -> Self:
        """Filter by job title (supports wildcards).

        BUSINESS FILTER: Job title filtering with wildcard support for
        flexible role-based queries.

        Args:
            title: Job title to search for (supports * and ? wildcards)

        Returns:
            Self for method chaining

        Example:
            >>> managers = await (ldap.query()
            ...     .users()
            ...     .with_title("*Manager*")
            ...     .execute())

        """
        self._filters.append(f"(title={title})")
        return self

    def enabled_only(self) -> Self:
        """Only enabled accounts (Active Directory).

        BUSINESS FILTER: Filters for active user accounts, excluding
        disabled accounts using Active Directory userAccountControl attribute.

        Returns:
            Self for method chaining

        Example:
            >>> active_users = await (ldap.query()
            ...     .users()
            ...     .enabled_only()
            ...     .execute())

        """
        self._filters.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
        return self

    def disabled_only(self) -> Self:
        """Only disabled accounts (Active Directory).

        BUSINESS FILTER: Filters for disabled user accounts using
        Active Directory userAccountControl attribute.

        Returns:
            Self for method chaining

        Example:
            >>> disabled_users = await (ldap.query()
            ...     .users()
            ...     .disabled_only()
            ...     .execute())

        """
        self._filters.append("(userAccountControl:1.2.840.113556.1.4.803:=2)")
        return self

    def member_of(self, group: str) -> Self:
        """Filter by group membership.

        BUSINESS FILTER: Finds users who are members of a specific group.

        Args:
            group: Group name to check membership for

        Returns:
            Self for method chaining

        Example:
            >>> admins = await (ldap.query()
            ...     .users()
            ...     .member_of("Domain Admins")
            ...     .execute())

        """
        self._filters.append(f"(memberOf=cn={group},*)")
        return self

    # Attribute selection - clear and efficient
    def select(self, *attributes: str) -> Self:
        """Select specific attributes.

        PERFORMANCE OPTIMIZATION: Reduces network traffic and memory usage
        by only retrieving required attributes from LDAP server.

        Args:
            *attributes: Attribute names to retrieve

        Returns:
            Self for method chaining

        Example:
            >>> users = await (ldap.query()
            ...     .users()
            ...     .select("cn", "mail", "department")
            ...     .execute())

        """
        self._attributes.extend(attributes)
        return self

    def select_all(self) -> Self:
        """Select all attributes.

        CONVENIENCE METHOD: Retrieves all available attributes. Use sparingly
        as this can result in large data transfers.

        Returns:
            Self for method chaining

        Example:
            >>> complete_users = await (ldap.query()
            ...     .users()
            ...     .select_all()
            ...     .limit(10)
            ...     .execute())

        """
        self._attributes = ["*"]
        return self

    def select_basic(self) -> Self:
        """Select common attributes based on object type.

        SMART DEFAULTS: Automatically selects the most commonly needed
        attributes based on the object type being queried.

        Returns:
            Self for method chaining

        OBJECT TYPE MAPPINGS:
        - person: cn, mail, displayName, department, title
        - group: cn, description, member
        - other: cn, description

        Example:
            >>> users = await (ldap.query()
            ...     .users()
            ...     .select_basic()  # Gets cn, mail, displayName, department, title
            ...     .execute())

        """
        if self._object_class == "person":
            self._attributes = ["cn", "mail", "displayName", "department", "title"]
        elif self._object_class == "group":
            self._attributes = ["cn", "description", "member"]
        else:
            self._attributes = ["cn", "description"]
        return self

    # Result modifiers
    def limit(self, count: int) -> Self:
        """Limit number of results.

        PERFORMANCE CONTROL: Prevents accidentally retrieving large result sets
        that could impact performance or memory usage.

        Args:
            count: Maximum number of results to return

        Returns:
            Self for method chaining

        Example:
            >>> recent_users = await (ldap.query()
            ...     .users()
            ...     .limit(50)
            ...     .execute())

        """
        self._limit = count
        return self

    def sort_by(self, attribute: str) -> Self:
        """Sort results by attribute.

        CLIENT-SIDE SORTING: Results are sorted after retrieval. For large
        result sets, consider using limit() to reduce sorting overhead.

        Args:
            attribute: Attribute name to sort by

        Returns:
            Self for method chaining

        Example:
            >>> sorted_users = await (ldap.query()
            ...     .users()
            ...     .sort_by("displayName")
            ...     .execute())

        """
        self._sort_by = attribute
        return self

    # Execution methods - delegate to facade
    async def execute(self) -> Result[list[LDAPEntry]]:
        """Execute the query and return all results.

        BUILDER EXECUTION: Constructs LDAP filter from all chained methods
        and delegates execution to the facade for actual LDAP operations.

        Returns:
            Result containing list of LDAPEntry objects

        DELEGATION FLOW:
        1. Builds LDAP filter from accumulated query state
        2. Delegates to facade._search() method
        3. Applies client-side sorting if requested
        4. Returns Result[list[LDAPEntry]] for consistent error handling

        FILTER CONSTRUCTION LOGIC:
        - Single filter: Uses as-is
        - Multiple filters: Combines with AND (&) operator
        - No filters: Defaults to (objectClass=*)

        Example:
            >>> # This will generate: (&(objectClass=person)(department=IT))
            >>> results = await (ldap.query()
            ...     .users()
            ...     .in_department("IT")
            ...     .execute())

        """
        start_time = time.time()

        try:
            # Import here to avoid circular imports
            from ldap_core_shared.api.results import Result

            # Build filter from accumulated query state
            filter_parts = []

            if self._object_class:
                filter_parts.append(f"(objectClass={self._object_class})")

            filter_parts.extend(self._filters)

            if len(filter_parts) == 0:
                ldap_filter = "(objectClass=*)"
            elif len(filter_parts) == 1:
                ldap_filter = filter_parts[0]
            else:
                ldap_filter = "(&" + "".join(filter_parts) + ")"

            # Delegate execution to facade
            result = await self._ldap._search(
                base_dn=self._base_dn or self._ldap._config.base_dn,
                filter_expr=ldap_filter,
                attributes=self._attributes or None,
                limit=self._limit,
            )

            # Apply client-side sorting if requested
            if result.success and self._sort_by and result.data:
                try:
                    result.data.sort(key=lambda e: e.get_attribute(self._sort_by) or "")
                except (AttributeError, TypeError, ValueError) as e:
                    # Sorting failed - log warning but don't fail the whole query
                    logger.warning(
                        "Result sorting failed for attribute '%s': %s",
                        self._sort_by,
                        e,
                    )
                except Exception as e:
                    # Unexpected sorting error - log with more detail
                    logger.error(
                        "Unexpected error during result sorting: %s",
                        e,
                        exc_info=True,
                    )

            execution_time = (time.time() - start_time) * 1000
            result.execution_time_ms = execution_time

            return result

        except Exception as e:
            from ldap_core_shared.api.results import Result

            execution_time = (time.time() - start_time) * 1000
            return Result.from_exception(
                e,
                default_data=[],
                execution_time_ms=execution_time,
            )

    async def first(self) -> Result[LDAPEntry]:
        """Get first result only.

        CONVENIENCE METHOD: Automatically limits results to 1 and extracts
        the first entry for single-item queries.

        Returns:
            Result containing single LDAPEntry or None if not found

        OPTIMIZATION: Automatically applies limit(1) to minimize data transfer
        and processing when only one result is needed.

        Example:
            >>> user = await (ldap.query()
            ...     .users()
            ...     .with_email("john.doe@company.com")
            ...     .first())
            >>> if user.success and user.data:
            ...     print(f"Found: {user.data.get_attribute('cn')}")

        """
        from ldap_core_shared.api.results import Result

        result = await self.limit(1).execute()
        if result.success:
            first_item = result.data[0] if result.data else None
            return Result.ok(first_item, result.execution_time_ms)
        return Result.fail(
            result.error,
            result.error_code,
            result.execution_time_ms,
            None,
        )

    async def count(self) -> Result[int]:
        """Count results without returning data.

        OPTIMIZATION METHOD: Counts matching entries with minimal data transfer
        by only retrieving a single attribute (cn).

        Returns:
            Result containing count of matching entries

        PERFORMANCE: Selects only minimal data to reduce network traffic
        while still getting accurate count of matching entries.

        Example:
            >>> user_count = await (ldap.query()
            ...     .users()
            ...     .in_department("Engineering")
            ...     .count())
            >>> if user_count.success:
            ...     print(f"Found {user_count.data} engineers")

        """
        from ldap_core_shared.api.results import Result

        result = await self.select("cn").execute()  # Select minimal data
        if result.success:
            return Result.ok(len(result.data), result.execution_time_ms)
        return Result.fail(result.error, result.error_code, result.execution_time_ms, 0)
