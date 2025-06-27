"""LDAP URL Parsing and Manipulation Utilities.

This module provides comprehensive LDAP URL processing following RFC 4516
with perl-ldap compatibility patterns for URL parsing, validation, manipulation,
and construction of LDAP Uniform Resource Locators.

LDAP URLs provide a standard way to represent LDAP search operations and
connection parameters in a portable format, essential for configuration,
bookmarks, and cross-platform directory integration.

Architecture:
    - LDAPUrl: Main URL representation and manipulation class
    - URLComponents: Individual URL component management
    - URLValidator: URL validation and compliance checking
    - URLBuilder: Dynamic URL construction utilities

Usage Example:
    >>> from ldap_core_shared.utilities.url import LDAPUrl
    >>>
    >>> # Parse existing LDAP URL
    >>> url = LDAPUrl("ldap://server.example.com:389/ou=users,dc=example,dc=com?cn,mail?sub?(cn=john*)")
    >>>
    >>> # Access URL components
    >>> print(f"Server: {url.hostname}:{url.port}")
    >>> print(f"Base DN: {url.base_dn}")
    >>> print(f"Filter: {url.filter}")
    >>>
    >>> # Modify URL components
    >>> url.set_filter("(objectClass=person)")
    >>> url.add_attribute("telephoneNumber")
    >>>
    >>> # Generate modified URL
    >>> modified_url = str(url)

References:
    - perl-ldap: lib/Net/LDAP/Util.pm (ldap_url_parse)
    - RFC 4516: LDAP Uniform Resource Locator
    - RFC 3986: URI Generic Syntax
    - URL encoding and component handling standards
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from urllib.parse import quote, unquote, urlparse, urlunparse

from pydantic import BaseModel, Field


class LDAPScope(Enum):
    """LDAP search scope values."""

    BASE = "base"
    ONE = "one"
    SUB = "sub"
    SUBORDINATE = "subordinate"


class LDAPUrlScheme(Enum):
    """LDAP URL schemes."""

    LDAP = "ldap"
    LDAPS = "ldaps"
    LDAPI = "ldapi"


class URLComponents(BaseModel):
    """Individual components of an LDAP URL."""

    # Basic URL components
    scheme: LDAPUrlScheme = Field(description="URL scheme (ldap, ldaps, ldapi)")

    hostname: str | None = Field(default=None, description="Server hostname")

    port: int | None = Field(default=None, description="Server port number")

    # LDAP-specific components
    base_dn: str = Field(default="", description="Base distinguished name")

    attributes: list[str] = Field(
        default_factory=list,
        description="Attributes to retrieve",
    )

    scope: LDAPScope | None = Field(default=None, description="Search scope")

    filter: str = Field(default="", description="LDAP search filter")

    extensions: dict[str, str] = Field(
        default_factory=dict,
        description="URL extensions",
    )

    # Additional components
    query_params: dict[str, str] = Field(
        default_factory=dict,
        description="Additional query parameters",
    )

    fragment: str | None = Field(default=None, description="URL fragment")

    def get_default_port(self) -> int | None:
        """Get default port for scheme."""
        port_mapping = {
            LDAPUrlScheme.LDAP: 389,
            LDAPUrlScheme.LDAPS: 636,
            LDAPUrlScheme.LDAPI: None,  # Unix sockets don't use ports
        }
        return port_mapping.get(self.scheme)

    def is_secure_scheme(self) -> bool:
        """Check if URL scheme is secure."""
        return self.scheme == LDAPUrlScheme.LDAPS

    def requires_hostname(self) -> bool:
        """Check if URL scheme requires hostname."""
        return self.scheme in {LDAPUrlScheme.LDAP, LDAPUrlScheme.LDAPS}


class LDAPUrl:
    """LDAP URL representation and manipulation.

    This class provides comprehensive LDAP URL parsing, validation, and
    manipulation capabilities following RFC 4516 standards with perl-ldap
    compatibility patterns.

    Example:
        >>> # Parse complete LDAP URL
        >>> url = LDAPUrl("ldap://server.example.com:389/ou=users,dc=example,dc=com?cn,mail?sub?(cn=john*)")
        >>>
        >>> # Access components
        >>> print(f"Host: {url.hostname}")
        >>> print(f"Port: {url.port}")
        >>> print(f"Base: {url.base_dn}")
        >>> print(f"Attributes: {url.attributes}")
        >>> print(f"Scope: {url.scope}")
        >>> print(f"Filter: {url.filter}")
        >>>
        >>> # Modify components
        >>> url.set_base_dn("ou=groups,dc=example,dc=com")
        >>> url.set_filter("(objectClass=groupOfNames)")
        >>> url.add_attribute("member")
        >>>
        >>> # Generate URL string
        >>> new_url = str(url)
    """

    def __init__(self, url: str | None = None) -> None:
        """Initialize LDAP URL.

        Args:
            url: LDAP URL string to parse (optional)
        """
        self._components = URLComponents(scheme=LDAPUrlScheme.LDAP)

        if url:
            self._parse_url(url)

    def _parse_url(self, url: str) -> None:
        """Parse LDAP URL string into components.

        Args:
            url: LDAP URL string to parse
        """
        # Basic URL parsing
        parsed = urlparse(url)

        # Validate and set scheme
        if parsed.scheme not in {"ldap", "ldaps", "ldapi"}:
            msg = f"Invalid LDAP URL scheme: {parsed.scheme}"
            raise ValueError(msg)

        self._components.scheme = LDAPUrlScheme(parsed.scheme)

        # Set hostname and port
        if self._components.requires_hostname():
            if not parsed.hostname:
                msg = f"Hostname required for {parsed.scheme} URLs"
                raise ValueError(msg)
            self._components.hostname = parsed.hostname

        self._components.port = parsed.port

        # Parse LDAP-specific path components
        if parsed.path:
            self._parse_ldap_path(parsed.path)

        # Parse query parameters (extensions)
        if parsed.query:
            self._parse_query_params(parsed.query)

        # Set fragment
        self._components.fragment = parsed.fragment or None

    def _parse_ldap_path(self, path: str) -> None:
        """Parse LDAP path component.

        Args:
            path: URL path containing LDAP components
        """
        # Remove leading slash
        path = path.removeprefix("/")

        # Split LDAP URL components: dn?attributes?scope?filter
        parts = path.split("?")

        # Base DN (first part)
        if parts and parts[0]:
            self._components.base_dn = unquote(parts[0])

        # Attributes (second part)
        if len(parts) > 1 and parts[1]:
            attributes = parts[1].split(",")
            self._components.attributes = [
                unquote(attr.strip()) for attr in attributes if attr.strip()
            ]

        # Scope (third part)
        if len(parts) > 2 and parts[2]:
            scope_str = unquote(parts[2]).lower()
            try:
                self._components.scope = LDAPScope(scope_str)
            except ValueError:
                msg = f"Invalid LDAP scope: {scope_str}"
                raise ValueError(msg)

        # Filter (fourth part)
        if len(parts) > 3 and parts[3]:
            self._components.filter = unquote(parts[3])

        # Extensions (additional parts)
        if len(parts) > 4:
            for extension_part in parts[4:]:
                if "=" in extension_part:
                    key, value = extension_part.split("=", 1)
                    self._components.extensions[unquote(key)] = unquote(value)
                else:
                    self._components.extensions[unquote(extension_part)] = ""

    def _parse_query_params(self, query: str) -> None:
        """Parse query parameters.

        Args:
            query: URL query string
        """
        # Simple query parameter parsing
        for param in query.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                self._components.query_params[unquote(key)] = unquote(value)
            else:
                self._components.query_params[unquote(param)] = ""

    def to_url_string(self) -> str:
        """Convert LDAP URL components back to URL string.

        Returns:
            LDAP URL string
        """
        # Build basic URL components
        scheme = self._components.scheme.value

        if self._components.hostname:
            netloc = self._components.hostname
            if self._components.port is not None:
                netloc += f":{self._components.port}"
        else:
            netloc = ""

        # Build LDAP path
        path_parts = []

        # Base DN
        if self._components.base_dn:
            path_parts.append(quote(self._components.base_dn, safe=""))
        else:
            path_parts.append("")

        # Attributes
        if self._components.attributes:
            attrs = ",".join(
                quote(attr, safe="") for attr in self._components.attributes
            )
            path_parts.append(attrs)
        else:
            path_parts.append("")

        # Scope
        if self._components.scope:
            path_parts.append(self._components.scope.value)
        else:
            path_parts.append("")

        # Filter
        if self._components.filter:
            path_parts.append(quote(self._components.filter, safe=""))
        else:
            path_parts.append("")

        # Extensions
        for key, value in self._components.extensions.items():
            if value:
                path_parts.append(f"{quote(key, safe='')}={quote(value, safe='')}")
            else:
                path_parts.append(quote(key, safe=""))

        path = "/" + "?".join(path_parts)

        # Build query string
        query = ""
        if self._components.query_params:
            query_parts = []
            for key, value in self._components.query_params.items():
                if value:
                    query_parts.append(f"{quote(key)}={quote(value)}")
                else:
                    query_parts.append(quote(key))
            query = "&".join(query_parts)

        # Build fragment
        fragment = self._components.fragment or ""

        # Construct final URL
        return urlunparse((scheme, netloc, path, "", query, fragment))

    def validate(self) -> list[str]:
        """Validate LDAP URL components.

        Returns:
            List of validation errors
        """
        errors = []

        # Check scheme-specific requirements
        if self._components.requires_hostname() and not self._components.hostname:
            errors.append(f"Hostname required for {self._components.scheme.value} URLs")

        # Validate port range
        if self._components.port is not None:
            if not (1 <= self._components.port <= 65535):
                errors.append(f"Invalid port number: {self._components.port}")

        # Validate DN format (basic check)
        if self._components.base_dn:
            if not self._is_valid_dn_format(self._components.base_dn):
                errors.append(f"Invalid DN format: {self._components.base_dn}")

        # Validate filter format (basic check)
        if self._components.filter:
            if not self._is_valid_filter_format(self._components.filter):
                errors.append(f"Invalid filter format: {self._components.filter}")

        return errors

    def _is_valid_dn_format(self, dn: str) -> bool:
        """Basic DN format validation.

        Args:
            dn: Distinguished name to validate

        Returns:
            True if DN format appears valid
        """
        # Very basic DN validation - just check for typical patterns
        if not dn:
            return True  # Empty DN is valid

        # Must contain at least one attribute=value pair
        return "=" in dn and not dn.startswith("=") and not dn.endswith("=")

    def _is_valid_filter_format(self, filter_str: str) -> bool:
        """Basic filter format validation.

        Args:
            filter_str: LDAP filter to validate

        Returns:
            True if filter format appears valid
        """
        if not filter_str:
            return True  # Empty filter is valid

        # Must be wrapped in parentheses
        return filter_str.startswith("(") and filter_str.endswith(")")

    # Component access methods
    def get_scheme(self) -> LDAPUrlScheme:
        """Get URL scheme."""
        return self._components.scheme

    def set_scheme(self, scheme: LDAPUrlScheme | str) -> None:
        """Set URL scheme."""
        if isinstance(scheme, str):
            scheme = LDAPUrlScheme(scheme)
        self._components.scheme = scheme

    @property
    def hostname(self) -> str | None:
        """Get hostname."""
        return self._components.hostname

    def set_hostname(self, hostname: str) -> None:
        """Set hostname."""
        self._components.hostname = hostname

    @property
    def port(self) -> int | None:
        """Get port number."""
        return self._components.port or self._components.get_default_port()

    def set_port(self, port: int) -> None:
        """Set port number."""
        if not (1 <= port <= 65535):
            msg = f"Invalid port number: {port}"
            raise ValueError(msg)
        self._components.port = port

    @property
    def base_dn(self) -> str:
        """Get base DN."""
        return self._components.base_dn

    def set_base_dn(self, base_dn: str) -> None:
        """Set base DN."""
        self._components.base_dn = base_dn

    @property
    def attributes(self) -> list[str]:
        """Get attribute list."""
        return self._components.attributes.copy()

    def set_attributes(self, attributes: list[str]) -> None:
        """Set attribute list."""
        self._components.attributes = attributes.copy()

    def add_attribute(self, attribute: str) -> None:
        """Add attribute to list."""
        if attribute not in self._components.attributes:
            self._components.attributes.append(attribute)

    def remove_attribute(self, attribute: str) -> bool:
        """Remove attribute from list.

        Returns:
            True if attribute was removed
        """
        try:
            self._components.attributes.remove(attribute)
            return True
        except ValueError:
            return False

    @property
    def scope(self) -> LDAPScope | None:
        """Get search scope."""
        return self._components.scope

    def set_scope(self, scope: LDAPScope | str) -> None:
        """Set search scope."""
        if isinstance(scope, str):
            scope = LDAPScope(scope)
        self._components.scope = scope

    @property
    def filter(self) -> str:
        """Get search filter."""
        return self._components.filter

    def set_filter(self, filter_str: str) -> None:
        """Set search filter."""
        self._components.filter = filter_str

    @property
    def extensions(self) -> dict[str, str]:
        """Get URL extensions."""
        return self._components.extensions.copy()

    def add_extension(self, name: str, value: str = "") -> None:
        """Add URL extension."""
        self._components.extensions[name] = value

    def remove_extension(self, name: str) -> bool:
        """Remove URL extension.

        Returns:
            True if extension was removed
        """
        return self._components.extensions.pop(name, None) is not None

    # Utility methods
    def is_secure(self) -> bool:
        """Check if URL uses secure scheme."""
        return self._components.is_secure_scheme()

    def get_connection_params(self) -> dict[str, Any]:
        """Get connection parameters from URL.

        Returns:
            Dictionary with connection parameters
        """
        params = {
            "scheme": self._components.scheme.value,
        }

        if self._components.hostname:
            params["hostname"] = self._components.hostname

        if self._components.port is not None:
            params["port"] = str(self._components.port)
        else:
            default_port = self._components.get_default_port()
            if default_port:
                params["port"] = str(default_port)

        return params

    def get_search_params(self) -> dict[str, Any]:
        """Get search parameters from URL.

        Returns:
            Dictionary with search parameters
        """
        params: dict[str, Any] = {}

        if self._components.base_dn:
            params["base_dn"] = self._components.base_dn

        if self._components.attributes:
            params["attributes"] = self._components.attributes

        if self._components.scope:
            params["scope"] = self._components.scope.value

        if self._components.filter:
            params["filter"] = self._components.filter

        return params

    def copy(self) -> LDAPUrl:
        """Create copy of LDAP URL."""
        new_url = LDAPUrl()
        new_url._components = URLComponents(**self._components.dict())
        return new_url

    def __str__(self) -> str:
        """Convert to URL string."""
        return self.to_url_string()

    def __repr__(self) -> str:
        """String representation."""
        return f"LDAPUrl('{self.to_url_string()}')"

    def __eq__(self, other: object) -> bool:
        """Check URL equality."""
        if not isinstance(other, LDAPUrl):
            return False
        return self._components == other._components

    def __hash__(self) -> int:
        """Hash for LDAPUrl."""
        return hash(
            (
                self._components.scheme,
                self._components.hostname,
                self._components.port,
                self._components.base_dn,
                tuple(self._components.attributes),
                self._components.scope,
                self._components.filter,
                tuple(sorted(self._components.extensions.items())),
            ),
        )


# Utility functions
def parse_ldap_url(url: str) -> LDAPUrl:
    """Parse LDAP URL string.

    Args:
        url: LDAP URL string

    Returns:
        Parsed LDAPUrl object
    """
    return LDAPUrl(url)


def build_ldap_url(
    hostname: str,
    port: int | None = None,
    base_dn: str = "",
    attributes: list[str] | None = None,
    scope: LDAPScope | str | None = None,
    filter_str: str = "",
    scheme: LDAPUrlScheme | str = LDAPUrlScheme.LDAP,
    **extensions: Any,
) -> LDAPUrl:
    """Build LDAP URL from components.

    Args:
        hostname: Server hostname
        port: Server port
        base_dn: Base distinguished name
        attributes: Attributes to retrieve
        scope: Search scope
        filter_str: Search filter
        scheme: URL scheme
        **extensions: URL extensions

    Returns:
        Constructed LDAPUrl object
    """
    url = LDAPUrl()

    if isinstance(scheme, str):
        scheme = LDAPUrlScheme(scheme)
    url.set_scheme(scheme)

    url.set_hostname(hostname)

    if port is not None:
        url.set_port(port)

    url.set_base_dn(base_dn)

    if attributes:
        url.set_attributes(attributes)

    if scope:
        url.set_scope(scope)

    if filter_str:
        url.set_filter(filter_str)

    for name, value in extensions.items():
        url.add_extension(name, str(value))

    return url


def validate_ldap_url(url: str) -> list[str]:
    """Validate LDAP URL format.

    Args:
        url: LDAP URL string to validate

    Returns:
        List of validation errors
    """
    try:
        ldap_url = LDAPUrl(url)
        return ldap_url.validate()
    except Exception as e:
        return [f"URL parsing error: {e}"]


def normalize_ldap_url(url: str) -> str:
    """Normalize LDAP URL format.

    Args:
        url: LDAP URL string to normalize

    Returns:
        Normalized LDAP URL string
    """
    try:
        ldap_url = LDAPUrl(url)
        return str(ldap_url)
    except Exception:
        return url  # Return original if parsing fails


def extract_connection_info(url: str) -> dict[str, Any]:
    """Extract connection information from LDAP URL.

    Args:
        url: LDAP URL string

    Returns:
        Dictionary with connection information
    """
    try:
        ldap_url = LDAPUrl(url)
        return ldap_url.get_connection_params()
    except Exception:
        return {}


def extract_search_info(url: str) -> dict[str, Any]:
    """Extract search information from LDAP URL.

    Args:
        url: LDAP URL string

    Returns:
        Dictionary with search information
    """
    try:
        ldap_url = LDAPUrl(url)
        return ldap_url.get_search_params()
    except Exception:
        return {}


# TODO: Integration points for implementation:
#
# 1. Advanced URL Validation:
#    - Comprehensive DN syntax validation
#    - LDAP filter syntax validation
#    - Extension validation and processing
#
# 2. URL Security and Encoding:
#    - Proper URL encoding/decoding handling
#    - Security validation for URL components
#    - Injection prevention and sanitization
#
# 3. Extended URL Features:
#    - Support for additional URL extensions
#    - Custom attribute and scope handling
#    - Vendor-specific URL extensions
#
# 4. Integration with LDAP Operations:
#    - Direct conversion to LDAP operation parameters
#    - Integration with connection management
#    - Search operation parameter extraction
#
# 5. Performance Optimization:
#    - Efficient URL parsing and manipulation
#    - Caching of parsed URL components
#    - Optimized string generation
#
# 6. Compatibility and Standards:
#    - Full RFC 4516 compliance
#    - Perl-ldap compatibility patterns
#    - Cross-platform URL handling
#
# 7. Testing Requirements:
#    - Unit tests for all URL functionality
#    - Compliance tests with RFC 4516
#    - Edge case and error handling tests
#    - Performance tests for URL processing
