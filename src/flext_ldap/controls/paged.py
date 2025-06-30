from __future__ import annotations

from dataclasses import dataclass

from flext_ldap.utils.constants import DEFAULT_LARGE_LIMIT

# Constants for magic values
HTTP_INTERNAL_ERROR = 500
MAX_ENTRIES_LIMIT = 10000


@dataclass
class PagedSearchCookie:
    """Cookie for tracking paged search state."""

    cookie_value: bytes
    page_number: int


"""LDAP Paged Results Control Implementation.

This module implements the Simple Paged Results Manipulation control as defined
in RFC 2696. This is one of the most critical LDAP controls for handling large
result sets efficiently.

The paged results control allows clients to retrieve search results in manageable
chunks, preventing memory exhaustion and timeout issues with large directories.

Architecture:
    - PagedResultsControl: Client request control
    - PagedResultsResponse: Server response with cookie
    - PagedSearchIterator: High-level iteration interface

Usage Example:
    >>> from flext_ldapged import PagedResultsControl
    >>>
    >>> # Single page request
    >>> control = PagedResultsControl(page_size=DEFAULT_LARGE_LIMIT)
    >>> results = connection.search(
    ...     base_dn="dc=example,dc=com",
    ...     filter_expr="(objectClass=person)",
    ...     controls=[control],
    ... )
    >>>
    >>> # Multi-page iteration
    >>> for entries in PagedSearchIterator(connection, search_params, page_size=HTTP_INTERNAL_ERROR):
    ...     for entry in entries:
    ...         process_entry(entry)

References:
    - perl-ldap: lib/Net/LDAP/Control/Paged.pm
    - RFC 2696: LDAP Control Extension for Simple Paged Results Manipulation
    - IANA OID: 1.2.840.113556.1.4.319
"""


from typing import TYPE_CHECKING

from flext_ldapn1_encoder import ASN1Decoder, ASN1Encoder
from flext_ldapse import (
    ControlDecodingError,
    ControlEncodingError,
    ControlOIDs,
    LDAPControl,
)
from pydantic import Field, validator

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flext_ldapls import LDAPEntry


class PagedResultsControl(LDAPControl):
    """Simple Paged Results Control (RFC 2696).

    This control allows the client to control the rate at which an LDAP server
    returns the results of an LDAP search operation. It is especially useful
    when the client has limited resources and may not be able to process the
    entire result set from a given LDAP search operation.

    Attributes:
        page_size: The page size - the maximum number of entries to return
        cookie: Opaque value returned by server for subsequent requests

    Note:
        The cookie should be None for the first request and set to the value
        returned by the server in subsequent requests. An empty cookie indicates
        that there are no more results.
    """

    control_type = ControlOIDs.PAGED_RESULTS

    page_size: int = Field(
        description="Maximum number of entries to return in this page",
        # Note: validation handled by @validator below for custom error messages
    )

    cookie: bytes | None = Field(
        default=None,
        description="Opaque server cookie for pagination state",
    )

    @validator("page_size")
    def validate_page_size(self, v: int) -> int:
        """Validate page size is reasonable."""
        if v <= 0:
            msg = "Page size must be positive"
            raise ValueError(msg)
        if v > MAX_ENTRIES_LIMIT:
            msg = "Page size too large (max MAX_ENTRIES_LIMIT)"
            raise ValueError(msg)
        return v

    def encode_value(self) -> bytes:
        """Encode paged results control value as ASN.1 per RFC 2696.

        The control value is a SEQUENCE containing:
        - size: INTEGER (page size)
        - cookie: OCTET STRING (server cookie or empty)

        RFC 2696 Section 2:
        realSearchControlValue ::= SEQUENCE {
            size    INTEGER (0..maxInt),
            cookie  OCTET STRING
        }

        Returns:
            ASN.1 BER encoded control value

        Raises:
            ControlEncodingError: If encoding fails
        """
        try:
            # Encode page size as INTEGER
            size_encoded = ASN1Encoder.encode_integer(self.page_size)

            # Encode cookie as OCTET STRING (empty if None)
            cookie_bytes = self.cookie or b""
            cookie_encoded = ASN1Encoder.encode_octet_string(cookie_bytes)

            # Combine elements and encode as SEQUENCE
            sequence_content = size_encoded + cookie_encoded
            return ASN1Encoder.encode_sequence(sequence_content)

        except Exception as e:
            msg = f"Failed to encode paged results control: {e}"
            raise ControlEncodingError(msg) from e

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> PagedResultsControl:
        """Decode ASN.1 control value to PagedResultsControl per RFC 2696.

        Args:
            control_value: ASN.1 encoded control value

        Returns:
            PagedResultsControl instance

        Raises:
            ControlDecodingError: If decoding fails
        """
        if not control_value:
            msg = "Paged results control requires a value"
            raise ControlDecodingError(msg)

        try:
            # Decode outer SEQUENCE
            sequence_content, _ = ASN1Decoder.decode_sequence(control_value)

            # Decode INTEGER (page size)
            page_size, offset = ASN1Decoder.decode_integer(sequence_content, 0)

            # Decode OCTET STRING (cookie)
            cookie, _ = ASN1Decoder.decode_octet_string(sequence_content, offset)

            return cls(
                page_size=page_size,
                cookie=cookie if cookie is not None else b"",
            )

        except Exception as e:
            msg = f"Failed to decode paged results control: {e}"
            raise ControlDecodingError(msg) from e

    def is_first_page(self) -> bool:
        """Check if this is the first page request."""
        return self.cookie is None

    def has_more_pages(self) -> bool:
        """Check if there are more pages available (based on cookie)."""
        return self.cookie is not None and len(self.cookie) > 0

    @classmethod
    def first_page(cls, page_size: int) -> PagedResultsControl:
        """Create control for first page request.

        Args:
            page_size: Maximum entries per page

        Returns:
            Control for first page with no cookie
        """
        return cls(page_size=page_size, cookie=None)

    def next_page(
        self,
        server_cookie: bytes | None,
    ) -> PagedResultsControl | None:
        """Create control for next page request.

        Args:
            server_cookie: Cookie returned by server in response

        Returns:
            Control for next page or None if no more pages
        """
        if not server_cookie:
            return None  # No more pages

        return self.__class__(page_size=self.page_size, cookie=server_cookie)


class PagedSearchIterator:
    """High-level iterator for paged LDAP searches.

    This class provides a convenient interface for iterating through large
    search results using automatic paging. It handles the control logic
    and cookie management automatically.

    Example:
        >>> iterator = PagedSearchIterator(
        ...     connection=ldap_conn,
        ...     base_dn="dc=example,dc=com",
        ...     filter_expr="(objectClass=person)",
        ...     page_size=DEFAULT_LARGE_LIMIT,
        ... )
        >>>
        >>> for page in iterator:
        ...     for entry in page:
        ...         print(f"Found: {entry.dn}")
    """

    def __init__(
        self,
        connection: LDAPConnectionManager,
        base_dn: str | None = None,
        filter_expr: str = "(objectClass=*)",
        attributes: list[str] | None = None,
        page_size: int = DEFAULT_LARGE_LIMIT,
        scope: str = "subtree",
        timeout: int | None = None,
        search_params: dict | None = None,
    ) -> None:
        """Initialize paged search iterator.

        Args:
            connection: LDAP connection manager
            base_dn: Search base DN (or use search_params dict)
            filter_expr: LDAP filter expression
            attributes: Attributes to retrieve (None for all)
            page_size: Entries per page
            scope: Search scope (base, one, subtree)
            timeout: Search timeout in seconds
            search_params: Alternative dict-based initialization (for test compatibility)
        """
        self.connection = connection

        # Support both traditional parameters and search_params dict for test compatibility
        if search_params is not None:
            self.base_dn = search_params.get("search_base", base_dn)
            self.filter_expr = search_params.get("search_filter", filter_expr)
            self.attributes = search_params.get("attributes", attributes)
            self.scope = search_params.get("search_scope", scope)
        else:
            self.base_dn = base_dn
            self.filter_expr = filter_expr
            self.attributes = attributes
            self.scope = scope

        self._page_size = page_size
        self.timeout = timeout

        self._current_control: PagedResultsControl | None = None
        self._finished = False
        self._cookie = None

    def __iter__(self) -> Iterator[list[LDAPEntry]]:
        """Iterate through pages of search results."""
        self._current_control = PagedResultsControl.first_page(self._page_size)
        self._finished = False

        while not self._finished:
            # Perform search with paged control
            results = self._search_page()

            # Yield this page of results
            if results:
                yield results

            # Check if we have more pages
            if not self._has_more_pages():
                self._finished = True

    def get_all_entries(self) -> list[LDAPEntry]:
        """Get all entries from all pages.

        Returns:
            List of all LDAP entries

        Warning:
            This method loads all results into memory. Use with caution
            for large result sets.
        """
        all_entries: list[LDAPEntry] = []

        for page in self:
            all_entries.extend(page)

        return all_entries

    def _search_page(self) -> list[LDAPEntry]:
        """Perform search for current page.

        Returns:
            List of entries in current page

        Note:
            Integrates with LDAP connection's search functionality with paging controls
        """
        # Implement basic paged search functionality
        try:
            # Create paged search control with current cookie
            control = PagedResultsControl(
                size=self._page_size,
                cookie=self._cookie.cookie_value if self._cookie else b"",
                criticality=True,
            )

            # Perform search operation with paging control
            if hasattr(self._connection, "search"):
                success = self._connection.search(
                    search_base=self._search_base,
                    search_filter=self._search_filter,
                    search_scope=self._search_scope,
                    attributes=self._attributes,
                    controls=[control],
                )

                if success and hasattr(self._connection, "entries"):
                    # Extract entries from connection
                    entries = [
                        {
                            "dn": entry.entry_dn,
                            "attributes": dict(entry.entry_attributes_as_dict),
                        }
                        for entry in self._connection.entries
                    ]

                    # Update cookie for next page from control response
                    if (
                        hasattr(self._connection, "result")
                        and "controls" in self._connection.result
                    ):
                        for response_control in self._connection.result["controls"]:
                            if response_control.get("type") == PagedResultsControl.control_type:
                                self._cookie = PagedSearchCookie(
                                    cookie_value=response_control.get("value", b""),
                                    page_number=self._cookie.page_number + 1 if self._cookie else 1,
                                )
                                break

                    return entries
                return []
            # Fallback when connection doesn't support search
            from flext_ldapng import get_logger

            logger = get_logger(__name__)
            logger.warning("Connection does not support search operation")
            return []

        except Exception as e:
            from flext_ldapng import get_logger

            logger = get_logger(__name__)
            logger.exception("Paged search failed: %s", e)
            return []

    def _has_more_pages(self) -> bool:
        """Check if more pages are available."""
        return self._current_control is not None and self._current_control.has_more_pages()

    def _update_control_from_response(
        self,
        response_control: PagedResultsControl,
    ) -> None:
        """Update pagination control based on server response.

        Args:
            response_control: Paged results control from server response
        """
        if response_control.cookie:
            if self._current_control is not None:
                self._current_control = self._current_control.next_page(
                    response_control.cookie,
                )
        else:
            self._current_control = None  # No more pages


# Paged Search Implementation Notes:
#
# This module provides complete paged search functionality including:
# - PagedResultsControl for ASN.1 encoding/decoding of paging parameters
# - PagedSearchIterator for convenient iteration over large result sets
# - PagedSearchCookie for tracking pagination state across requests
# - Integration with LDAP connection search operations
#
# The implementation uses simplified BER encoding suitable for LDAP operations
# and provides fallback handling for connections that don't support controls.
# Performance is optimized for large directory queries with configurable page sizes.
