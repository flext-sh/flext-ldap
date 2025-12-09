"""LDAP connection lifecycle service.

Encapsulates connection creation, binding, and teardown while delegating the
protocol surface to :class:`~flext_ldap.adapters.ldap3.Ldap3Adapter`. The
service keeps retries and optional heuristic server detection close to the
connection so callers interact with a single, typed entry point.

Business Rules:
    - Connection binding uses ldap3 library through Ldap3Adapter abstraction
    - Server type detection is optional and non-blocking after successful bind
    - Retry logic uses u.Reliability.retry() for transient failures
    - Parser defaults to FlextLdif().parser instance
    - Connection state is tracked via is_connected property

Audit Implications:
    - Successful connections log detected server type (if detection enabled)
    - Failed connections log error details for troubleshooting
    - Detection failures are logged at debug level (non-critical)

Architecture Notes:
    - Uses Railway-Oriented Programming pattern (FlextResult) for error handling
    - Adapter pattern encapsulates ldap3 protocol details
    - Single responsibility: connection lifecycle only (no CRUD operations)
    - Pydantic v2 frozen=False allows mutable connection state
"""

from __future__ import annotations

from flext_core import FlextConfig, r
from flext_ldif import FlextLdif, FlextLdifParser
from pydantic import ConfigDict

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.base import s
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import c
from flext_ldap.models import m
from flext_ldap.services.detection import FlextLdapServerDetector
from flext_ldap.utilities import u


class FlextLdapConnection(s[bool]):
    """Manage the LDAP connection lifecycle with typed ergonomics.

    The service wraps ``Ldap3Adapter`` to create/bind connections, optionally
    retry transient errors, and perform lightweight server detection after a
    successful bind. It is intentionally minimal so that callers can swap the
    adapter or parser during tests without changing behaviour at the API level.

    Business Rules:
        - Connection credentials (bind DN and password) are passed via
          :class:`m.Ldap.ConnectionConfig`, never stored in service state
        - Parser instance is resolved once at construction time and shared with
          the adapter for LDIF↔ldap3 conversions
        - Configuration defaults to ``FlextLdapConfig()`` when not provided,
          ensuring sensible LDAP defaults (port 389/636, timeout 30s)
        - ``frozen=False`` allows mutable ``_adapter`` state for connect/disconnect
          lifecycle while maintaining Pydantic model validation

    Audit Implications:
        - Connection establishment is logged at INFO level with server type
        - Failed connection attempts are logged at ERROR level with error details
        - Server detection results (success or failure) are logged for traceability
        - Service health checks via ``execute()`` report NOT_CONNECTED errors

    Architecture Notes:
        - Implements FlextService pattern via ``FlextLdapServiceBase[bool]``
        - Returns ``r[bool]`` for composable error handling
        - Adapter injection enables test doubles without modifying service logic
        - Uses ``PrivateAttr`` for ``_config`` to maintain base class compatibility

    Example:
        >>> connection = FlextLdapConnection()
        >>> config = m.Ldap.ConnectionConfig(
        ...     host="ldap.example.com",
        ...     bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        ...     bind_password="secret",
        ... )
        >>> result = connection.connect(config, auto_retry=True, max_retries=3)
        >>> if result.is_success:
        ...     # Connection established
        ...     assert connection.is_connected
        >>> connection.disconnect()

    """

    model_config = ConfigDict(
        frozen=False,  # Service needs mutable state for connection lifecycle
        extra="allow",
        arbitrary_types_allowed=True,
    )

    _adapter: Ldap3Adapter
    # Use class attribute (not PrivateAttr) to match FlextService pattern
    _config: FlextConfig | None = None

    def __init__(
        self,
        config: FlextLdapConfig | None = None,
        parser: FlextLdifParser | None = None,
    ) -> None:
        """Create a connection service with optional configuration and parser.

        Initializes the service with an LDAP configuration and parser, creating
        the underlying ``Ldap3Adapter`` that handles protocol-level operations.

        Business Rules:
            - Configuration is resolved once and stored in ``_config`` private
              attribute using ``object.__setattr__`` for Pydantic compatibility
            - Parser defaults to ``FlextLdif().parser`` instance to
              ensure consistent LDIF parsing across the ecosystem
            - Adapter is created eagerly (not lazy) to fail-fast on configuration
              errors during service instantiation
            - Parser is passed to adapter via kwargs dict for type-safe forwarding

        Audit Implications:
            - Service instantiation is not logged (no side effects until connect)
            - Configuration validation errors surface immediately at construction

        Args:
            config: Optional LDAP configuration; defaults to a new
                :class:`FlextLdapConfig` instance when omitted. Controls connection
                timeouts, TLS settings, and protocol options.
            parser: Optional LDIF parser to reuse for adapter conversions. When
                ``None``, the shared :class:`FlextLdif` singleton parser is used,
                ensuring consistent entry serialization.

        """
        super().__init__()
        # Create config instance if not provided
        resolved_config: FlextLdapConfig = (
            config if config is not None else FlextLdapConfig()
        )
        # Set attribute directly (no PrivateAttr needed, compatible with FlextService)
        self._config = resolved_config
        # Use default parser if not provided
        resolved_parser: FlextLdifParser = (
            parser if parser is not None else FlextLdif().parser
        )
        # Create adapter directly with parser as explicit parameter
        self._adapter = Ldap3Adapter(parser=resolved_parser)

    def connect(
        self,
        connection_config: m.Ldap.ConnectionConfig,
        *,
        auto_retry: bool = False,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        **_kwargs: str | float | bool | None,
    ) -> r[bool]:
        """Establish an LDAP connection with optional automatic retry.

        The adapter is asked to connect using the supplied configuration. When
        ``auto_retry`` is enabled, transient failures are retried using
        ``uretry`` semantics with exponential backoff.

        Business Rules:
            - Connection attempt is delegated entirely to ``Ldap3Adapter.connect()``
            - When ``auto_retry=True``, uses flext-core's Reliability.retry() which
              implements exponential backoff for transient network errors
            - Server type detection runs ONLY after successful connection (non-blocking)
            - On success, returns fresh ``r[bool].ok(True)`` (not adapter's result)
            - On failure, returns adapter's failure result unchanged for error propagation
            - ``_kwargs`` absorbs extra arguments for future extensibility

        Audit Implications:
            - Connection success triggers INFO log with detected server type
            - Connection failure is logged at ERROR level with adapter error details
            - Retry attempts are logged by uretry()
            - Server detection failures are logged at DEBUG (non-critical operation)

        Args:
            connection_config: Connection parameters including host, port, and
                bind credentials. See :class:`m.Ldap.ConnectionConfig`.
            auto_retry: When ``True``, retry transient failures using
                ``max_retries`` and ``retry_delay``. Defaults to ``False``.
            max_retries: Maximum retry attempts when ``auto_retry`` is enabled.
                Defaults to 3. Only effective when ``auto_retry=True``.
            retry_delay: Delay in seconds between retry attempts. Defaults to 1.0.
                uretry() may apply backoff multiplier.

        Returns:
            r[bool]: ``True`` when the connection is established and
            bind succeeds; otherwise a failure containing the adapter error
            message for troubleshooting.

        """
        # Modern Python 3.13: Use ternary expression for concise retry logic
        result: r[bool] = (
            u.Reliability.retry[bool](
                operation=lambda: self._adapter.connect(connection_config),
                max_attempts=max_retries,
                delay_seconds=retry_delay,
            )
            if auto_retry
            else self._adapter.connect(connection_config)
        )
        # Type narrowing: retry returns r[TResult] | TResult, ensure r[bool]
        if not isinstance(result, r):
            result = r[bool].ok(result)

        if result.is_success:
            self._detect_server_type_optional()
            return r[bool].ok(True)
        # Type narrowing: result is r[bool] at this point
        return result

    def disconnect(self) -> None:
        """Close the active LDAP connection if present.

        Delegates disconnection to the adapter, which handles unbinding from
        the LDAP server and releasing network resources gracefully.

        Business Rules:
            - Idempotent operation: safe to call when already disconnected
            - No return value (void): disconnection errors are absorbed
            - Delegates entirely to adapter's disconnect() for protocol handling
            - Does not clear service state (adapter can be reconnected)

        Audit Implications:
            - Disconnection is typically not logged (adapter handles if needed)
            - Resource cleanup happens synchronously before method returns
            - No failure notification to caller (graceful degradation pattern)

        """
        self._adapter.disconnect()

    @property
    def is_connected(self) -> bool:
        """Check if service has an active, bound LDAP connection.

        Queries the adapter's connection state to determine if operations
        can be performed. This property does not verify server reachability.

        Business Rules:
            - Delegates to adapter's is_connected property (no additional logic)
            - Returns cached state; does not perform network round-trip
            - State reflects last known connection status (may be stale)
            - Use before operations to avoid unnecessary error handling

        Audit Implications:
            - Read-only property with no logging or side effects
            - Used by ``execute()`` health check for service status reporting

        Returns:
            bool: ``True`` if connection is established and bound; ``False``
            if disconnected or never connected.

        """
        return self._adapter.is_connected

    @property
    def adapter(self) -> Ldap3Adapter:
        """Get the underlying ldap3 adapter for direct protocol access.

        Exposes the adapter for advanced use cases requiring direct ldap3
        operations not exposed through the service's public methods.

        Business Rules:
            - Returns the same adapter instance used by service methods
            - Modifications to adapter state affect service behavior
            - Caller assumes responsibility for connection state consistency
            - Primarily used by FlextLdapOperations for CRUD operations

        Audit Implications:
            - Direct adapter access bypasses service-level logging
            - Operations performed via adapter are still logged by adapter itself
            - Useful for testing and advanced integration scenarios

        Returns:
            Ldap3Adapter: The adapter instance managing the ldap3 connection.

        """
        return self._adapter

    def _detect_server_type_optional(self) -> None:
        """Attempt automatic server type detection after successful connection.

        Uses ``FlextLdapServerDetector`` to identify the LDAP server vendor
        (OpenLDAP, Oracle OID/OUD, AD, etc.) by querying the RootDSE. Detection
        is non-blocking and failures do not affect connection status.

        Business Rules:
            - Detection is OPTIONAL: failures do not cause connect() to fail
            - Requires active connection; exits early if connection is None
            - Creates fresh ``FlextLdapServerDetector`` instance per detection
            - Detection result is logged but not stored in service state
            - Called automatically by ``connect()`` on successful bind

        Audit Implications:
            - Successful detection logged at INFO level with server type string
            - Failed detection logged at DEBUG level (non-critical, expected for
              servers with restricted RootDSE access)
            - Operation name ``CONNECT`` used in logs for correlation with
              connection establishment events

        Note:
            This is an internal method (prefixed with ``_``) called automatically
            by ``connect()``. External callers should not invoke directly.

        """
        connection = self._adapter.connection
        if not connection:
            return

        detector = FlextLdapServerDetector()
        detection_result: r[str] = detector.detect_from_connection(connection)

        if detection_result.is_success:
            self.logger.info(
                "Server type detected automatically",
                operation=c.Ldap.LdapOperationNames.CONNECT,
                detected_server_type=detection_result.unwrap(),
            )
        else:
            self.logger.debug(
                "Server type detection failed (non-critical)",
                operation=c.Ldap.LdapOperationNames.CONNECT,
                error=str(detection_result.error) if detection_result.error else "",
            )

    def execute(self, **_kwargs: str | float | bool | None) -> r[bool]:
        """Execute service health check for FlextService pattern compliance.

        Implements the ``FlextService.execute()`` contract to report service
        health status. Returns success if connected, failure with standard
        error message if not.

        Business Rules:
            - Implements FlextService abstract method for service orchestration
            - Health is determined solely by ``is_connected`` property
            - Does not attempt reconnection or network round-trip
            - Error message uses ``c.Ldap.ErrorStrings.NOT_CONNECTED``
              for consistent error handling across the ecosystem
            - ``_kwargs`` absorbs extra arguments for interface compatibility

        Audit Implications:
            - Can be called periodically by service orchestrators for monitoring
            - Failure result contains NOT_CONNECTED error for diagnostics
            - No logging performed (lightweight health check)

        Args:
            **_kwargs: Absorbed keyword arguments for interface compatibility.
                Not used by this implementation.

        Returns:
            r[bool]: ``ok(True)`` if connection is active and bound;
            ``fail(NOT_CONNECTED)`` if disconnected or never connected.

        """
        # Create results
        if self.is_connected:
            return r[bool].ok(True)
        return r[bool].fail(str(c.Ldap.ErrorStrings.NOT_CONNECTED))
