"""LDAP connection lifecycle service.

Encapsulates connection creation, binding, and teardown while delegating the
protocol surface to :class:`~flext_ldap.adapters.ldap3.Ldap3Adapter`. The
service keeps retries and optional heuristic server detection close to the
connection so callers interact with a single, typed entry point.
"""

from __future__ import annotations

from flext_core import FlextResult, FlextUtilities
from flext_ldif import FlextLdif
from flext_ldif.services.parser import FlextLdifParser
from pydantic import ConfigDict, PrivateAttr

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.detection import FlextLdapServerDetector


class FlextLdapConnection(FlextLdapServiceBase[bool]):
    """Manage the LDAP connection lifecycle with typed ergonomics.

    The service wraps `Ldap3Adapter` to create/bind connections, optionally
    retry transient errors, and perform lightweight server detection after a
    successful bind. It is intentionally minimal so that callers can swap the
    adapter or parser during tests without changing behaviour at the API level.
    """

    model_config = ConfigDict(
        frozen=False,  # Service needs mutable state for connection lifecycle
        extra="allow",
        arbitrary_types_allowed=True,
    )

    _adapter: Ldap3Adapter
    _config: FlextLdapConfig = PrivateAttr()

    def __init__(
        self,
        config: FlextLdapConfig | None = None,
        parser: FlextLdifParser | None = None,
    ) -> None:
        """Create a connection service.

        Args:
            config: Optional LDAP configuration; defaults to a new
                :class:`FlextLdapConfig` instance when omitted.
            parser: Optional LDIF parser to reuse for adapter conversions. When
                ``None``, the shared :class:`FlextLdif` singleton parser is used.
        """
        super().__init__()
        # Create config instance if not provided
        resolved_config = config if config is not None else FlextLdapConfig()
        object.__setattr__(self, "_config", resolved_config)
        if parser is None:
            parser = FlextLdif.get_instance().parser
        # Create adapter directly
        self._adapter = Ldap3Adapter(parser=parser)

    def connect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        *,
        auto_retry: bool = False,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[bool]:
        """Establish an LDAP connection.

        The adapter is asked to connect using the supplied configuration. When
        ``auto_retry`` is enabled, transient failures are retried using
        ``FlextUtilities.Reliability.retry`` semantics.

        Args:
            connection_config: Connection parameters including host, port, and
                bind credentials.
            auto_retry: When ``True``, retry using ``max_retries`` and
                ``retry_delay``.
            max_retries: Maximum retry attempts when ``auto_retry`` is enabled.
            retry_delay: Delay (seconds) between retries.

        Returns:
            FlextResult[bool]: ``True`` when the connection is established;
            otherwise a failure describing the adapter error.
        """

        def attempt_connect() -> FlextResult[bool]:
            return self._adapter.connect(connection_config)

        result = (
            FlextUtilities.Reliability.retry(
                operation=attempt_connect,
                max_attempts=max_retries,
                delay_seconds=retry_delay,
            )
            if auto_retry
            else attempt_connect()
        )

        if result.is_success:
            self._detect_server_type_optional()
            return FlextResult[bool].ok(True)
        return result

    def disconnect(self) -> None:
        """Close the active LDAP connection if present."""
        self._adapter.disconnect()

    @property
    def is_connected(self) -> bool:
        """Check if service has active connection."""
        return self._adapter.is_connected

    @property
    def adapter(self) -> Ldap3Adapter:
        """Get underlying ldap3 adapter."""
        return self._adapter

    def _detect_server_type_optional(self) -> None:
        """Attempt automatic server type detection (optional, non-blocking)."""
        connection = self._adapter.connection
        if not connection:
            return

        detector = FlextLdapServerDetector()
        detection_result: FlextResult[str] = detector.detect_from_connection(connection)

        if detection_result.is_success:
            self.logger.info(
                "Server type detected automatically",
                operation=FlextLdapConstants.LdapOperationNames.CONNECT,
                detected_server_type=detection_result.unwrap(),
            )
        else:
            self.logger.debug(
                "Server type detection failed (non-critical)",
                operation=FlextLdapConstants.LdapOperationNames.CONNECT,
                error=str(detection_result.error) if detection_result.error else "",
            )

    def execute(self, **_kwargs: str | float | bool | None) -> FlextResult[bool]:
        """Execute service health check."""
        if self.is_connected:
            return FlextResult[bool].ok(True)
        return FlextResult[bool].fail(
            str(FlextLdapConstants.ErrorStrings.NOT_CONNECTED),
        )
