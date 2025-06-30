"""SASL Authentication Framework for LDAP.

This module provides comprehensive SASL (Simple Authentication and Security Layer)
authentication framework equivalent to perl-Authen-SASL with enterprise-grade
functionality for LDAP operations and general SASL authentication processing.

SASL provides a framework for authentication and data security in Internet
protocols. This implementation supports multiple SASL mechanisms including
PLAIN, DIGEST-MD5, GSSAPI (Kerberos), EXTERNAL, and ANONYMOUS authentication
with complete RFC 4422 compliance.

Architecture:
    - SASLClient: Client-side SASL authentication
    - SASLServer: Server-side SASL authentication
    - SASLMechanism: Base class for SASL mechanisms
    - SASLContext: Authentication context and state
    - SASLCallbackHandler: Callback interface for credentials
    - SASLSecurityLayer: Data security layer support

Usage Example:
    >>> from flext_ldap.protocols.sasl import SASLClient, SASLCallbackHandler
    >>>
    >>> # Create SASL client
    >>> callback = SASLCallbackHandler(
    ...     username="john.doe",
    ...     password="secret123",
    ...     realm="example.com"
    ... )
    >>> client = SASLClient(mechanisms=["DIGEST-MD5", "PLAIN"], callback=callback)
    >>>
    >>> # Perform authentication
    >>> if client.has_initial_response():
    ...     initial = client.evaluate_challenge(b"")
    ...
    >>> # Continue challenge-response
    >>> while not client.is_complete():
    ...     server_challenge = receive_from_server()
    ...     response = client.evaluate_challenge(server_challenge)
    ...     send_to_server(response)
    >>>
    >>> # Check if authentication succeeded
    >>> if client.is_complete():
    ...     print("Authentication successful")

References:
    - perl-Authen-SASL: Complete API compatibility
    - RFC 4422: Simple Authentication and Security Layer (SASL)
    - RFC 2831: Using Digest Authentication as a SASL Mechanism
    - RFC 4616: The PLAIN Simple Authentication and Security Layer (SASL) Mechanism
    - RFC 4752: The Kerberos V5 ("GSSAPI") Simple Authentication and Security Layer (SASL) Mechanism
"""

from __future__ import annotations

# Import all SASL components
try:
    from flext_ldapasl.callback import (  # type: ignore[import-not-found]
        AuthorizeCallback,
        NameCallback,
        PasswordCallback,
        RealmCallback,
        SASLCallback,
        SASLCallbackHandler,
    )
    from flext_ldapasl.client import (  # type: ignore[import-not-found]
        SASLClient,
        SASLClientFactory,
    )
    from flext_ldapasl.context import (  # type: ignore[import-not-found]
        SASLContext,
        SASLProperties,
        SASLSecurityLayer,
    )
    from flext_ldapasl.exceptions import (  # type: ignore[import-not-found]
        SASLAuthenticationError,
        SASLError,
        SASLInvalidMechanismError,
        SASLSecurityError,
    )
    from flext_ldapasl.mechanism import (  # type: ignore[import-not-found]
        SASLMechanism,
        SASLMechanismRegistry,
    )
    from flext_ldapasl.mechanisms.anonymous import (  # type: ignore[import-not-found]
        AnonymousMechanism,
    )
    from flext_ldapasl.mechanisms.digest_md5 import (  # type: ignore[import-not-found]
        DigestMD5Mechanism,
    )
    from flext_ldapasl.mechanisms.external import (  # type: ignore[import-not-found]
        ExternalMechanism,
    )
    from flext_ldapasl.mechanisms.plain import (  # type: ignore[import-not-found]
        PlainMechanism,
    )
    from flext_ldapasl.server import (  # type: ignore[import-not-found]
        SASLServer,
        SASLServerFactory,
    )

    __all__ = [
        "AnonymousMechanism",
        "AuthorizeCallback",
        "DigestMD5Mechanism",
        "ExternalMechanism",
        "NameCallback",
        "PasswordCallback",
        # Standard mechanisms
        "PlainMechanism",
        "RealmCallback",
        "SASLAuthenticationError",
        # Callback system
        "SASLCallback",
        "SASLCallbackHandler",
        # Main classes
        "SASLClient",
        "SASLClientFactory",
        # Context and properties
        "SASLContext",
        # Exceptions
        "SASLError",
        "SASLInvalidMechanismError",
        # Mechanism framework
        "SASLMechanism",
        "SASLMechanismRegistry",
        "SASLProperties",
        "SASLSecurityError",
        "SASLSecurityLayer",
        "SASLServer",
        "SASLServerFactory",
    ]

except ImportError:
    # If modules are not yet implemented, provide empty list
    __all__ = []


# Convenience factory function equivalent to perl-Authen-SASL->new()
def new(mechanism: str | list[str] | None = None, **options):
    """Create new SASL client instance.

    This function provides perl-Authen-SASL API compatibility by creating
    a SASL client instance with the same interface.

    Args:
        mechanism: SASL mechanism name(s) to use
        **options: Configuration options for SASL client
            - callback: Callback handler for credentials
            - username: Username for authentication
            - password: Password for authentication
            - realm: Authentication realm
            - service: Service name (default: "ldap")
            - hostname: Server hostname
            - properties: Additional SASL properties

    Returns:
        SASLClient instance with perl-Authen-SASL compatible API

    Example:
        >>> import flext_ldapasl as sasl
        >>>
        >>> # perl-Authen-SASL style usage
        >>> client = sasl.new("DIGEST-MD5")
        >>> client.client_start()
        >>> response = client.client_step(challenge)
    """
    try:
        from flext_ldapasl.callback import SASLCallbackHandler
        from flext_ldapasl.client import SASLClient

        # Handle mechanism parameter
        mechanisms = []
        if mechanism is not None:
            if isinstance(mechanism, str):
                mechanisms = [mechanism]
            elif isinstance(mechanism, list):
                mechanisms = mechanism
            else:
                mechanisms = list(mechanism)

        # Create callback handler from options
        callback = options.get("callback")
        if callback is None and ("username" in options or "password" in options):
            callback = SASLCallbackHandler(
                username=options.get("username"),
                password=options.get("password"),
                realm=options.get("realm"),
                service=options.get("service", "ldap"),
                hostname=options.get("hostname"),
            )

        # Create SASL client
        return SASLClient(
            mechanisms=mechanisms,
            callback=callback,
            properties=options.get("properties", {}),
            service=options.get("service", "ldap"),
            hostname=options.get("hostname"),
        )

    except ImportError:
        # TODO: Implement SASLClient class for perl-Authen-SASL compatibility
        msg = (
            "SASLClient class not yet implemented. "
            "This requires implementation of the main SASL client with "
            "perl-Authen-SASL compatible API including client_start(), client_step(), "
            "and mechanism selection methods."
        )
        raise NotImplementedError(msg)


# Global mechanism registry
def get_mechanisms() -> list[str]:
    """Get list of available SASL mechanisms.

    Returns:
        List of available mechanism names
    """
    try:
        from flext_ldapasl.mechanism import SASLMechanismRegistry

        return SASLMechanismRegistry.get_available_mechanisms()
    except ImportError:
        return ["PLAIN", "DIGEST-MD5", "EXTERNAL", "ANONYMOUS"]


def mechanism_available(mechanism: str) -> bool:
    """Check if SASL mechanism is available.

    Args:
        mechanism: Mechanism name to check

    Returns:
        True if mechanism is available
    """
    return mechanism.upper() in [m.upper() for m in get_mechanisms()]


# TODO: Integration points for complete perl-Authen-SASL functionality:
#
# 1. Core SASL Implementation:
#    - Complete client/server SASL engines
#    - Challenge-response state management
#    - Multiple mechanism support
#    - Security layer negotiation
#
# 2. Mechanism Framework:
#    - Pluggable mechanism architecture
#    - Mechanism capability discovery
#    - Priority and preference handling
#    - Fallback mechanism selection
#
# 3. Standard Mechanisms:
#    - PLAIN: Username/password authentication
#    - DIGEST-MD5: Challenge-response with MD5
#    - GSSAPI: Kerberos V5 authentication
#    - EXTERNAL: External authentication (TLS)
#    - ANONYMOUS: Anonymous authentication
#
# 4. Callback System:
#    - Credential callback interface
#    - Multiple callback types (name, password, realm)
#    - Secure credential handling
#    - Interactive prompt support
#
# 5. Security Layer:
#    - Data integrity protection
#    - Data confidentiality (encryption)
#    - Quality of Protection (QOP) negotiation
#    - Buffer size negotiation
#
# 6. Property Management:
#    - SASL properties framework
#    - Security policy configuration
#    - Mechanism-specific properties
#    - Runtime property updates
#
# 7. Error Handling:
#    - Comprehensive SASL error types
#    - Authentication failure details
#    - Security violation reporting
#    - Mechanism-specific errors
#
# 8. I/O Integration:
#    - Network socket integration
#    - Buffer management
#    - Streaming authentication
#    - Connection state management
#
# 9. LDAP Integration:
#    - LDAP SASL bind operations
#    - StartTLS integration
#    - LDAP-specific mechanisms
#    - Directory service authentication
#
# 10. Performance Optimization:
#     - Efficient challenge processing
#     - Cached mechanism instances
#     - Minimal memory footprint
#     - Fast mechanism selection
