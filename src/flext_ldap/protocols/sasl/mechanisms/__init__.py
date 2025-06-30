"""SASL Authentication Mechanisms.

This package provides standard SASL authentication mechanism implementations
with comprehensive support for common SASL mechanisms used in LDAP and
other network protocols.

Available Mechanisms:
    - PLAIN: Simple username/password authentication (RFC 4616)
    - DIGEST-MD5: Challenge-response with MD5 digest (RFC 2831)
    - EXTERNAL: External authentication (certificates, etc.)
    - ANONYMOUS: Anonymous authentication (RFC 4505)
    - GSSAPI: Kerberos V5 authentication (RFC 4752) [future]
    - CRAM-MD5: Challenge-response with CRAM-MD5 [future]

Architecture:
    Each mechanism implements the SASLMechanism interface providing:
    - Challenge-response processing
    - Security layer negotiation
    - Mechanism-specific capabilities
    - Error handling and validation

Usage Example:
    >>> from flext_ldap.protocols.sasl.mechanisms import PlainMechanism
    >>> from flext_ldapasl.callback import SASLCallbackHandler
    >>>
    >>> callback = SASLCallbackHandler(username="user", password="pass")
    >>> mechanism = PlainMechanism(callback)
    >>> response = mechanism.get_initial_response()

References:
    - RFC 4422: Simple Authentication and Security Layer (SASL)
    - RFC 4616: The PLAIN Simple Authentication and Security Layer (SASL) Mechanism
    - RFC 2831: Using Digest Authentication as a SASL Mechanism
    - RFC 4505: Anonymous Simple Authentication and Security Layer (SASL) Mechanism
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_ldapasl.mechanism import BaseSASLMechanism

# Import all available mechanisms
try:
    from flext_ldapasl.mechanisms.plain import (  # type: ignore[import-not-found]
        PlainMechanism,
    )
except ImportError:
    PlainMechanism = None  # type: ignore

try:
    from flext_ldapasl.mechanisms.digest_md5 import (  # type: ignore[import-not-found]
        DigestMD5Mechanism,
    )
except ImportError:
    DigestMD5Mechanism = None  # type: ignore

try:
    from flext_ldapasl.mechanisms.external import (  # type: ignore[import-not-found]
        ExternalMechanism,
    )
except ImportError:
    ExternalMechanism = None  # type: ignore

try:
    from flext_ldapasl.mechanisms.anonymous import (  # type: ignore[import-not-found]
        AnonymousMechanism,
    )
except ImportError:
    AnonymousMechanism = None  # type: ignore

# Build exports list based on available mechanisms
__all__ = []

if PlainMechanism is not None:
    __all__.append("PlainMechanism")

if DigestMD5Mechanism is not None:
    __all__.append("DigestMD5Mechanism")

if ExternalMechanism is not None:
    __all__.append("ExternalMechanism")

if AnonymousMechanism is not None:
    __all__.append("AnonymousMechanism")


def get_available_mechanisms() -> list[str]:
    """Get list of available mechanism names.

    Returns:
        List of mechanism names that are implemented
    """
    mechanisms = []

    if PlainMechanism is not None:
        mechanisms.append("PLAIN")
    if DigestMD5Mechanism is not None:
        mechanisms.append("DIGEST-MD5")
    if ExternalMechanism is not None:
        mechanisms.append("EXTERNAL")
    if AnonymousMechanism is not None:
        mechanisms.append("ANONYMOUS")

    return mechanisms


def get_mechanism_class(mechanism_name: str) -> type[BaseSASLMechanism] | None:
    """Get mechanism class by name.

    Args:
        mechanism_name: Name of mechanism

    Returns:
        Mechanism class or None if not available
    """
    mechanism_map = {
        "PLAIN": PlainMechanism,
        "DIGEST-MD5": DigestMD5Mechanism,
        "EXTERNAL": ExternalMechanism,
        "ANONYMOUS": AnonymousMechanism,
    }

    return mechanism_map.get(mechanism_name.upper())


# TODO: Integration points for additional SASL mechanisms:
#
# 1. GSSAPI (Kerberos V5):
#    - Kerberos ticket handling
#    - GSS-API integration
#    - Mutual authentication
#    - Delegation support
#
# 2. CRAM-MD5:
#    - Challenge-response with HMAC-MD5
#    - Simple implementation
#    - Legacy compatibility
#
# 3. SCRAM-SHA-1/SHA-256:
#    - Salted Challenge Response Authentication Mechanism
#    - Modern password-based authentication
#    - Channel binding support
#
# 4. OAUTHBEARER:
#    - OAuth 2.0 bearer token authentication
#    - Modern token-based auth
#    - API integration
#
# 5. Mechanism Testing Framework:
#    - Unit tests for all mechanisms
#    - Interoperability testing
#    - Security validation
#    - Performance benchmarks
