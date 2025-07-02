"""LDAP Referral Handling Module.

This module provides comprehensive LDAP referral processing following
perl-ldap patterns with enterprise-grade referral chasing, rebind
authentication, and automatic server redirection capabilities.

Referral handling enables automatic following of LDAP referrals to
other servers, essential for distributed directory environments and
multi-server LDAP deployments with proper authentication and security.

Architecture:
    - ReferralHandler: Main referral processing and coordination
    - ReferralChaser: Automatic referral following with rebind support
    - ReferralAuthenticator: Authentication handling for referral servers
    - ReferralPolicy: Configuration and policy management for referrals

Usage Example:
    >>> from ldap_core_shared.referrals import ReferralHandler
    >>>
    >>> # Automatic referral handling with authentication
    >>> referral_handler = ReferralHandler(
    ...     max_referral_depth=5,
    ...     rebind_credentials={"binddn": "cn=admin", "password": "secret"}
    ... )
    >>>
    >>> # Configure on connection
    >>> connection.set_referral_handler(referral_handler)
    >>>
    >>> # Operations automatically follow referrals
    >>> results = connection.search("ou=users,dc=example,dc=com", "(uid=john)")
    >>> # Automatically follows referrals to other servers if needed

References:
    - perl-ldap: lib/Net/LDAP.pod (referral handling, lines 456-478)
    - RFC 4511: LDAP Protocol Specification (referral processing)
    - Enterprise referral handling patterns

"""

from typing import TYPE_CHECKING

from ldap_core_shared.referrals.chaser import ReferralChaser, ReferralCredentials

# Import referral components
from ldap_core_shared.referrals.handler import ReferralHandler, ReferralResult

__all__ = [
    "ReferralChaser",
    "ReferralCredentials",
    # Core referral handling
    "ReferralHandler",
    "ReferralResult",
]
