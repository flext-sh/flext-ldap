"""Test constants for flext-ldap - complementary to src/flext_ldap/constants.py."""

from __future__ import annotations

from typing import Final

from flext_ldap.constants import FlextLdapConstants


class FlextLdapTestConstants:
    """Test-specific constants that complement FlextLdapConstants.

    Rules:
        - NUNCA duplicar constantes de src/
        - Apenas constantes específicas para testes
        - Fixtures, mocks, test data
        - Referenciar FlextLdapConstants para valores de produção
    """

    class Fixtures:
        """Fixture-related test constants."""

        # Valores de teste específicos (não duplicar de src/)
        SAMPLE_DN: Final[str] = "cn=test,dc=example,dc=com"
        SAMPLE_UID: Final[str] = "testuser"

        # Referência a constantes de produção
        DEFAULT_STATUS: Final[FlextLdapConstants.Domain.Status] = (
            FlextLdapConstants.Domain.Status.ACTIVE
        )

    class Mocks:
        """Mock-related test constants."""

        MOCK_SERVER_RESPONSE: Final[dict[str, str]] = {
            "status": "ok",
            "code": "200",
        }

    class Servers:
        """Server-specific test constants (para quirks)."""

        class OUD:
            """OUD server test constants."""

            SAMPLE_ACL: Final[str] = "access to * by * read"

        class OID:
            """OID server test constants."""

            SAMPLE_ACL: Final[str] = "aci: (target=*)"
