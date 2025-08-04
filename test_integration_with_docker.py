#!/usr/bin/env python3
"""Teste de integração usando o fixture Docker LDAP."""

import asyncio

import pytest
from flext_ldap.ldap_infrastructure import (
    FlextLdapConnectionConfig,
    FlextLdapSimpleClient,
)


@pytest.mark.integration
def test_ldap_integration_with_docker_container(
    docker_openldap_container,
    ldap_test_config,
) -> bool:
    """Test LDAP operations using Docker container fixture."""
    # Create client with proper config
    config = FlextLdapConnectionConfig(
        server="localhost",
        port=3389,  # Using test port
        use_ssl=False,
        timeout_seconds=30,
    )

    client = FlextLdapSimpleClient(config)

    # Test connection
    result = client.connect()

    if result.success:
        # Test basic search
        asyncio.run(
            client.search(
                "dc=flext,dc=local",  # Using the configured domain
                "(objectClass=*)",
                scope="base",
            ),
        )

        # Cleanup
        client.disconnect()
        return True
    return False


if __name__ == "__main__":
    # Run with pytest
    import sys

    sys.exit(pytest.main([__file__, "-v", "-s"]))
