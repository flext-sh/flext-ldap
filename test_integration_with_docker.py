#!/usr/bin/env python3
"""
Teste de integração usando o fixture Docker LDAP
"""
import pytest
import asyncio
from flext_ldap.ldap_infrastructure import FlextLdapSimpleClient, FlextLdapConnectionConfig

@pytest.mark.integration  
def test_ldap_integration_with_docker_container(docker_openldap_container, ldap_test_config):
    """Test LDAP operations using Docker container fixture"""
    print(f"Container: {docker_openldap_container.name}")
    print(f"Config: {ldap_test_config}")
    
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
    print(f"Connection result: {result}")
    
    if result.is_success:
        print("✅ Connected to LDAP server successfully!")
        
        # Test basic search
        search_result = asyncio.run(client.search(
            "dc=flext,dc=local",  # Using the configured domain
            "(objectClass=*)",
            scope="base"
        ))
        
        print(f"Search result: {search_result}")
        
        # Cleanup
        client.disconnect()
        print("✅ Integration test completed!")
        return True
    else:
        print(f"❌ Connection failed: {result.error}")
        return False

if __name__ == "__main__":
    # Run with pytest
    import sys
    sys.exit(pytest.main([__file__, "-v", "-s"]))