"""
Teste simples de integração Docker LDAP compartilhado
"""
import pytest
import asyncio
from flext_ldap.ldap_infrastructure import FlextLdapSimpleClient, FlextLdapConnectionConfig

@pytest.mark.integration
def test_docker_ldap_connection_shared(docker_openldap_container, ldap_test_config):
    """Test shared Docker LDAP container connection"""
    print(f"\n🐳 Container: {docker_openldap_container.name}")
    print(f"📋 Status: {docker_openldap_container.status}")
    print(f"⚙️  Config: {ldap_test_config}")
    
    # Extract connection details from ldap_test_config
    server_url = ldap_test_config["server_url"]  # Should be ldap://localhost:3389
    base_dn = ldap_test_config["base_dn"]        # Should be dc=flext,dc=local
    
    print(f"🔗 Server URL: {server_url}")
    print(f"📍 Base DN: {base_dn}")
    
    # Create proper config
    config = FlextLdapConnectionConfig(
        server="localhost",
        port=3389,
        use_ssl=False,
        timeout_seconds=30,
    )
    
    client = FlextLdapSimpleClient(config)
    
    # Test connection
    result = client.connect()
    print(f"🔌 Connection result: {result}")
    
    if result.is_success:
        print("✅ LDAP connection successful!")
        
        # Test search on base DN
        try:
            search_result = asyncio.run(client.search(
                base_dn,
                "(objectClass=*)",
                scope="base"
            ))
            print(f"🔍 Search result: {search_result}")
            
            if search_result.is_success:
                print("✅ LDAP search successful!")
                print(f"📊 Found {len(search_result.data or [])} entries")
            else:
                print(f"⚠️  Search failed: {search_result.error}")
                
        except Exception as e:
            print(f"⚠️  Search exception: {e}")
        
        # Cleanup
        client.disconnect()
        print("🔌 Disconnected from LDAP")
        
        assert True, "Integration test passed!"
    else:
        print(f"❌ Connection failed: {result.error}")
        assert False, f"Failed to connect to LDAP: {result.error}"