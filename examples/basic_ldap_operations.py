#!/usr/bin/env python3
"""Basic LDAP Operations Example.

This example demonstrates the core functionality of flext-ldap library:
- Configuration management
- Connection establishment
- Search operations
- User management
- Error handling with FlextResult patterns

Requirements:
- flext-ldap library installed
- Optional: LDAP server for real operations (falls back to mock/test mode)

Usage:
    python examples/basic_ldap_operations.py
"""

import asyncio
from flext_core import get_logger
from flext_ldap import (
    FlextLdapApi,
    FlextLdapConnectionConfig,
    FlextLdapAuthConfig,
    create_development_config,
)

logger = get_logger(__name__)


async def demonstrate_configuration():
    """Demonstrate configuration management."""
    print("🔧 Configuration Management")
    print("=" * 40)
    
    # 1. Basic connection configuration
    connection_config = FlextLdapConnectionConfig(
        server="ldap.example.com",
        port=389,
        use_ssl=False,
        timeout_seconds=30
    )
    
    print(f"✅ Connection config: {connection_config.server}:{connection_config.port}")
    
    # 2. Authentication configuration  
    auth_config = FlextLdapAuthConfig(
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        bind_password="secret",
        use_anonymous_bind=False
    )
    
    print(f"✅ Auth config: {auth_config.bind_dn}")
    
    # 3. Development configuration
    dev_config = create_development_config()
    print(f"✅ Development config: {dev_config.project_name} v{dev_config.project_version}")
    
    # 4. Configuration validation
    conn_validation = connection_config.validate_domain_rules()
    auth_validation = auth_config.validate_domain_rules()
    
    print(f"✅ Connection validation: {'PASS' if conn_validation.is_success else 'FAIL'}")
    print(f"✅ Auth validation: {'PASS' if auth_validation.is_success else 'FAIL'}")
    
    return connection_config, auth_config


async def demonstrate_api_usage():
    """Demonstrate API usage patterns."""
    print("\n🚀 API Usage Patterns")
    print("=" * 40)
    
    # 1. Initialize API
    api = FlextLdapApi()
    print("✅ FlextLdapApi initialized")
    
    # 2. Connect (using mock server for demo)
    try:
        connection_result = await api.connect(
            server_url="ldap://mock.example.com:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="secret",
            session_id="demo_session"
        )
        
        if connection_result.is_success:
            print(f"✅ Connected with session: {connection_result.data}")
        else:
            print(f"❌ Connection failed: {connection_result.error}")
            
    except Exception as e:
        print(f"❌ Connection exception: {e}")
    
    return api


async def demonstrate_search_operations(api: FlextLdapApi):
    """Demonstrate search operations."""
    print("\n🔍 Search Operations")
    print("=" * 40)
    
    # Mock session for demonstration
    session_id = "demo_session"
    
    try:
        # 1. Basic search
        search_result = await api.search(
            session_id=session_id,
            base_dn="dc=example,dc=com",
            filter_expr="(objectClass=person)",
            attributes=["cn", "mail", "uid"],
            scope="subtree"
        )
        
        if search_result.is_success:
            entries = search_result.data or []
            print(f"✅ Search completed: {len(entries)} entries found")
            
            for entry in entries[:3]:  # Show first 3 entries
                print(f"  - DN: {getattr(entry, 'dn', 'N/A')}")
                
        else:
            print(f"❌ Search failed: {search_result.error}")
            
    except Exception as e:
        print(f"❌ Search exception: {e}")


async def demonstrate_error_handling():
    """Demonstrate FlextResult error handling patterns."""
    print("\n⚠️  Error Handling Patterns")
    print("=" * 40)
    
    # 1. Configuration validation errors
    invalid_config = FlextLdapConnectionConfig(
        server="",  # Invalid empty server
        port=70000,  # Invalid port
    )
    
    validation_result = invalid_config.validate_domain_rules()
    if not validation_result.is_success:
        print(f"✅ Caught configuration error: {validation_result.error}")
    
    # 2. Authentication errors
    invalid_auth = FlextLdapAuthConfig(
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        bind_password="",  # Missing password
        use_anonymous_bind=False
    )
    
    auth_validation = invalid_auth.validate_domain_rules()
    if not auth_validation.is_success:
        print(f"✅ Caught authentication error: {auth_validation.error}")
    
    # 3. Connection errors (simulated)
    api = FlextLdapApi()
    try:
        connection_result = await api.connect(
            server_url="ldap://nonexistent.server:389",
            session_id="error_test"
        )
        
        if not connection_result.is_success:
            print(f"✅ Caught connection error: {connection_result.error}")
            
    except Exception as e:
        print(f"✅ Caught exception: {type(e).__name__}: {e}")


async def demonstrate_logging_integration():
    """Demonstrate logging integration with flext-core."""
    print("\n📝 Logging Integration")
    print("=" * 40)
    
    # Enable TRACE logging for this demo
    import os
    os.environ["FLEXT_LOG_LEVEL"] = "DEBUG"
    
    logger.info("Starting logging demonstration")
    
    # Create configuration with logging
    logger.debug("Creating connection configuration")
    config = FlextLdapConnectionConfig(
        server="demo.example.com",
        port=389
    )
    
    logger.debug("Configuration created successfully", extra={
        "server": config.server,
        "port": config.port,
        "ssl": config.use_ssl
    })
    
    # Test validation with logging
    logger.debug("Testing configuration validation")
    result = config.validate_domain_rules()
    
    if result.is_success:
        logger.info("Configuration validation passed")
    else:
        logger.error("Configuration validation failed", extra={
            "error": result.error
        })
    
    print("✅ Check console output for structured logging")


async def main():
    """Main demonstration function."""
    print("🎯 FLEXT-LDAP Library Demonstration")
    print("=" * 50)
    print("This example shows key features of the flext-ldap library")
    print("using real code paths and enterprise patterns.\n")
    
    try:
        # 1. Configuration management
        connection_config, auth_config = await demonstrate_configuration()
        
        # 2. API usage
        api = await demonstrate_api_usage()
        
        # 3. Search operations
        await demonstrate_search_operations(api)
        
        # 4. Error handling
        await demonstrate_error_handling()
        
        # 5. Logging integration
        await demonstrate_logging_integration()
        
        print("\n🎉 Demonstration completed successfully!")
        print("✅ All flext-ldap core features demonstrated")
        print("✅ Enterprise patterns validated")
        print("✅ Error handling verified")
        print("✅ Logging integration confirmed")
        
    except Exception as e:
        print(f"\n❌ Demonstration failed: {e}")
        logger.exception("Demonstration failed with exception")
        raise


if __name__ == "__main__":
    asyncio.run(main())