#!/usr/bin/env python3
"""Test script for centralized logging configuration in flext-ldap.

This script demonstrates how flext-ldap respects centralized logging
configuration from flext-core and shows proper TRACE level usage.
"""

import os
from flext_core import get_logger
from flext_ldap.config import FlextLdapConnectionConfig, create_development_config
from flext_ldap.ldap_infrastructure import FlextLdapClient, FlextLdapConverter

def test_centralized_logging():
    """Test centralized logging configuration."""
    
    print("🔧 FLEXT-CORE CENTRALIZED LOGGING TEST")
    print("=" * 50)
    
    # Show current environment configuration
    flext_level = os.environ.get("FLEXT_LOG_LEVEL", "Not set")
    client-a_level = os.environ.get("client-a_LOG_LEVEL", "Not set") 
    generic_level = os.environ.get("LOG_LEVEL", "Not set")
    
    print(f"Environment variables:")
    print(f"  FLEXT_LOG_LEVEL: {flext_level}")
    print(f"  client-a_LOG_LEVEL: {client-a_level}")
    print(f"  LOG_LEVEL: {generic_level}")
    print()
    
    # Test logger creation and level detection
    logger = get_logger("flext_ldap.test")
    logger_level = getattr(logger, '_level_value', 'Unknown')
    
    print(f"Logger level: {logger_level}")
    print(f"TRACE enabled: {logger_level <= 5}")
    print(f"DEBUG enabled: {logger_level <= 10}")
    print()
    
    # Test configuration objects with centralized logging
    print("🧪 Testing FlextLdapConnectionConfig validation...")
    try:
        config = FlextLdapConnectionConfig(
            server="test.example.com",
            port=389,
            timeout_seconds=30
        )
        print("✅ Config validation completed")
    except Exception as e:
        print(f"❌ Config validation failed: {e}")
    
    print()
    
    # Test converter with centralized logging
    print("🧪 Testing FlextLdapConverter with TRACE...")
    converter = FlextLdapConverter()
    
    # Test type detection - should show TRACE logs if enabled
    test_values = ["test@example.com", "123", "cn=user,dc=example,dc=com"]
    for value in test_values:
        detected_type = converter.detect_type(value)
        print(f"  Value '{value}' -> Type: {detected_type.value}")
    
    print()
    
    # Test LDAP client initialization
    print("🧪 Testing FlextLdapClient initialization...")
    try:
        client = FlextLdapClient(config)
        print("✅ LDAP client initialized successfully")
    except Exception as e:
        print(f"❌ LDAP client initialization failed: {e}")
    
    print()
    
    # Test development config factory
    print("🧪 Testing development config factory...")
    try:
        dev_config = create_development_config()
        print("✅ Development config created successfully")
        print(f"  Debug mode: {dev_config.enable_debug_mode}")
        print(f"  Project: {dev_config.project_name} v{dev_config.project_version}")
    except Exception as e:
        print(f"❌ Development config creation failed: {e}")
    
    print()
    print("✅ Centralized logging test completed!")

def test_different_log_levels():
    """Test logging with different centralized levels."""
    
    print("\n🎯 TESTING DIFFERENT LOG LEVELS")
    print("=" * 40)
    
    levels = ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR"]
    
    for level in levels:
        print(f"\n--- Testing with {level} level ---")
        
        # Set environment variable
        os.environ["FLEXT_LOG_LEVEL"] = level
        
        # Create new logger to pick up the change
        logger = get_logger(f"flext_ldap.test_{level.lower()}")
        logger_level = getattr(logger, '_level_value', 'Unknown')
        
        print(f"Logger numeric level: {logger_level}")
        
        # Test all log levels
        logger.trace(f"TRACE message with {level} configuration")
        logger.debug(f"DEBUG message with {level} configuration") 
        logger.info(f"INFO message with {level} configuration")
        logger.warning(f"WARNING message with {level} configuration")
        logger.error(f"ERROR message with {level} configuration")

if __name__ == "__main__":
    # Test basic centralized logging
    test_centralized_logging()
    
    # Test different log levels
    test_different_log_levels()
    
    # Reset environment
    os.environ.pop("FLEXT_LOG_LEVEL", None)
    
    print("\n🚀 All tests completed!")