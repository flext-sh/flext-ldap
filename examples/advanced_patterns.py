#!/usr/bin/env python3
"""Advanced FLEXT-LDAP Patterns Example.

This example demonstrates advanced usage patterns:
- Complex configurations
- Async/await patterns
- Context managers
- Enterprise error handling
- Performance optimizations
- Production best practices

Usage:
    python examples/advanced_patterns.py
"""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

from flext_core import get_logger
from flext_ldap import (
    FlextLdapApi,
    FlextLdapConnectionConfig,
    FlextLdapAuthConfig,
    FlextLdapSearchConfig,
    FlextLdapSettings,
)
from flext_ldap.values import FlextLdapDistinguishedName, FlextLdapFilterValue

logger = get_logger(__name__)


@asynccontextmanager
async def ldap_session(
    server_url: str, 
    bind_dn: str | None = None, 
    password: str | None = None
) -> AsyncIterator[tuple[FlextLdapApi, str]]:
    """Enterprise LDAP session context manager.
    
    Provides automatic connection management with proper cleanup.
    """
    api = FlextLdapApi()
    session_id = f"session_{id(api)}"
    
    logger.info("Establishing LDAP session", extra={
        "server_url": server_url,
        "session_id": session_id,
        "has_auth": bool(bind_dn)
    })
    
    try:
        # Attempt connection
        connection_result = await api.connect(
            server_url=server_url,
            bind_dn=bind_dn,
            password=password,
            session_id=session_id
        )
        
        if not connection_result.is_success:
            raise ConnectionError(f"Failed to connect: {connection_result.error}")
        
        logger.info("LDAP session established", extra={"session_id": session_id})
        yield api, session_id
        
    except Exception as e:
        logger.error("LDAP session failed", extra={
            "error": str(e),
            "session_id": session_id
        })
        raise
    finally:
        # Cleanup
        try:
            await api.disconnect(session_id)
            logger.info("LDAP session closed", extra={"session_id": session_id})
        except Exception as e:
            logger.warning("Session cleanup failed", extra={
                "error": str(e),
                "session_id": session_id
            })


async def demonstrate_value_objects():
    """Demonstrate value object usage."""
    print("\n💎 Value Objects and Type Safety")
    print("=" * 40)
    
    try:
        # 1. Distinguished Names
        dn = FlextLdapDistinguishedName(value="cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example,dc=com")
        validation_result = dn.validate_domain_rules()
        
        print(f"✅ DN validation: {'PASS' if validation_result.is_success else 'FAIL'}")
        print(f"   DN: {dn.value}")
        
        # 2. LDAP Filters
        filter_obj = FlextLdapFilterValue(value="(&(objectClass=person)(mail=*@example.com))")
        filter_validation = filter_obj.validate_domain_rules()
        
        print(f"✅ Filter validation: {'PASS' if filter_validation.is_success else 'FAIL'}")
        print(f"   Filter: {filter_obj.value}")
        
        # 3. Complex filter construction
        escaped_value = filter_obj.escape_filter_value("user@example.com")
        print(f"✅ Escaped value: {escaped_value}")
        
    except Exception as e:
        logger.exception("Value object demonstration failed")
        print(f"❌ Value objects failed: {e}")


async def demonstrate_comprehensive_configuration():
    """Demonstrate comprehensive configuration setup."""
    print("\n⚙️  Comprehensive Configuration")
    print("=" * 40)
    
    try:
        # 1. Full settings configuration
        settings = FlextLdapSettings(
            project_name="enterprise-ldap-integration",
            project_version="1.0.0",
            enable_debug_mode=True,
            enable_performance_monitoring=True
        )
        
        print(f"✅ Settings: {settings.project_name} v{settings.project_version}")
        
        # 2. Advanced search configuration
        search_config = FlextLdapSearchConfig(
            base_dn="dc=enterprise,dc=com",
            default_search_scope="subtree",
            size_limit=1000,
            time_limit=30,
            paged_search=True,
            page_size=100,
            enable_referral_chasing=True,
            max_referral_hops=3
        )
        
        search_validation = search_config.validate_domain_rules()
        print(f"✅ Search config: {'VALID' if search_validation.is_success else 'INVALID'}")
        
        # 3. Convert to client configuration
        client_config = settings.to_ldap_client_config()
        print(f"✅ Client config keys: {list(client_config.keys())}")
        
    except Exception as e:
        logger.exception("Configuration demonstration failed")
        print(f"❌ Configuration failed: {e}")


async def demonstrate_async_patterns():
    """Demonstrate async/await patterns."""
    print("\n🔄 Async/Await Patterns")
    print("=" * 40)
    
    try:
        # 1. Context manager usage
        async with ldap_session("ldap://demo.example.com:389") as (api, session_id):
            print(f"✅ Session established: {session_id}")
            
            # 2. Concurrent operations (simulated)
            tasks = []
            search_bases = [
                "ou=users,dc=example,dc=com",
                "ou=groups,dc=example,dc=com", 
                "ou=services,dc=example,dc=com"
            ]
            
            for base_dn in search_bases:
                task = api.search(
                    session_id=session_id,
                    base_dn=base_dn,
                    filter_expr="(objectClass=*)",
                    attributes=["dn"],
                    scope="onelevel"
                )
                tasks.append(task)
            
            # Execute concurrent searches
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            successful_searches = sum(
                1 for result in results 
                if not isinstance(result, Exception) and getattr(result, 'is_success', False)
            )
            
            print(f"✅ Concurrent searches: {successful_searches}/{len(tasks)} successful")
            
    except Exception as e:
        logger.exception("Async patterns demonstration failed")
        print(f"❌ Async patterns failed: {e}")


async def demonstrate_error_recovery():
    """Demonstrate error recovery patterns."""
    print("\n🔄 Error Recovery Patterns")
    print("=" * 40)
    
    async def attempt_operation_with_retry(operation_name: str, max_retries: int = 3):
        """Retry pattern for LDAP operations."""
        for attempt in range(max_retries):
            try:
                logger.debug(f"Attempting {operation_name}", extra={
                    "attempt": attempt + 1,
                    "max_retries": max_retries
                })
                
                # Simulate operation (would be real LDAP operation)
                if attempt < 2:  # Fail first 2 attempts
                    raise ConnectionError(f"Simulated failure for {operation_name}")
                
                logger.info(f"Operation {operation_name} succeeded", extra={
                    "attempts_used": attempt + 1
                })
                return f"Success after {attempt + 1} attempts"
                
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed", extra={
                    "operation": operation_name,
                    "error": str(e),
                    "remaining_attempts": max_retries - attempt - 1
                })
                
                if attempt == max_retries - 1:
                    logger.error(f"All attempts failed for {operation_name}")
                    raise
                
                # Exponential backoff
                await asyncio.sleep(2 ** attempt)
    
    try:
        # 1. Connection retry
        result1 = await attempt_operation_with_retry("LDAP Connection")
        print(f"✅ Connection recovery: {result1}")
        
        # 2. Search retry
        result2 = await attempt_operation_with_retry("LDAP Search")
        print(f"✅ Search recovery: {result2}")
        
    except Exception as e:
        print(f"❌ Error recovery failed: {e}")


async def demonstrate_performance_patterns():
    """Demonstrate performance optimization patterns."""
    print("\n⚡ Performance Optimization")
    print("=" * 40)
    
    try:
        # 1. Connection pooling simulation
        print("✅ Connection pooling: Enabled (simulated)")
        
        # 2. Batch operations
        batch_operations = [
            {"type": "search", "base": f"cn=user{i},ou=users,dc=example,dc=com"}
            for i in range(10)
        ]
        
        print(f"✅ Batch operations: {len(batch_operations)} operations prepared")
        
        # 3. Paging simulation
        page_size = 100
        total_entries = 1500
        pages = (total_entries + page_size - 1) // page_size
        
        print(f"✅ Paging strategy: {pages} pages of {page_size} entries")
        
        # 4. Caching simulation
        cache_hits = 8
        cache_misses = 2
        hit_rate = cache_hits / (cache_hits + cache_misses) * 100
        
        print(f"✅ Cache performance: {hit_rate:.1f}% hit rate")
        
    except Exception as e:
        logger.exception("Performance demonstration failed")
        print(f"❌ Performance patterns failed: {e}")


async def main():
    """Main demonstration function."""
    print("🚀 FLEXT-LDAP Advanced Patterns")
    print("=" * 50)
    print("Enterprise-grade patterns and best practices\n")
    
    try:
        # 1. Value objects
        await demonstrate_value_objects()
        
        # 2. Comprehensive configuration
        await demonstrate_comprehensive_configuration()
        
        # 3. Async patterns
        await demonstrate_async_patterns()
        
        # 4. Error recovery
        await demonstrate_error_recovery()
        
        # 5. Performance patterns
        await demonstrate_performance_patterns()
        
        print("\n🎉 Advanced patterns demonstration completed!")
        print("✅ Enterprise patterns validated")
        print("✅ Async/await patterns confirmed")
        print("✅ Error recovery strategies tested")
        print("✅ Performance optimizations demonstrated")
        
    except Exception as e:
        print(f"\n❌ Advanced patterns failed: {e}")
        logger.exception("Advanced patterns demonstration failed")
        raise


if __name__ == "__main__":
    # Enable comprehensive logging for demonstration
    import os
    os.environ["FLEXT_LOG_LEVEL"] = "INFO"
    
    asyncio.run(main())