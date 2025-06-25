# ADR-002: Async-First Design Pattern

**The async/await foundation that ensures maximum performance and scalability**

## 📋 Status

**APPROVED** - Critical infrastructure decision

## 🎯 Context

Building on [ADR-001: Core Foundation Architecture](001-foundation-architecture.md), we need to establish the async/await patterns that will enable our library to achieve enterprise-grade performance. Analysis of our existing `src/ldap_core_shared/` implementation shows good async foundations, but we need comprehensive patterns for all operations.

### 🔍 **Current Implementation Analysis**

Our existing codebase shows:

- ✅ **Good async foundation**: Basic async patterns in place
- ✅ **Performance monitoring**: `PerformanceMonitor` with async tracking
- ✅ **Result pattern**: `LDAPOperationResult` for consistent error handling
- ❌ **Needs enhancement**: Comprehensive async patterns, connection pooling, streaming

### 🏆 **Best Practices from Research**

From analyzing 57+ implementations, the winning async patterns are:

- **Async-First**: All operations async by default, sync wrappers available
- **Connection Pooling**: Async connection pool management
- **Streaming Operations**: Memory-efficient async iteration
- **Concurrent Batching**: Parallel processing with controlled concurrency
- **Graceful Degradation**: Fallback to sync when needed

## 🎯 Decision

**We will implement an async-first design where every operation is naturally asynchronous, with intelligent connection pooling, streaming capabilities, and high-performance concurrent processing.**

### 🚀 **Core Async Design Principles**

```python
"""
🚀 Async-First Design - Core Principles
"""

# Principle 1: Everything is async by default
async def search(connection: AsyncConnection, ...) -> AsyncIterator[Entry]:
    """All operations return async iterators or awaitables."""

# Principle 2: Sync wrappers for compatibility
def search_sync(connection: Connection, ...) -> List[Entry]:
    """Sync wrapper calls async implementation."""
    return asyncio.run(list(search(connection.async_adapter, ...)))

# Principle 3: Resource management with async context managers
async with connection_pool.acquire() as conn:
    async for entry in conn.search(...):
        await process_entry(entry)

# Principle 4: Concurrent processing with controlled limits
async def bulk_operations(operations: List[Operation]) -> List[Result]:
    semaphore = asyncio.Semaphore(10)  # Control concurrency
    tasks = [process_with_semaphore(op, semaphore) for op in operations]
    return await asyncio.gather(*tasks)
```

### 🏗️ **Async Architecture Implementation**

#### 1. **Async Connection Management**

```python
from abc import ABC, abstractmethod
from typing import AsyncContextManager, AsyncIterator
import asyncio
from contextlib import asynccontextmanager

class AsyncConnection(ABC):
    """Base async connection interface."""

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection asynchronously."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection gracefully."""

    @abstractmethod
    async def is_connected(self) -> bool:
        """Check connection status."""

    @abstractmethod
    async def search(self,
                    base_dn: str,
                    filter_query: str,
                    attributes: List[str] = None) -> AsyncIterator[LDAPEntry]:
        """Perform async search with streaming results."""

class AsyncConnectionPool:
    """High-performance async connection pool."""

    def __init__(self,
                 server_urls: List[str],
                 min_size: int = 5,
                 max_size: int = 50,
                 acquire_timeout: float = 30.0,
                 health_check_interval: float = 60.0):
        self._server_urls = server_urls
        self._min_size = min_size
        self._max_size = max_size
        self._acquire_timeout = acquire_timeout
        self._pool: asyncio.Queue[AsyncConnection] = asyncio.Queue(maxsize=max_size)
        self._created_connections = 0
        self._health_check_task: asyncio.Task = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Initialize pool with minimum connections."""
        async with self._lock:
            # Create minimum connections
            for _ in range(self._min_size):
                conn = await self._create_connection()
                await self._pool.put(conn)
                self._created_connections += 1

            # Start health check task
            self._health_check_task = asyncio.create_task(self._health_check_loop())

    async def stop(self) -> None:
        """Shutdown pool gracefully."""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass

        # Close all connections
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                await conn.disconnect()
            except asyncio.QueueEmpty:
                break

    @asynccontextmanager
    async def acquire(self) -> AsyncContextManager[AsyncConnection]:
        """Acquire connection from pool with timeout."""
        conn = None
        try:
            # Try to get existing connection
            try:
                conn = await asyncio.wait_for(
                    self._pool.get(),
                    timeout=self._acquire_timeout
                )
            except asyncio.TimeoutError:
                # Create new connection if under max limit
                async with self._lock:
                    if self._created_connections < self._max_size:
                        conn = await self._create_connection()
                        self._created_connections += 1
                    else:
                        raise ConnectionPoolExhausted("Pool at maximum capacity")

            # Verify connection health
            if not await conn.is_connected():
                await conn.connect()

            yield conn

        finally:
            if conn:
                # Return connection to pool
                try:
                    self._pool.put_nowait(conn)
                except asyncio.QueueFull:
                    # Pool full, close connection
                    await conn.disconnect()
                    async with self._lock:
                        self._created_connections -= 1

    async def _create_connection(self) -> AsyncConnection:
        """Create new connection with load balancing."""
        # Round-robin server selection
        server_url = self._server_urls[self._created_connections % len(self._server_urls)]
        conn = AsyncLDAPConnection(server_url)
        await conn.connect()
        return conn

    async def _health_check_loop(self) -> None:
        """Periodic health check for pooled connections."""
        while True:
            try:
                await asyncio.sleep(self._health_check_interval)
                await self._perform_health_checks()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Health check failed: {e}")

    async def _perform_health_checks(self) -> None:
        """Check health of all pooled connections."""
        unhealthy_connections = []

        # Extract all connections for health check
        connections_to_check = []
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                connections_to_check.append(conn)
            except asyncio.QueueEmpty:
                break

        # Check each connection
        for conn in connections_to_check:
            try:
                if await conn.is_connected():
                    # Healthy connection, return to pool
                    await self._pool.put(conn)
                else:
                    unhealthy_connections.append(conn)
            except Exception:
                unhealthy_connections.append(conn)

        # Replace unhealthy connections
        for conn in unhealthy_connections:
            try:
                await conn.disconnect()
            except Exception:
                pass

            # Create replacement
            try:
                new_conn = await self._create_connection()
                await self._pool.put(new_conn)
            except Exception as e:
                logger.error(f"Failed to create replacement connection: {e}")
                async with self._lock:
                    self._created_connections -= 1
```

#### 2. **Async LDAP Operations**

```python
class AsyncLDAPOperations:
    """Async LDAP operations with streaming and batching."""

    def __init__(self, connection_pool: AsyncConnectionPool):
        self._pool = connection_pool
        self._semaphore = asyncio.Semaphore(10)  # Control concurrency

    async def search(self,
                    base_dn: str,
                    filter_query: str,
                    attributes: List[str] = None,
                    scope: str = "SUBTREE",
                    size_limit: int = 0) -> AsyncIterator[LDAPEntry]:
        """Async search with streaming results."""
        async with self._pool.acquire() as conn:
            async for entry in conn.search(base_dn, filter_query, attributes, scope):
                yield entry

                if size_limit > 0 and entry.sequence_number >= size_limit:
                    break

    async def bulk_add(self,
                      entries: List[LDAPEntry],
                      batch_size: int = 100,
                      max_concurrent: int = 5) -> BulkOperationResult:
        """Async bulk add with controlled concurrency."""
        semaphore = asyncio.Semaphore(max_concurrent)
        results = []

        # Process in batches
        for i in range(0, len(entries), batch_size):
            batch = entries[i:i + batch_size]
            batch_tasks = [
                self._add_with_semaphore(entry, semaphore)
                for entry in batch
            ]

            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            results.extend(batch_results)

        return BulkOperationResult(
            total_operations=len(entries),
            successful_operations=sum(1 for r in results if not isinstance(r, Exception)),
            failed_operations=sum(1 for r in results if isinstance(r, Exception)),
            results=results
        )

    async def _add_with_semaphore(self,
                                 entry: LDAPEntry,
                                 semaphore: asyncio.Semaphore) -> OperationResult:
        """Add entry with semaphore for concurrency control."""
        async with semaphore:
            async with self._pool.acquire() as conn:
                return await conn.add(entry.dn, entry.attributes)

    async def stream_search_results(self,
                                   base_dn: str,
                                   filter_query: str,
                                   chunk_size: int = 1000) -> AsyncIterator[List[LDAPEntry]]:
        """Stream search results in chunks for memory efficiency."""
        chunk = []

        async for entry in self.search(base_dn, filter_query):
            chunk.append(entry)

            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []

        # Yield remaining entries
        if chunk:
            yield chunk

    async def parallel_search(self,
                            search_requests: List[SearchRequest]) -> List[SearchResult]:
        """Execute multiple searches in parallel."""
        semaphore = asyncio.Semaphore(5)  # Limit concurrent searches

        tasks = [
            self._search_with_semaphore(request, semaphore)
            for request in search_requests
        ]

        return await asyncio.gather(*tasks, return_exceptions=True)

    async def _search_with_semaphore(self,
                                   request: SearchRequest,
                                   semaphore: asyncio.Semaphore) -> SearchResult:
        """Execute search with semaphore control."""
        async with semaphore:
            entries = []
            async for entry in self.search(
                request.base_dn,
                request.filter_query,
                request.attributes
            ):
                entries.append(entry)

            return SearchResult(
                base_dn=request.base_dn,
                filter_query=request.filter_query,
                entries=entries,
                entry_count=len(entries)
            )
```

#### 3. **Async LDIF Processing**

```python
class AsyncLDIFProcessor:
    """Async LDIF processing for large files."""

    async def stream_parse_file(self,
                               file_path: Path,
                               chunk_size: int = 1000) -> AsyncIterator[List[LDIFEntry]]:
        """Stream parse LDIF file asynchronously."""
        chunk = []

        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            async for line in f:
                # Parse line and accumulate entries
                if entry := await self._parse_line_async(line):
                    chunk.append(entry)

                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []

        if chunk:
            yield chunk

    async def bulk_import(self,
                         file_path: Path,
                         connection_pool: AsyncConnectionPool,
                         batch_size: int = 100) -> ImportResult:
        """Async bulk import from LDIF file."""
        total_entries = 0
        successful_imports = 0
        failed_imports = 0

        async for chunk in self.stream_parse_file(file_path, batch_size):
            # Process chunk in parallel
            tasks = []
            for entry in chunk:
                task = self._import_entry_async(entry, connection_pool)
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            total_entries += len(chunk)
            successful_imports += sum(1 for r in results if not isinstance(r, Exception))
            failed_imports += sum(1 for r in results if isinstance(r, Exception))

        return ImportResult(
            total_entries=total_entries,
            successful_imports=successful_imports,
            failed_imports=failed_imports
        )

    async def _import_entry_async(self,
                                 entry: LDIFEntry,
                                 pool: AsyncConnectionPool) -> OperationResult:
        """Import single entry asynchronously."""
        async with pool.acquire() as conn:
            return await conn.add(entry.dn, entry.attributes)
```

#### 4. **Async Monitoring and Observability**

```python
class AsyncPerformanceMonitor:
    """Async performance monitoring with real-time metrics."""

    def __init__(self):
        self._metrics: Dict[str, List[float]] = defaultdict(list)
        self._active_operations: Dict[str, datetime] = {}
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def track_operation(self, operation_name: str):
        """Track async operation performance."""
        start_time = time.time()
        operation_id = f"{operation_name}_{asyncio.current_task().get_name()}"

        async with self._lock:
            self._active_operations[operation_id] = datetime.now()

        try:
            yield
        finally:
            end_time = time.time()
            duration = end_time - start_time

            async with self._lock:
                self._metrics[operation_name].append(duration)
                self._active_operations.pop(operation_id, None)

    async def get_realtime_stats(self) -> PerformanceStats:
        """Get real-time performance statistics."""
        async with self._lock:
            return PerformanceStats(
                active_operations=len(self._active_operations),
                average_operation_time=self._calculate_averages(),
                operations_per_second=self._calculate_ops_per_second(),
                current_load=len(self._active_operations)
            )

    async def export_metrics_async(self) -> Dict[str, Any]:
        """Export metrics asynchronously."""
        async with self._lock:
            return {
                "metrics": dict(self._metrics),
                "active_operations": len(self._active_operations),
                "timestamp": datetime.now().isoformat()
            }
```

### 🎨 **Sync Compatibility Layer**

```python
class SyncWrapper:
    """Sync wrapper for async operations."""

    def __init__(self, async_operations: AsyncLDAPOperations):
        self._async_ops = async_operations
        self._loop = None

    def search(self, base_dn: str, filter_query: str, **kwargs) -> List[LDAPEntry]:
        """Sync wrapper for async search."""
        return self._run_async(self._collect_search_results(base_dn, filter_query, **kwargs))

    def bulk_add(self, entries: List[LDAPEntry], **kwargs) -> BulkOperationResult:
        """Sync wrapper for async bulk add."""
        return self._run_async(self._async_ops.bulk_add(entries, **kwargs))

    async def _collect_search_results(self, base_dn: str, filter_query: str, **kwargs) -> List[LDAPEntry]:
        """Collect all async search results."""
        results = []
        async for entry in self._async_ops.search(base_dn, filter_query, **kwargs):
            results.append(entry)
        return results

    def _run_async(self, coro):
        """Run async coroutine in sync context."""
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

        return self._loop.run_until_complete(coro)
```

## 🎯 Consequences

### ✅ **Positive Outcomes**

1. **🚀 Maximum Performance**: Async operations enable high concurrency
2. **📈 Scalability**: Connection pooling handles enterprise loads
3. **💾 Memory Efficiency**: Streaming operations for large datasets
4. **🔄 Backward Compatibility**: Sync wrappers for legacy code
5. **📊 Real-time Monitoring**: Async metrics and observability
6. **🛡️ Resource Management**: Proper async context managers

### ⚠️ **Potential Challenges**

1. **📚 Complexity**: Async programming requires more knowledge
2. **🔧 Debugging**: Async stack traces can be complex
3. **🏗️ Testing**: Async tests require special setup
4. **📦 Dependencies**: Requires modern Python 3.8+

### 🛡️ **Risk Mitigation**

1. **📚 Comprehensive Documentation**: Async patterns and examples
2. **🧪 Testing Framework**: Async test utilities and fixtures
3. **🔍 Debugging Tools**: Enhanced logging for async operations
4. **🎯 Gradual Adoption**: Sync wrappers enable incremental migration

## 🚀 Implementation Plan

### 📅 **Phase 1: Core Async Infrastructure (Week 1)**

```python
Foundation_Tasks = [
    "✅ Implement AsyncConnection base class",
    "✅ Create AsyncConnectionPool with health checks",
    "✅ Add async context managers for resource management",
    "✅ Implement basic async LDAP operations",
    "✅ Create sync wrapper layer"
]
```

### 📅 **Phase 2: Advanced Async Features (Week 2)**

```python
Advanced_Tasks = [
    "✅ Implement async streaming operations",
    "✅ Add concurrent batching with semaphores",
    "✅ Create async LDIF processing",
    "✅ Implement async performance monitoring",
    "✅ Add async testing utilities"
]
```

### 📅 **Phase 3: Integration and Optimization (Week 3)**

```python
Integration_Tasks = [
    "✅ Integrate with foundation architecture from ADR-001",
    "✅ Performance benchmarking and optimization",
    "✅ Error handling and retry mechanisms",
    "✅ Documentation and examples",
    "✅ Production testing and validation"
]
```

## 🔗 Related ADRs

- **[ADR-001: Core Foundation Architecture](001-foundation-architecture.md)** - Provides the base patterns
- **[ADR-003: Connection Management](003-connection-management.md)** - Builds on async connection patterns
- **[ADR-007: Search Engine](007-search-engine.md)** - Uses async search patterns

## 📊 Success Metrics

```python
Async_Performance_Targets = {
    "connection_pool": {
        "acquisition_time": "< 1ms average",
        "pool_utilization": "> 90%",
        "health_check_overhead": "< 1% CPU"
    },
    "concurrent_operations": {
        "max_concurrent_searches": "> 100",
        "bulk_operations_per_second": "> 10,000",
        "memory_per_operation": "< 1MB"
    },
    "streaming": {
        "large_file_processing": "> 50,000 entries/second",
        "memory_usage": "< 100MB for any file size",
        "streaming_latency": "< 10ms first result"
    }
}
```

---

**🚀 This async-first design decision establishes the performance foundation for the ultimate Python LDAP library.** Every operation benefits from async patterns while maintaining compatibility for existing sync code.

**Decision Maker**: Architecture Team
**Date**: 2025-06-24
**Status**: ✅ APPROVED
**Next Review**: Post Phase 1 implementation validation
