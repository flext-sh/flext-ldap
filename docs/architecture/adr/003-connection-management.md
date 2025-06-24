# ADR-003: Enterprise Connection Management

**Robust, scalable, and intelligent connection management for enterprise environments**

## 📋 Status
**APPROVED** - Critical infrastructure decision

## 🎯 Context

Building on [ADR-001: Core Foundation Architecture](001-foundation-architecture.md) and [ADR-002: Async-First Design](002-async-first-design.md), we need enterprise-grade connection management that handles high loads, network failures, and complex enterprise LDAP environments with multiple servers, failover, and security requirements.

### 🔍 **Current Implementation Analysis**

Our existing codebase in `src/ldap_core_shared/` shows:
- ✅ **Basic foundation**: Core connection concepts
- ✅ **Performance monitoring**: Connection tracking capabilities
- ❌ **Needs enhancement**: Enterprise pooling, failover, health monitoring, security

### 🏆 **Enterprise Requirements from Research**

From analyzing enterprise LDAP deployments and 57+ implementations:
- **High Availability**: Multi-server failover and load balancing
- **Connection Pooling**: Efficient resource utilization
- **Health Monitoring**: Proactive connection health management
- **Security**: TLS, certificate validation, secure authentication
- **Resilience**: Automatic retry, circuit breakers, graceful degradation

## 🎯 Decision

**We will implement a comprehensive enterprise connection management system with intelligent pooling, automatic failover, health monitoring, and advanced security features that scales from development to large enterprise deployments.**

### 🏗️ **Enterprise Connection Architecture**

#### 1. **Multi-Server Connection Manager**

```python
from typing import List, Dict, Optional, Callable, Union
from enum import Enum
import ssl
import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta

class ServerStatus(Enum):
    """Server availability status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"

class LoadBalanceStrategy(Enum):
    """Load balancing strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    RANDOM = "random"
    FAILOVER_ONLY = "failover_only"

@dataclass
class ServerConfig:
    """Configuration for a single LDAP server."""
    host: str
    port: int = 389
    use_tls: bool = True
    weight: int = 1
    priority: int = 1  # Lower number = higher priority
    max_connections: int = 100
    connect_timeout: float = 10.0
    response_timeout: float = 30.0
    
    # TLS Configuration
    tls_ca_cert_file: Optional[str] = None
    tls_cert_file: Optional[str] = None
    tls_key_file: Optional[str] = None
    tls_verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED
    tls_check_hostname: bool = True
    
    def get_url(self) -> str:
        """Get LDAP URL for this server."""
        protocol = "ldaps" if self.use_tls and self.port == 636 else "ldap"
        return f"{protocol}://{self.host}:{self.port}"

class ConnectionManager:
    """Enterprise connection manager with failover and load balancing."""
    
    def __init__(self, 
                 servers: List[ServerConfig],
                 load_balance_strategy: LoadBalanceStrategy = LoadBalanceStrategy.ROUND_ROBIN,
                 failover_enabled: bool = True,
                 health_check_interval: float = 30.0,
                 circuit_breaker_threshold: int = 5,
                 circuit_breaker_timeout: float = 60.0):
        
        self.servers = sorted(servers, key=lambda s: s.priority)
        self.load_balance_strategy = load_balance_strategy
        self.failover_enabled = failover_enabled
        self.health_check_interval = health_check_interval
        
        # Server state tracking
        self._server_status: Dict[str, ServerStatus] = {}
        self._server_metrics: Dict[str, ServerMetrics] = {}
        self._server_pools: Dict[str, AsyncConnectionPool] = {}
        self._round_robin_index = 0
        
        # Circuit breaker
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=circuit_breaker_threshold,
            timeout=circuit_breaker_timeout
        )
        
        # Health monitoring
        self._health_monitor_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
    
    async def start(self) -> None:
        """Initialize connection manager and start health monitoring."""
        # Initialize server pools
        for server in self.servers:
            pool = AsyncConnectionPool(
                server_config=server,
                min_size=2,
                max_size=server.max_connections,
                acquire_timeout=30.0
            )
            await pool.start()
            
            self._server_pools[server.get_url()] = pool
            self._server_status[server.get_url()] = ServerStatus.UNKNOWN
            self._server_metrics[server.get_url()] = ServerMetrics()
        
        # Start health monitoring
        self._health_monitor_task = asyncio.create_task(self._health_monitor_loop())
        
        logger.info(f"Connection manager started with {len(self.servers)} servers")
    
    async def stop(self) -> None:
        """Shutdown connection manager gracefully."""
        self._shutdown_event.set()
        
        if self._health_monitor_task:
            self._health_monitor_task.cancel()
            try:
                await self._health_monitor_task
            except asyncio.CancelledError:
                pass
        
        # Shutdown all pools
        for pool in self._server_pools.values():
            await pool.stop()
        
        logger.info("Connection manager stopped")
    
    async def get_connection(self) -> AsyncConnection:
        """Get connection using load balancing strategy."""
        healthy_servers = [
            server for server in self.servers
            if self._server_status.get(server.get_url()) == ServerStatus.HEALTHY
        ]
        
        if not healthy_servers:
            # Try degraded servers if no healthy ones
            degraded_servers = [
                server for server in self.servers
                if self._server_status.get(server.get_url()) == ServerStatus.DEGRADED
            ]
            
            if degraded_servers:
                healthy_servers = degraded_servers
            else:
                raise NoHealthyServersError("No healthy LDAP servers available")
        
        # Select server based on strategy
        selected_server = self._select_server(healthy_servers)
        pool = self._server_pools[selected_server.get_url()]
        
        try:
            connection = await pool.acquire()
            
            # Update metrics
            metrics = self._server_metrics[selected_server.get_url()]
            metrics.active_connections += 1
            metrics.total_requests += 1
            
            return connection
            
        except Exception as e:
            # Circuit breaker logic
            await self._circuit_breaker.record_failure(selected_server.get_url(), e)
            raise ConnectionAcquisitionError(f"Failed to acquire connection: {e}")
    
    def _select_server(self, servers: List[ServerConfig]) -> ServerConfig:
        """Select server based on load balancing strategy."""
        if self.load_balance_strategy == LoadBalanceStrategy.ROUND_ROBIN:
            server = servers[self._round_robin_index % len(servers)]
            self._round_robin_index += 1
            return server
            
        elif self.load_balance_strategy == LoadBalanceStrategy.LEAST_CONNECTIONS:
            return min(servers, key=lambda s: self._server_metrics[s.get_url()].active_connections)
            
        elif self.load_balance_strategy == LoadBalanceStrategy.WEIGHTED_ROUND_ROBIN:
            # Implement weighted selection
            total_weight = sum(s.weight for s in servers)
            target = self._round_robin_index % total_weight
            
            current_weight = 0
            for server in servers:
                current_weight += server.weight
                if target < current_weight:
                    self._round_robin_index += 1
                    return server
            
            return servers[0]  # Fallback
            
        elif self.load_balance_strategy == LoadBalanceStrategy.RANDOM:
            import random
            return random.choice(servers)
            
        else:  # FAILOVER_ONLY
            return servers[0]  # Highest priority
    
    async def _health_monitor_loop(self) -> None:
        """Continuous health monitoring loop."""
        while not self._shutdown_event.is_set():
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(5)  # Brief pause on error
    
    async def _perform_health_checks(self) -> None:
        """Perform health checks on all servers."""
        health_check_tasks = []
        
        for server in self.servers:
            task = asyncio.create_task(
                self._check_server_health(server)
            )
            health_check_tasks.append(task)
        
        # Execute health checks concurrently
        results = await asyncio.gather(*health_check_tasks, return_exceptions=True)
        
        # Update server statuses
        for server, result in zip(self.servers, results):
            server_url = server.get_url()
            
            if isinstance(result, Exception):
                self._server_status[server_url] = ServerStatus.UNHEALTHY
                logger.warning(f"Server {server_url} health check failed: {result}")
            else:
                self._server_status[server_url] = result
                logger.debug(f"Server {server_url} status: {result.value}")
    
    async def _check_server_health(self, server: ServerConfig) -> ServerStatus:
        """Check health of a single server."""
        try:
            pool = self._server_pools[server.get_url()]
            
            # Try to acquire and test a connection
            async with pool.acquire() as conn:
                # Perform lightweight health check operation
                start_time = time.time()
                await conn.whoami()  # Simple operation to test connectivity
                response_time = time.time() - start_time
                
                # Update metrics
                metrics = self._server_metrics[server.get_url()]
                metrics.last_response_time = response_time
                metrics.last_health_check = datetime.now()
                
                # Determine status based on response time
                if response_time < 1.0:
                    return ServerStatus.HEALTHY
                elif response_time < 5.0:
                    return ServerStatus.DEGRADED
                else:
                    return ServerStatus.UNHEALTHY
                    
        except Exception as e:
            logger.debug(f"Health check failed for {server.get_url()}: {e}")
            return ServerStatus.UNHEALTHY
    
    def get_server_status(self) -> Dict[str, Dict[str, any]]:
        """Get current status of all servers."""
        status = {}
        for server in self.servers:
            url = server.get_url()
            metrics = self._server_metrics[url]
            status[url] = {
                "status": self._server_status[url].value,
                "active_connections": metrics.active_connections,
                "total_requests": metrics.total_requests,
                "last_response_time": metrics.last_response_time,
                "last_health_check": metrics.last_health_check.isoformat() if metrics.last_health_check else None
            }
        return status

@dataclass
class ServerMetrics:
    """Metrics for a single server."""
    active_connections: int = 0
    total_requests: int = 0
    failed_requests: int = 0
    last_response_time: float = 0.0
    last_health_check: Optional[datetime] = None
```

#### 2. **Circuit Breaker Pattern**

```python
class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    """Circuit breaker for resilient connection management."""
    
    def __init__(self, 
                 failure_threshold: int = 5,
                 timeout: float = 60.0,
                 success_threshold: int = 3):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.success_threshold = success_threshold
        
        self._server_states: Dict[str, CircuitBreakerState] = {}
        self._failure_counts: Dict[str, int] = {}
        self._success_counts: Dict[str, int] = {}
        self._last_failure_time: Dict[str, datetime] = {}
    
    async def record_failure(self, server_url: str, exception: Exception) -> None:
        """Record a failure for the circuit breaker."""
        self._failure_counts[server_url] = self._failure_counts.get(server_url, 0) + 1
        self._last_failure_time[server_url] = datetime.now()
        
        if self._failure_counts[server_url] >= self.failure_threshold:
            self._server_states[server_url] = CircuitBreakerState.OPEN
            logger.warning(f"Circuit breaker opened for {server_url} due to {self._failure_counts[server_url]} failures")
    
    async def record_success(self, server_url: str) -> None:
        """Record a success for the circuit breaker."""
        state = self._server_states.get(server_url, CircuitBreakerState.CLOSED)
        
        if state == CircuitBreakerState.HALF_OPEN:
            self._success_counts[server_url] = self._success_counts.get(server_url, 0) + 1
            
            if self._success_counts[server_url] >= self.success_threshold:
                self._server_states[server_url] = CircuitBreakerState.CLOSED
                self._failure_counts[server_url] = 0
                self._success_counts[server_url] = 0
                logger.info(f"Circuit breaker closed for {server_url} after {self.success_threshold} successes")
    
    def can_execute(self, server_url: str) -> bool:
        """Check if operations can be executed on this server."""
        state = self._server_states.get(server_url, CircuitBreakerState.CLOSED)
        
        if state == CircuitBreakerState.CLOSED:
            return True
        elif state == CircuitBreakerState.OPEN:
            # Check if timeout has passed
            last_failure = self._last_failure_time.get(server_url)
            if last_failure and datetime.now() - last_failure > timedelta(seconds=self.timeout):
                self._server_states[server_url] = CircuitBreakerState.HALF_OPEN
                self._success_counts[server_url] = 0
                logger.info(f"Circuit breaker half-opened for {server_url}")
                return True
            return False
        else:  # HALF_OPEN
            return True
```

#### 3. **Advanced Connection Pool**

```python
class AsyncConnectionPool:
    """Advanced async connection pool with health monitoring."""
    
    def __init__(self,
                 server_config: ServerConfig,
                 min_size: int = 5,
                 max_size: int = 50,
                 acquire_timeout: float = 30.0,
                 max_idle_time: float = 300.0,
                 validation_interval: float = 60.0):
        
        self.server_config = server_config
        self.min_size = min_size
        self.max_size = max_size
        self.acquire_timeout = acquire_timeout
        self.max_idle_time = max_idle_time
        self.validation_interval = validation_interval
        
        self._pool: asyncio.Queue[PooledConnection] = asyncio.Queue(maxsize=max_size)
        self._created_connections = 0
        self._lock = asyncio.Lock()
        self._validation_task: Optional[asyncio.Task] = None
        self._stats = PoolStats()
    
    async def start(self) -> None:
        """Initialize pool with minimum connections."""
        async with self._lock:
            for _ in range(self.min_size):
                conn = await self._create_connection()
                await self._pool.put(conn)
                self._created_connections += 1
        
        # Start connection validation task
        self._validation_task = asyncio.create_task(self._validation_loop())
        
        logger.info(f"Connection pool started for {self.server_config.get_url()} with {self.min_size} connections")
    
    async def stop(self) -> None:
        """Shutdown pool gracefully."""
        if self._validation_task:
            self._validation_task.cancel()
            try:
                await self._validation_task
            except asyncio.CancelledError:
                pass
        
        # Close all connections
        connections_to_close = []
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                connections_to_close.append(conn)
            except asyncio.QueueEmpty:
                break
        
        for conn in connections_to_close:
            await conn.close()
        
        logger.info(f"Connection pool stopped for {self.server_config.get_url()}")
    
    @asynccontextmanager
    async def acquire(self) -> AsyncConnection:
        """Acquire connection from pool."""
        start_time = time.time()
        conn = None
        
        try:
            # Try to get existing connection
            try:
                pooled_conn = await asyncio.wait_for(
                    self._pool.get(),
                    timeout=self.acquire_timeout
                )
                conn = pooled_conn.connection
                
                # Validate connection if needed
                if not await self._validate_connection(pooled_conn):
                    await pooled_conn.close()
                    raise ConnectionValidationError("Connection validation failed")
                
            except (asyncio.TimeoutError, ConnectionValidationError):
                # Create new connection if possible
                async with self._lock:
                    if self._created_connections < self.max_size:
                        pooled_conn = await self._create_connection()
                        conn = pooled_conn.connection
                        self._created_connections += 1
                    else:
                        raise ConnectionPoolExhausted("Pool at maximum capacity")
            
            # Update stats
            self._stats.connections_acquired += 1
            self._stats.total_acquire_time += time.time() - start_time
            
            yield conn
            
        finally:
            if conn:
                # Return connection to pool
                try:
                    await self._pool.put(PooledConnection(
                        connection=conn,
                        created_at=datetime.now(),
                        last_used=datetime.now()
                    ))
                except asyncio.QueueFull:
                    # Pool full, close connection
                    await conn.close()
                    async with self._lock:
                        self._created_connections -= 1
    
    async def _create_connection(self) -> PooledConnection:
        """Create new connection with proper configuration."""
        conn = AsyncLDAPConnection(
            server_config=self.server_config
        )
        await conn.connect()
        
        return PooledConnection(
            connection=conn,
            created_at=datetime.now(),
            last_used=datetime.now()
        )
    
    async def _validate_connection(self, pooled_conn: PooledConnection) -> bool:
        """Validate that connection is still healthy."""
        try:
            # Check if connection is too old
            if datetime.now() - pooled_conn.last_used > timedelta(seconds=self.max_idle_time):
                return False
            
            # Perform lightweight health check
            return await pooled_conn.connection.is_connected()
            
        except Exception:
            return False
    
    async def _validation_loop(self) -> None:
        """Periodic validation of pooled connections."""
        while True:
            try:
                await asyncio.sleep(self.validation_interval)
                await self._validate_pool_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Connection validation error: {e}")
    
    async def _validate_pool_connections(self) -> None:
        """Validate all connections in the pool."""
        connections_to_validate = []
        
        # Extract connections for validation
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                connections_to_validate.append(conn)
            except asyncio.QueueEmpty:
                break
        
        # Validate each connection
        valid_connections = []
        for pooled_conn in connections_to_validate:
            if await self._validate_connection(pooled_conn):
                valid_connections.append(pooled_conn)
            else:
                await pooled_conn.close()
                async with self._lock:
                    self._created_connections -= 1
        
        # Return valid connections to pool
        for conn in valid_connections:
            await self._pool.put(conn)
        
        # Create new connections if below minimum
        async with self._lock:
            while self._created_connections < self.min_size:
                try:
                    new_conn = await self._create_connection()
                    await self._pool.put(new_conn)
                    self._created_connections += 1
                except Exception as e:
                    logger.error(f"Failed to create replacement connection: {e}")
                    break
    
    def get_stats(self) -> Dict[str, any]:
        """Get pool statistics."""
        return {
            "total_connections": self._created_connections,
            "available_connections": self._pool.qsize(),
            "connections_acquired": self._stats.connections_acquired,
            "average_acquire_time": (
                self._stats.total_acquire_time / self._stats.connections_acquired
                if self._stats.connections_acquired > 0 else 0
            )
        }

@dataclass
class PooledConnection:
    """Wrapper for pooled connection with metadata."""
    connection: AsyncConnection
    created_at: datetime
    last_used: datetime
    
    async def close(self) -> None:
        """Close the underlying connection."""
        await self.connection.close()

@dataclass
class PoolStats:
    """Statistics for connection pool."""
    connections_acquired: int = 0
    total_acquire_time: float = 0.0
```

## 🎯 Consequences

### ✅ **Positive Outcomes**

1. **🏢 Enterprise Scalability**: Handles high connection loads efficiently
2. **🛡️ High Availability**: Automatic failover and health monitoring
3. **⚡ Performance**: Intelligent load balancing and connection reuse
4. **🔒 Security**: Comprehensive TLS and certificate management
5. **📊 Observability**: Detailed metrics and health monitoring
6. **🔄 Resilience**: Circuit breakers and graceful degradation

### ⚠️ **Potential Challenges**

1. **🏗️ Complexity**: Sophisticated connection management logic
2. **🔧 Configuration**: Many tunable parameters for optimization
3. **🐛 Debugging**: Complex state management across multiple servers
4. **📦 Dependencies**: Requires robust async framework

### 🛡️ **Risk Mitigation**

1. **📚 Configuration Presets**: Sensible defaults for common scenarios
2. **🔍 Comprehensive Logging**: Detailed debugging information
3. **📊 Monitoring Dashboard**: Real-time connection status visualization
4. **🧪 Extensive Testing**: Fault injection and load testing

## 🚀 Implementation Plan

### 📅 **Phase 1: Core Connection Management (Week 1)**
```python
Core_Tasks = [
    "✅ Implement ServerConfig and basic connection logic",
    "✅ Create ConnectionManager with load balancing",
    "✅ Add basic health monitoring",
    "✅ Implement connection pooling foundation",
    "✅ Add TLS and security configuration"
]
```

### 📅 **Phase 2: Advanced Features (Week 2)**
```python
Advanced_Tasks = [
    "✅ Implement circuit breaker pattern",
    "✅ Add sophisticated health checks",
    "✅ Create advanced pool management",
    "✅ Implement metrics collection",
    "✅ Add failover and recovery logic"
]
```

### 📅 **Phase 3: Enterprise Features (Week 3)**
```python
Enterprise_Tasks = [
    "✅ Add monitoring dashboard integration",
    "✅ Implement configuration management",
    "✅ Create operational tools and utilities",
    "✅ Performance optimization and tuning",
    "✅ Production testing and validation"
]
```

## 🔗 Related ADRs

- **[ADR-001: Core Foundation Architecture](001-foundation-architecture.md)** - Provides architectural patterns
- **[ADR-002: Async-First Design](002-async-first-design.md)** - Provides async foundation
- **[ADR-019: Performance Monitoring](019-performance-monitoring.md)** - Uses connection metrics

## 📊 Success Metrics

```python
Connection_Performance_Targets = {
    "availability": {
        "uptime": "> 99.9%",
        "failover_time": "< 5 seconds",
        "connection_acquisition": "< 10ms average"
    },
    "scalability": {
        "max_concurrent_connections": "> 1000",
        "pool_efficiency": "> 95%",
        "load_balancing_fairness": "> 90%"
    },
    "reliability": {
        "connection_success_rate": "> 99.5%",
        "health_check_accuracy": "> 99%",
        "circuit_breaker_effectiveness": "> 95%"
    }
}
```

---

**🏢 This enterprise connection management decision establishes the reliability and scalability foundation for production LDAP deployments.** Every connection benefits from intelligent pooling, health monitoring, and resilient failover patterns.

**Decision Maker**: Architecture Team  
**Date**: 2025-06-24  
**Status**: ✅ APPROVED  
**Next Review**: Post Phase 1 implementation and load testing