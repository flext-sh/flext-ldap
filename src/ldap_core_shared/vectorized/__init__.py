"""🚀 Vectorized LDAP Operations - Ultra High Performance CORE FUNCTIONALITY."""

# Core vectorized implementations (now integrated into main modules)
# Factory functions for direct access (if needed)
# Constants for magic values
HTTP_INTERNAL_ERROR = 500
HTTP_OK = 200
SECONDS_PER_MINUTE = 60

from ldap_core_shared.vectorized.benchmarks import (
    PerformanceBenchmarker,
    create_performance_benchmarker,
)
from ldap_core_shared.vectorized.bulk_processor import (
    VectorizedBulkProcessor,
    create_vectorized_processor,
)
from ldap_core_shared.vectorized.connection_pool import (
    PredictiveConnectionPool,
    create_predictive_pool,
)
from ldap_core_shared.vectorized.ldif_processor import (
    VectorizedLDIFProcessor,
    create_vectorized_ldif_processor,
)
from ldap_core_shared.vectorized.search_engine import (
    VectorizedSearchEngine,
    create_vectorized_search_engine,
)

__all__ = [
    "PerformanceBenchmarker",
    "PredictiveConnectionPool",
    # Core vectorized classes (integrated into main API)
    "VectorizedBulkProcessor",
    "VectorizedLDIFProcessor",
    "VectorizedSearchEngine",
    "create_performance_benchmarker",
    "create_predictive_pool",
    "create_vectorized_ldif_processor",
    # Factory functions (for direct instantiation if needed)
    "create_vectorized_processor",
    "create_vectorized_search_engine",
]
