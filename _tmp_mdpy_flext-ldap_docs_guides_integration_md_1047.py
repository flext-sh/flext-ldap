# from flext-ldap_docs/guides/integration.md:1047
from __future__ import annotations
from prometheus_client import Counter, Histogram, start_http_server
from flext_ldap.api import ldap
import time

# Metrics
ldap_operations_total = Counter(
    "ldap_operations_total", "Total LDAP operations", ["operation", "status"]
)

ldap_operation_duration = Histogram(
    "ldap_operation_duration_seconds", "LDAP operation duration", ["operation"]
)


class MetricsWrapper:
    """Wrapper to add metrics to LDAP operations."""

    def __init__(self):
        self._ldap_api = ldap

    def authenticate_user_with_metrics(self, username: str, password: str):
        """Authenticate user with metrics collection."""
        start_time = time.time()

        try:
            result = self._ldap_api.authenticate_user(username, password)

            status = "success" if result.success else "failure"
            ldap_operations_total.labels(operation="authenticate", status=status).inc()

            return result
        finally:
            duration = time.time() - start_time
            ldap_operation_duration.labels(operation="authenticate").observe(duration)


# Start metrics server
start_http_server(8001)```
### Health Check Endpoints

