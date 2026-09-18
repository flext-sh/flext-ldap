# from flext-ldap_docs/guides/integration.md:1089
from __future__ import annotations
from fastapi import FastAPI
from flext_ldap.api import ldap

app = FastAPI()


@app.get("/health")
def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "flext-ldap-app"}


@app.get("/ready")
def readiness_check():
    """Readiness check with LDAP connectivity."""
    ldap_api = ldap

    connection_result = ldap_api.test_connection()

    if connection_result.success:
        return {"status": "ready", "ldap": "connected"}
    return {
        "status": "not ready",
        "ldap": "disconnected",
        "error": connection_result.error,
    }, 503```
______________________________________________________________________

For more integration examples and patterns, see the examples/ directory.

______________________________________________________________________

**Next:** Troubleshooting Guide →
