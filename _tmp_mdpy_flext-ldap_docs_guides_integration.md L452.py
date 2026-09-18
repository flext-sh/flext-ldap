# from flext-ldap/docs/guides/integration.md:452
from __future__ import annotations

from flask import Flask, request, jsonify
from functools import wraps
from flext_ldap import FlextLdapEntities
from flext_ldap.api import ldap

app = Flask(__name__)


def route(f):
    """Decorator to handle routes in Flask."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        loop = new_event_loop()
        set_event_loop(loop)
        try:
            return loop.run_until_complete(f(*args, **kwargs))
        finally:
            loop.close()

    return wrapper


def require_auth(f):
    """Decorator for routes requiring authentication."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)

    return decorated_function


def check_auth(username: str, password: str) -> bool:
    """Check username/password against LDAP."""
    ldap_api = ldap

    loop = new_event_loop()
    set_event_loop(loop)
    try:
        auth_result = loop.run_until_complete(
            ldap_api.authenticate_user(username, password)
        )
        return auth_result.success
    finally:
        loop.close()


@app.route("/api/users/search")
@require_auth
@route
def search_users():
    """Search users endpoint."""
    filter_str = request.args.get("filter", "(objectClass=person)")
    limit = int(request.args.get("limit", 100))

    ldap_api = ldap

    search_request = FlextLdapEntities.SearchRequest(
        base_dn="ou=users,dc=example,dc=com",
        filter_str=filter_str,
        scope="subtree",
        attributes=["uid", "cn", "mail"],
        size_limit=limit,
    )

    result = ldap_api.search_entries(search_request)
    if result.failure:
        return jsonify({"error": result.error}), 500

    entries = result.unwrap()
    return jsonify({
        "users": [
            {"uid": entry.uid, "name": entry.cn, "email": entry.mail}
            for entry in entries
        ]
    })


if __name__ == "__main__":
    app.run(debug=True)```
______________________________________________________________________

## Docker Integration

### Docker Compose Setup

