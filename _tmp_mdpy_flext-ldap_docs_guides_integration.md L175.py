# from flext-ldap/docs/guides/integration.md:175
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from flext_ldap import FlextLdapEntities
from flext_ldap.api import ldap

app = FastAPI(title="FLEXT LDAP API")
security = HTTPBearer()


def authenticate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency for LDAP-based token authentication."""
    # Token validation logic here
    return credentials.credentials


@app.post("/auth/login")
def login(username: str, password: str) -> t.JsonMapping:
    """User login endpoint with LDAP authentication."""
    ldap_api = ldap

    auth_result = ldap_api.authenticate_user(username, password)
    if auth_result.failure:
        raise HTTPException(status_code=401, detail=auth_result.error)

    user = auth_result.unwrap()
    return {
        "user_id": user.uid,
        "display_name": user.cn,
        "email": user.mail,
        "groups": user.member_of,
    }


@app.get("/users/search")
def search_users(
    filter_str: str = "(objectClass=person)",
    limit: int = 100,
    token: str = Depends(authenticate_token),
) -> t.JsonMapping:
    """Search users endpoint with LDAP integration."""
    ldap_api = ldap

    search_request = FlextLdapEntities.SearchRequest(
        base_dn="ou=users,dc=example,dc=com",
        filter_str=filter_str,
        scope="subtree",
        attributes=["uid", "cn", "mail", "memberOf"],
        size_limit=limit,
    )

    result = ldap_api.search_entries(search_request)
    if result.failure:
        raise HTTPException(status_code=500, detail=result.error)

    entries = result.unwrap()
    return {
        "users": [
            {
                "uid": entry.uid,
                "name": entry.cn,
                "email": entry.mail,
                "groups": entry.member_of or [],
            }
            for entry in entries
        ],
        "count": len(entries),
    }


@app.post("/users/create")
def create_user(
    user_data: dict, token: str = Depends(authenticate_token)
) -> t.JsonMapping:
    """Create user endpoint with LDAP integration."""
    ldap_api = ldap

    create_request = FlextLdapEntities.CreateUserRequest(
        dn=f"cn={user_data['uid']},ou=users,dc=example,dc=com",
        uid=user_data["uid"],
        cn=user_data["cn"],
        sn=user_data["sn"],
        mail=user_data.get("mail"),
        object_classes=["person", "organizationalPerson", "inetOrgPerson"],
    )

    result = ldap_api.create_user(create_request)
    if result.failure:
        raise HTTPException(status_code=400, detail=result.error)

    user = result.unwrap()
    return {
        "message": "User created successfully",
        "user": {"uid": user.uid, "dn": user.dn, "name": user.cn},
    }```
______________________________________________________________________

## Django Integration

### Django Authentication Backend

