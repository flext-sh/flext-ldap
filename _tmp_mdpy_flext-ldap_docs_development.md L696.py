# from flext-ldap/docs/development.md:696
# Use context managers for resource management
with get_ldap_client() as client:
    result = client.search(search_request)
    # Client automatically closed

# Batch operations for efficiency
users_to_create = [user1, user2, user3]
results = gather(*[api.create_user(user) for user in users_to_create])```
______________________________________________________________________

## Contribution Guidelines

### Pull Request Process

1. **Create Feature Branch**

   ```bash
   git checkout -b feature/ldap-group-management
