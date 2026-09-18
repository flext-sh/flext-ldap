# from flext-ldap_docs/api-reference.md:232
result = api.test_connection()
if result.success:
    print("Connection successful")```
______________________________________________________________________

## 📊 Domain Entities

### FlextLdapEntities

Container for domain entities and request objects.

#### SearchRequest

Search criteria for LDAP operations.

**Attributes:**

- `base_dn` (str): Base distinguished name for search
- `filter_str` (str): LDAP search filter
- `scope` (str): Search scope ("base", "onelevel", "subtree")
- `attributes` (t.StringList): Attributes to retrieve
- `size_limit` (int, optional): Maximum results to return
- `time_limit` (int, optional): Search timeout in seconds

#### CreateUserRequest

User creation request data.

**Attributes:**

- `dn` (str): Distinguished name for new user
- `uid` (str): User identifier
- `cn` (str): Common name
- `sn` (str): Surname
- `mail` (str, optional): Email address
- `object_classes` (t.StringList, optional): LDAP object classes

#### FlextLdapUser

LDAP user entity.

**Attributes:**

- `dn` (str): Distinguished name
- `uid` (str): User identifier
- `cn` (str): Common name
- `sn` (str): Surname
- `given_name` (str, optional): First name
- `mail` (str, optional): Email address
- `member_of` (t.StringList, optional): Group memberships

**Methods:**

- `is_valid() -> bool`: Validate user data
- `get_display_name() -> str`: Get display name

#### FlextLdapGroup

LDAP group entity.

**Attributes:**

- `dn` (str): Distinguished name
- `cn` (str): Common name
- `members` (t.StringList): Member distinguished names
- `description` (str, optional): Group description

**Methods:**

- `add_member(member_dn: str) -> None`: Add group member
- `remove_member(member_dn: str) -> None`: Remove group member

______________________________________________________________________

## 🎯 Value Objects

### FlextLdapModels.Values

Container for value objects.

#### DN

RFC 4514 compliant distinguished name.

**Attributes:**

- `value` (str): DN string value

**Methods:**

- `rdn() -> str`: Get relative distinguished name
- `parent_dn() -> str`: Get parent DN

**Example:**

