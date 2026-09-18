# from flext-ldap_docs/guides/acl-management.md:183
# Attribute ACL
"""access to attr=(userPassword) by group="cn=REDACTED_LDAP_BIND_PASSWORDs" (write)"""

# Entry-level ACL
'access to entry by user="cn=REDACTED_LDAP_BIND_PASSWORD" (read,write,delete)'

# Multiple attributes
'access to attr=(cn, sn, mail) by group="cn=users" (read)'```
### ACI Format (389 DS / Apache DS)

