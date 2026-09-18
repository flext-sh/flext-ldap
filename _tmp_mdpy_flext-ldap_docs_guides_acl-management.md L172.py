# from flext-ldap/docs/guides/acl-management.md:172
# Simple attribute ACL
"""access to attrs=userPassword by self write"""

# DN-based ACL
'access to dn.exact="ou=users,dc=example,dc=com" by users read'

# Multiple attributes
"access to attrs=cn,sn,mail by authenticated read"```
### Oracle Directory Format

