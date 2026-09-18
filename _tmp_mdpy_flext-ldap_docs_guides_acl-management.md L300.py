# from flext-ldap/docs/guides/acl-management.md:300
# Create ACL with time and IP restrictions
unified_result = FlextLdapModels.Acl.create(
    name="Time and IP restricted access",
    target=target,
    subject=subject,
    permissions=permissions,
    conditions={
        "time": "09:00-17:00",
        "ip": "192.168.1.0/24",
        "day_of_week": "Mon-Fri",
    },
)```
### Permission Mapping

