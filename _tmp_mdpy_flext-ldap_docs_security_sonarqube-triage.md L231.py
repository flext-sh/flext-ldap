# from flext-ldap/docs/security/sonarqube-triage.md:231
       14
       15      class Ldap:
       16          """LDAP type aliases."""
       17
>>>    18          LDAPException: type[Exception] = _Ldap3LDAPException
       19
       20          type Ldap3AttributeScalar = str | bytes
       21          type Ldap3AttributeValues = t.SequenceOf[Ldap3AttributeScalar]
       22          type Ldap3AttributeDict = t.MappingKV[str, Ldap3AttributeValues]
