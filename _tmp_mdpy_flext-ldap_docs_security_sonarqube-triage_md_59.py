# from flext-ldap_docs/security/sonarqube-triage.md:59
      261                      )
      262                  )
      263              )
      264
>>>   265          def handle_schema_modify(
      266              self, entry: p.Ldif.Entry
      267          ) -> p.Result[m.Ldap.LdapOperationResult]:
      268              """Apply a schema modification entry (supports multiple add operations).
      269
