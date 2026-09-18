# from flext-ldap/docs/security/sonarqube-triage.md:39
      147              if changetype == c.Ldif.LdifChangeType.MODIFY:
      148                  return self.handle_schema_modify(entry)
      149              return self.handle_regular_add(entry)
      150
>>>   151          def handle_existing_entry(
      152              self, entry: p.Ldif.Entry
      153          ) -> p.Result[m.Ldap.LdapOperationResult]:
      154              """Handle an upsert when the entry already exists in LDAP.
      155
