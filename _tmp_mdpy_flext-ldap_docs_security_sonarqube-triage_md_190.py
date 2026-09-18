# from flext-ldap_docs/security/sonarqube-triage.md:190
      143          ldif_file.write_text(
      144              c.Ldap.Tests.SYNC_FACADE_SINGLE_ENTRY_LDIF, encoding="utf-8"
      145          )
      146          # Act / Assert: an unsupported arity is a contract violation, not a failure result
>>>   147          with pytest.raises(TypeError, match="single-phase"):
      148              ldap.sync_phase_entries(
      149                  ldif_file,
      150                  c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS,
      151                  settings=m.Ldap.SyncPhaseConfig(
