# from flext-ldap_docs/security/sonarqube-triage.md:79
      575          dn_model: m.Ldif.DN = dn_build.unwrap()
      576          result = self._ensure_adapter().delete(dn_model)
      577          folded: p.Result[m.Ldap.OperationResult] = result.fold(
      578              on_failure=lambda e: r[m.Ldap.OperationResult].fail(
>>>   579                  u.to_str(e, default="Unknown error")
      580              ),
      581              on_success=r[m.Ldap.OperationResult].ok,
      582          )
      583          return folded
