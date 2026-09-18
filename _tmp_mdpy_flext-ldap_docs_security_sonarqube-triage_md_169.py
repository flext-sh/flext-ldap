# from flext-ldap_docs/security/sonarqube-triage.md:169
       73
       74      @pytest.mark.parametrize("port", [0, -1, 65536, 70000, 999999])
       75      def test_out_of_range_port_is_rejected(self, port: int) -> None:
       76          """Verify out of range port is rejected."""
>>>    77          with pytest.raises(c.ValidationError):
       78              LdapTestSettings(Ldap=_LdapSettings(port=port))
       79
       80      # ── Host values ────────────────────────────────────────────────────
       81
