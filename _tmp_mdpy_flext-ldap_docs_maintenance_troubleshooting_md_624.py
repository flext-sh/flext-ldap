# from flext-ldap_docs/maintenance/troubleshooting.md:624
# Profile script execution
python -m cProfile docs/maintenance/audit.py --comprehensive > audit_profile.txt

# Analyze results
python -c "
import pstats
p = pstats.Stats('audit_profile.txt')
p.sort_stats('cumulative').print_stats(20)
"```
### Memory Monitoring

