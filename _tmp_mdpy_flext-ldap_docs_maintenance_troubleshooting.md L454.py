# from flext-ldap/docs/maintenance/troubleshooting.md:454
from __future__ import annotations

# Validate configuration
python -c "
import yaml
from cerberus import Validator

schema = {
    'audit': {
        'thresholds': {
            'min_word_count': {'type': 'integer', 'min': 0},
            'max_age_days': {'type': 'integer', 'min': 1}
        }
    }
}

with open('docs/maintenance/settings.yaml') as f:
    settings = yaml.safe_load(f)

v = Validator(schema)
if v.validate(settings):
    print('✅ Configuration is valid')
else:
    print('❌ Configuration errors:', v.errors)
"```
### Environment-Specific Settings

**Symptom:** Configuration works in development but fails in production

**Solutions:**

- Use environment variables for sensitive data
- Create environment-specific settings files
- Use settings inheritance (base + environment overrides)

