# from flext-ldap/docs/api-reference.md:491
result = api.search_entries(request)

# Check success
if result.success:
    data = result.unwrap()

# Alternative: direct access (raises if failure)
try:
    data = result.unwrap()
except rError:
    print("Operation failed")```
### Error Handling

