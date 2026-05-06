Before any commit, automatically:
# Run security hook first
/security-check
- Run ruff format & check
- Validate all JSON schemas
- Run CLI tests
- Ensure no breaking changes to public schema
If any step fails, block the commit and explain why.