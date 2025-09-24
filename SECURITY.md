# Security Policy

## Supply Chain Security

This project implements several measures to protect against supply chain attacks:

### Dependency Management

- **Pinned Versions**: All dependencies use exact version pins in `requirements.txt` and `pyproject.toml`
- **Dependency Tracking**: Comprehensive dependency reports generated automatically
- **Security Scanning**: Automated vulnerability scanning with Safety and pip-audit
- **Regular Updates**: Weekly automated security checks via GitHub Actions

### Dependency Documentation

- `docs/DEPENDENCIES.md` - Human-readable dependency report
- `docs/dependency-report.json` - Machine-readable dependency data
- Generated automatically by `scripts/generate_dependency_report.py`

### Security Workflow

1. **Before Updates**: Review current dependency report
2. **During Updates**: Update pinned versions in both `requirements.txt` and `pyproject.toml`
3. **After Updates**: Regenerate dependency report and review changes
4. **Continuous**: Monitor security advisories for listed dependencies

### Vulnerability Response

If a security vulnerability is discovered in a dependency:

1. Check `docs/DEPENDENCIES.md` to see if we use the affected package/version
2. If affected, update to a patched version immediately
3. Regenerate dependency report to document the change
4. Test thoroughly before deploying

### Tools

- **Safety**: Checks for known security vulnerabilities
- **pip-audit**: OSV database vulnerability scanning
- **GitHub Dependabot**: Automated dependency updates (if enabled)

### Manual Security Checks

```bash
# Install security tools
pip3 install safety pip-audit

# Check for vulnerabilities
safety check
pip-audit

# Generate fresh dependency report
python3 scripts/generate_dependency_report.py
```

## SSH Security Considerations

### Connection Security
- Uses paramiko for secure SSH connections
- Supports key-based authentication
- Connection timeouts and retry logic
- No credential storage in code

### Best Practices
- Use SSH keys instead of passwords
- Implement proper key management
- Monitor SSH connection logs
- Use least privilege access

## Reporting Security Issues

Please report security vulnerabilities to: rory.mcmahon@vocus.com.au

Do not create public GitHub issues for security vulnerabilities.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |
