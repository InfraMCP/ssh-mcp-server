# SSH MCP Server

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An MCP (Model Context Protocol) server that provides SSH client functionality for remote Linux server management. This server enables AI assistants to execute commands on remote Linux hosts via SSH, solving the limitations of built-in tools when working with remote systems.

## Why SSH MCP Server?

Built-in MCP tools are limited to local operations. This server extends AI capabilities to remote Linux systems by providing:

- **Remote Command Execution**: Execute any command on remote Linux hosts
- **System Administration**: Manage services, check system health, monitor processes
- **Secure Authentication**: Multiple secure credential storage options
- **Enterprise Integration**: Works with domain-joined systems and enterprise environments

## Features

- **SSH Command Execution**: Execute arbitrary commands on remote Linux hosts
- **Sudo Support**: Run commands with elevated privileges (secure password handling)

## Installation

### From PyPI (Recommended)

```bash
pip install ssh-mcp-server
```

### From Source

```bash
git clone https://github.com/rorymcmahon/ssh-mcp-server.git
cd ssh-mcp-server
pip install -e .
```
- **System Information**: Get system stats, processes, disk usage, and services
- **Secure Credentials**: Secure credential storage (currently macOS Keychain, expanding to other providers)
- **Connection Management**: Automatic connection handling with timeouts
- **Error Handling**: Comprehensive error reporting and recovery
- **Puppet Integration**: Run Puppet agent in no-op mode for configuration management

## Installation

### From PyPI (when published)
```bash
pip install ssh-mcp-server
```

### From Source
```bash
git clone https://github.com/rorymcmahon/ssh-mcp-server.git
cd ssh-mcp-server
pip install -e .
```

### Development Installation
```bash
git clone https://github.com/rorymcmahon/ssh-mcp-server.git
cd ssh-mcp-server
pip install -e ".[dev]"
```

## Configuration

### MCP Client Configuration

Add to your MCP client configuration (e.g., Claude Desktop, Q CLI):

```json
{
  "mcpServers": {
    "ssh": {
      "command": "ssh-mcp-server",
      "args": []
    }
  }
}
```

### Credential Management

The server uses secure credential storage with multiple provider support:

#### Secure Storage Providers
- **macOS Keychain**: TouchID/password protected storage (macOS only)
- **Memory Cache**: Session-only credential caching
- **Interactive Prompt**: Fallback for manual entry

#### Authentication Setup
```bash
# Add domain credentials securely
ssh-mcp-auth add domain.local
ssh-mcp-auth add company.com

# Test if credentials are available
ssh-mcp-auth test domain.local

# List available providers
ssh-mcp-auth list
```

#### Security Features
- **TouchID Protection**: macOS Keychain integration requires TouchID/password
- **Memory Safety**: Passwords cleared immediately after use
- **No Plain Text**: Never stored in logs or configuration files
- **Session Caching**: Credentials cached in memory during session only
- **Secure Transmission**: Sudo passwords sent via stdin (not visible in process lists)

## Available Tools

### Core SSH Operations

#### `execute_ssh(hostname: str, command: str)`
Execute a command on a remote Linux host via SSH.

**Parameters:**
- `hostname`: Target hostname (e.g., "server.company.local")
- `command`: Command to execute

**Returns:**
```json
{
  "status": 0,
  "stdout": "total 24\ndrwxr-xr-x 3 user user 4096 ...",
  "stderr": ""
}
```
Or on error:
```json
{
  "error": "SSH connection or authentication failed"
}
```

#### `execute_sudo(hostname: str, command: str)`
Execute a command with sudo privileges. Automatically handles password input securely.

**Returns:** Same format as `execute_ssh`

### System Information Tools

#### `ssh_get_system_info(hostname: str)`
Get basic system information (OS, kernel, memory, root disk usage).

#### `get_running_processes(hostname: str)`
Get top 10 CPU-consuming processes.

#### `get_disk_usage(hostname: str)`
Get disk usage for all mounted filesystems.

#### `get_services(hostname: str)`
Get top 20 running systemd services.

#### `ssh_puppet_noop(hostname: str)`
Run Puppet agent in no-op mode (dry run) with verbose output.

## Usage Examples

### Basic Command Execution
```python
# Execute a simple command
result = execute_ssh("server.company.local", "uptime")
if "error" not in result:
    print(result["stdout"])  # System uptime information
```

### System Administration
```python
# Check system health
system_info = ssh_get_system_info("server.company.local")
disk_usage = get_disk_usage("server.company.local")
processes = get_running_processes("server.company.local")

# Restart a service with sudo
result = execute_sudo("server.company.local", "systemctl restart nginx")
```

### Error Handling
```python
result = execute_ssh("server.company.local", "invalid_command")
if "error" in result:
    print(f"Error: {result['error']}")
elif result["status"] != 0:
    print(f"Command failed with exit code {result['status']}")
    print(f"Error output: {result['stderr']}")
```

## Security Considerations

- **Credential Storage**: Uses secure credential storage (Keychain, future: Vault, AWS Secrets Manager)
- **Network Security**: Ensure SSH connections are over secure networks
- **Access Control**: Limit SSH user permissions on target hosts
- **Audit Logging**: Monitor SSH access and command execution
- **TouchID Protection**: macOS Keychain integration requires TouchID/password for access
- **Password Security**: Sudo passwords are passed securely via stdin, not visible in process lists

## Development

### Running Tests
```bash
pytest
```

### Code Formatting
```bash
black src/ tests/
isort src/ tests/
```

### Type Checking
```bash
mypy src/
```

### Coverage Report
```bash
pytest --cov=ssh_mcp_server --cov-report=html
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Format code (`black` and `isort`)
7. Commit changes (`git commit -m 'Add amazing feature'`)
8. Push to branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## Roadmap

- [ ] SSH key-based authentication
- [ ] AWS Secrets Manager credential provider
- [ ] HashiCorp Vault credential provider
- [ ] Azure Key Vault credential provider
- [ ] Connection pooling and reuse
- [ ] File transfer operations (SCP/SFTP)
- [ ] Interactive shell sessions
- [ ] Connection health monitoring
- [ ] Batch command execution
- [ ] Custom SSH client configuration
- [ ] Windows support (additional credential providers)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/rorymcmahon/ssh-mcp-server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/rorymcmahon/ssh-mcp-server/discussions)

## Changelog

### v0.1.0 (Initial Release)
- Basic SSH command execution with secure credential management
- macOS Keychain credential support
- System information and administration tools
- Puppet integration for configuration management
- Comprehensive test suite and documentation
