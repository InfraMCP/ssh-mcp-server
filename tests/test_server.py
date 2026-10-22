"""Tests for SSH MCP server tools."""

from unittest.mock import MagicMock, patch

import paramiko

from ssh_mcp_server.server import (
    ssh_execute_ssh,
    ssh_get_disk_usage,
    ssh_get_system_info,
)


def _mock_ssh_client(mock_ssh_client_cls, exit_status=0, stdout=b"", stderr=b""):
    """Wire up a mocked paramiko.SSHClient with a canned exec_command result."""
    mock_ssh = MagicMock()
    mock_ssh_client_cls.return_value = mock_ssh

    mock_stdout = MagicMock()
    mock_stdout.read.return_value = stdout
    mock_stdout.channel.recv_exit_status.return_value = exit_status

    mock_stderr = MagicMock()
    mock_stderr.read.return_value = stderr

    mock_ssh.exec_command.return_value = (None, mock_stdout, mock_stderr)
    return mock_ssh


class TestSSHExecute:
    """Test ssh_execute_ssh tool."""

    @patch("ssh_mcp_server.server.get_username_suggestion", return_value="alice")
    @patch("paramiko.SSHClient")
    def test_success_via_key_auth(self, mock_ssh_client_cls, _mock_user):
        _mock_ssh_client(mock_ssh_client_cls, exit_status=0, stdout=b"command output")

        result = ssh_execute_ssh("test.vocus.local", "ls -la")

        assert result["status"] == 0
        assert result["stdout"] == "command output"
        assert result["hostname"] == "test.vocus.local"
        assert result["command"] == "ls -la"
        assert "error" not in result

    @patch("ssh_mcp_server.server.get_username_suggestion", return_value="alice")
    @patch("paramiko.SSHClient")
    def test_connection_failure_returns_error(self, mock_ssh_client_cls, _mock_user):
        mock_ssh = MagicMock()
        mock_ssh_client_cls.return_value = mock_ssh
        mock_ssh.connect.side_effect = paramiko.SSHException("Connection failed")

        result = ssh_execute_ssh("test.vocus.local", "ls -la")

        assert "error" in result
        assert result["error"] == "SSH connection failed"
        assert "troubleshooting" in result

    @patch("ssh_mcp_server.server.get_credentials")
    @patch("ssh_mcp_server.server.get_username_suggestion", return_value="alice")
    @patch("paramiko.SSHClient")
    def test_falls_back_to_password_auth(
        self, mock_ssh_client_cls, _mock_user, mock_get_creds
    ):
        mock_ssh = _mock_ssh_client(mock_ssh_client_cls, exit_status=0, stdout=b"ok")
        # First connect (key auth) raises, second (password auth) succeeds.
        mock_ssh.connect.side_effect = [
            paramiko.AuthenticationException(),
            None,
        ]
        mock_get_creds.return_value = ("alice", "secret")

        result = ssh_execute_ssh("test.vocus.local", "whoami")

        assert result["status"] == 0
        assert result["stdout"] == "ok"
        mock_get_creds.assert_called_once_with("test.vocus.local")


class TestSystemInfoWrappers:
    """Test the convenience wrapper tools delegate to ssh_execute_ssh."""

    @patch("ssh_mcp_server.server.ssh_execute_ssh")
    def test_get_system_info_delegates(self, mock_exec):
        mock_exec.return_value = {"status": 0, "stdout": "Linux"}

        result = ssh_get_system_info("test.vocus.local")

        assert result["status"] == 0
        mock_exec.assert_called_once()
        # First positional arg is the hostname.
        assert mock_exec.call_args.args[0] == "test.vocus.local"

    @patch("ssh_mcp_server.server.ssh_execute_ssh")
    def test_get_disk_usage_uses_df(self, mock_exec):
        mock_exec.return_value = {"status": 0, "stdout": ""}

        ssh_get_disk_usage("test.vocus.local")

        mock_exec.assert_called_once_with("test.vocus.local", "df -h")
