"""Tests for credential management (function-based API)."""

from unittest.mock import MagicMock, patch

from ssh_mcp_server.credentials import (
    clear_cached_credentials,
    get_credential_manager,
    get_credentials,
    get_domain_from_hostname,
    get_username_suggestion,
    keychain_check_expired,
    keychain_get_password,
)
from ssh_mcp_server.credentials import (
    test_credentials_available as _credentials_available,
)


class TestDomainParsing:
    """Test domain extraction from hostnames."""

    def test_fqdn(self):
        assert get_domain_from_hostname("host.vocus.local") == "vocus.local"

    def test_multi_level_fqdn(self):
        assert get_domain_from_hostname("server.retail.example.com") == (
            "retail.example.com"
        )

    def test_bare_hostname_gets_local_suffix(self):
        assert get_domain_from_hostname("simple") == "simple.local"


class TestUsernameSuggestion:
    """Test current-user suggestion."""

    def test_returns_current_user(self):
        with patch("getpass.getuser", return_value="alice"):
            assert get_username_suggestion() == "alice"


class TestKeychainHelpers:
    """Test the macOS Keychain helper functions."""

    @patch("subprocess.run")
    def test_get_password_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="s3cret\n")
        assert keychain_get_password("ssh-mcp", "alice@vocus.local") == "s3cret"

    @patch("subprocess.run")
    def test_check_expired_when_past_expiry(self, mock_run):
        # Expiry in the past -> expired.
        mock_run.return_value = MagicMock(returncode=0, stdout="expires:1\n")
        assert keychain_check_expired("ssh-mcp", "alice@vocus.local") is True

    @patch("subprocess.run")
    def test_check_expired_when_no_comment(self, mock_run):
        # No expiry comment -> assume expired.
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        assert keychain_check_expired("ssh-mcp", "alice@vocus.local") is True


class TestGetCredentials:
    """Test credential retrieval with caching."""

    @patch("ssh_mcp_server.credentials.keychain_get_password")
    @patch("subprocess.run")
    def test_returns_cached_credentials(self, mock_run, mock_get_password):
        # Simulate `security find-generic-password -s ssh-mcp` listing an account.
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='    "acct"<blob>="alice@vocus.local"\n',
        )
        mock_get_password.return_value = "cachedpass"

        username, password = get_credentials("host.vocus.local")

        assert username == "alice"
        assert password == "cachedpass"

    @patch("ssh_mcp_server.credentials.prompt_credentials_gui")
    @patch("ssh_mcp_server.credentials.keychain_set_password")
    @patch("subprocess.run")
    def test_prompts_when_no_cache(self, mock_run, mock_set_password, mock_prompt):
        # No matching cached account -> fall back to GUI prompt.
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        mock_prompt.return_value = ("bob", "newpass")

        username, password = get_credentials("host.vocus.local")

        assert (username, password) == ("bob", "newpass")
        mock_prompt.assert_called_once()
        mock_set_password.assert_called_once()


class TestCredentialAvailability:
    """Test credential availability check."""

    @patch("subprocess.run")
    def test_unavailable_when_nothing_cached(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        assert _credentials_available("host.vocus.local") is False


class TestClearCredentials:
    """Test clearing cached credentials."""

    @patch("subprocess.run")
    def test_returns_false_when_none_present(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert clear_cached_credentials() is False

    @patch("subprocess.run")
    def test_clears_matching_accounts(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='    "acct"<blob>="alice@vocus.local"\n',
        )
        assert clear_cached_credentials() is True


class TestLegacyManager:
    """Test the backward-compatibility manager shim."""

    def test_manager_exposes_domain_helper(self):
        manager = get_credential_manager()
        assert manager.get_domain_from_hostname("host.vocus.local") == "vocus.local"
