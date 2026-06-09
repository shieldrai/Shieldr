"""
test_guard.py
==============
Unit tests for guard.py — the main command router and Bankr.bot integration
hook.
"""

import pytest
from guard import Shieldr, handle_command, SUPPORTED_COMMANDS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def shieldr():
    return Shieldr()


# ---------------------------------------------------------------------------
# Command parser tests
# ---------------------------------------------------------------------------

class TestCommandParser:
    def test_strips_prefix(self):
        tokens = Shieldr._parse_command("/shieldr wallet 0xAbC")
        assert tokens == ["wallet", "0xAbC"]

    def test_no_prefix(self):
        tokens = Shieldr._parse_command("wallet 0xAbC --brief")
        assert tokens == ["wallet", "0xAbC", "--brief"]

    def test_empty_command_returns_empty_list(self):
        tokens = Shieldr._parse_command("/shieldr")
        assert tokens == []

    def test_whitespace_stripped(self):
        tokens = Shieldr._parse_command("  /shieldr   token   0xToken  ")
        assert tokens == ["token", "0xToken"]


# ---------------------------------------------------------------------------
# Help text tests
# ---------------------------------------------------------------------------

class TestHelpText:
    def test_help_contains_all_commands(self):
        text = Shieldr._help_text()
        for cmd in SUPPORTED_COMMANDS:
            assert cmd in text.lower(), f"Command '{cmd}' missing from help text"

    def test_help_command_returns_help(self, shieldr):
        response = shieldr.handle_command("/shieldr help", {})
        assert "wallet" in response.lower()
        assert "token" in response.lower()


# ---------------------------------------------------------------------------
# Command routing tests
# ---------------------------------------------------------------------------

class TestCommandRouting:
    def test_unknown_command_graceful(self, shieldr):
        response = shieldr.handle_command("/shieldr doesnotexist", {})
        assert "unknown" in response.lower()

    def test_empty_command_returns_help(self, shieldr):
        response = shieldr.handle_command("/shieldr", {})
        assert "wallet" in response.lower()

    def test_wallet_no_args(self, shieldr):
        response = shieldr.handle_command("/shieldr wallet", {})
        assert "usage" in response.lower()

    def test_token_no_args(self, shieldr):
        response = shieldr.handle_command("/shieldr token", {})
        assert "usage" in response.lower()

    def test_audit_no_args(self, shieldr):
        response = shieldr.handle_command("/shieldr audit", {})
        assert "usage" in response.lower()

    def test_tx_no_args(self, shieldr):
        response = shieldr.handle_command("/shieldr tx", {})
        assert "usage" in response.lower()

    def test_url_no_args(self, shieldr):
        response = shieldr.handle_command("/shieldr url", {})
        assert "usage" in response.lower()

    def test_wallet_with_address(self, shieldr):
        response = shieldr.handle_command("/shieldr wallet 0xAbC123", {})
        assert "0xAbC123" in response or "walletguard" in response.lower()

    def test_status_command(self, shieldr):
        response = shieldr.handle_command("/shieldr status", {})
        assert "SHIELDR" in response

    def test_alerts_on(self, shieldr):
        response = shieldr.handle_command("/shieldr alerts on", {})
        assert "on" in response.lower()

    def test_alerts_off(self, shieldr):
        response = shieldr.handle_command("/shieldr alerts off", {})
        assert "off" in response.lower()

    def test_alerts_invalid_arg(self, shieldr):
        response = shieldr.handle_command("/shieldr alerts maybe", {})
        assert "usage" in response.lower()


# ---------------------------------------------------------------------------
# Module-level handle_command tests
# ---------------------------------------------------------------------------

class TestModuleLevelHandler:
    def test_module_handler_callable(self):
        response = handle_command("/shieldr help")
        assert isinstance(response, str)
        assert len(response) > 0

    def test_module_handler_with_context(self):
        response = handle_command("/shieldr status", {"chain_id": 1, "user_id": "u123"})
        assert isinstance(response, str)
