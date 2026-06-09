"""
test_wallet_guard.py
=====================
Unit tests for the WalletGuard module.
"""

import pytest
from modules.wallet_guard import WalletGuard, WalletFinding, WalletRiskResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class MockChainClient:
    """Minimal mock for ChainClient used in unit tests."""
    async def get_transactions(self, address, chain_id=1, limit=100):
        return []
    async def get_first_tx_timestamp(self, address, chain_id=1):
        return None
    async def get_approvals(self, address, chain_id=1):
        return []


class MockSettings:
    """Minimal mock for settings."""
    class threat_intel:
        trm_labs_key    = ""
        chainalysis_key = ""
        gopluslabs_key  = ""


@pytest.fixture
def wallet_guard():
    return WalletGuard(MockChainClient(), MockSettings())


# ---------------------------------------------------------------------------
# Score aggregation tests
# ---------------------------------------------------------------------------

class TestScoreAggregation:
    def test_no_findings_returns_zero(self, wallet_guard):
        assert wallet_guard._aggregate_score([]) == 0

    def test_single_critical_finding(self, wallet_guard):
        findings = [WalletFinding("CRITICAL", "TEST", "test", "test_src")]
        assert wallet_guard._aggregate_score(findings) == 40

    def test_score_capped_at_100(self, wallet_guard):
        findings = [WalletFinding("CRITICAL", f"C{i}", "x", "src") for i in range(5)]
        assert wallet_guard._aggregate_score(findings) == 100

    def test_mixed_severities(self, wallet_guard):
        findings = [
            WalletFinding("HIGH",   "H1", "x", "src"),   # 20
            WalletFinding("MEDIUM", "M1", "x", "src"),   # 10
            WalletFinding("LOW",    "L1", "x", "src"),   # 5
        ]
        assert wallet_guard._aggregate_score(findings) == 35


# ---------------------------------------------------------------------------
# Grade mapping tests
# ---------------------------------------------------------------------------

class TestGradeMapping:
    @pytest.mark.parametrize("score,expected_grade", [
        (0,   "A"),
        (15,  "A"),
        (16,  "B"),
        (35,  "B"),
        (36,  "C"),
        (55,  "C"),
        (56,  "D"),
        (75,  "D"),
        (76,  "E"),
        (90,  "E"),
        (91,  "F"),
        (100, "F"),
    ])
    def test_grade_thresholds(self, wallet_guard, score, expected_grade):
        grade, _ = wallet_guard._score_to_grade(score)
        assert grade == expected_grade


# ---------------------------------------------------------------------------
# WalletRiskResult tests
# ---------------------------------------------------------------------------

class TestWalletRiskResult:
    def test_is_safe_below_threshold(self):
        result = WalletRiskResult(
            address="0xSafe", chain_id=1, score=10,
            grade="A", label="Safe",
        )
        assert result.is_safe is True

    def test_is_not_safe_above_threshold(self):
        result = WalletRiskResult(
            address="0xRisky", chain_id=1, score=80,
            grade="E", label="Very High Risk",
        )
        assert result.is_safe is False

    def test_critical_findings_filter(self):
        findings = [
            WalletFinding("CRITICAL", "C1", "x", "src"),
            WalletFinding("HIGH",     "H1", "x", "src"),
            WalletFinding("CRITICAL", "C2", "x", "src"),
        ]
        result = WalletRiskResult(
            address="0xTest", chain_id=1, score=80,
            grade="E", label="Very High Risk", findings=findings,
        )
        assert len(result.critical_findings) == 2
        assert len(result.high_findings) == 1


# ---------------------------------------------------------------------------
# Async score stub test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_score_returns_result(wallet_guard):
    """Verify that score() returns a WalletRiskResult even with stub implementation."""
    result = await wallet_guard.score("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
    assert isinstance(result, WalletRiskResult)
    assert 0 <= result.score <= 100
    assert result.grade in ("A", "B", "C", "D", "E", "F")
