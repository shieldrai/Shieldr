"""
wallet_guard.py — WalletGuard Module
======================================
Responsible for producing a comprehensive risk score (0–100) for any EVM
wallet address by aggregating data from multiple threat-intelligence sources.

Risk factors assessed:
  - Sanctions list membership (OFAC, Chainalysis, TRM Labs)
  - Historical interaction with known exploit/drainer contracts
  - Mixer service usage (Tornado Cash, etc.)
  - Wallet age and activity patterns
  - Association with flagged counterparties
  - Token approval exposure

Usage:
    from modules.wallet_guard import WalletGuard
    guard = WalletGuard(chain_client, settings)
    result = await guard.score("0xAbC…")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("shieldr.wallet_guard")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class WalletFinding:
    """A single risk finding for a wallet address."""
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW | INFO
    code: str               # Machine-readable finding code (e.g. "SANCTIONS_HIT")
    message: str            # Human-readable description
    source: str             # Data source that produced this finding
    metadata: dict = field(default_factory=dict)


@dataclass
class WalletRiskResult:
    """Aggregated risk result returned by WalletGuard.score()."""
    address: str
    chain_id: int
    score: int                              # 0 (safe) – 100 (critical)
    grade: str                              # A | B | C | D | E | F
    label: str                              # Human-readable score label
    findings: list[WalletFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        return self.score <= 15

    @property
    def critical_findings(self) -> list[WalletFinding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]

    @property
    def high_findings(self) -> list[WalletFinding]:
        return [f for f in self.findings if f.severity == "HIGH"]


# ---------------------------------------------------------------------------
# WalletGuard
# ---------------------------------------------------------------------------

class WalletGuard:
    """
    Produces risk scores for EVM wallet addresses.

    All public methods are async to allow concurrent fetching from multiple
    threat-intelligence APIs without blocking.
    """

    # Mapping of score ranges to (grade, label) tuples
    SCORE_GRADES = [
        (15,  "A", "Safe"),
        (35,  "B", "Low Risk"),
        (55,  "C", "Moderate Risk"),
        (75,  "D", "High Risk"),
        (90,  "E", "Very High Risk"),
        (100, "F", "Critical"),
    ]

    def __init__(self, chain_client: Any, settings: Any) -> None:
        """
        Initialise WalletGuard.

        Args:
            chain_client: An instance of ChainClient for on-chain lookups.
            settings:     Loaded settings object (contains API keys, etc.).
        """
        self.chain_client = chain_client
        self.settings     = settings
        logger.debug("WalletGuard initialised.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def score(self, address: str, chain_id: int = 1) -> WalletRiskResult:
        """
        Produce a comprehensive risk score for the given wallet address.

        Steps:
        1. Validate and normalise the address (checksum).
        2. Run all sub-checks concurrently.
        3. Aggregate findings into a final score.
        4. Assign a grade and label.
        5. Return a WalletRiskResult.

        Args:
            address:  EVM wallet address (any casing).
            chain_id: Chain to query for on-chain data.

        Returns:
            WalletRiskResult containing score, grade, and all findings.
        """
        # TODO: implement all sub-checks and concurrency
        logger.info("Scoring wallet %s on chain %d", address, chain_id)
        findings: list[WalletFinding] = []

        # --- Sub-checks (to be implemented) ---
        # findings += await self._check_sanctions(address)
        # findings += await self._check_exploit_interactions(address, chain_id)
        # findings += await self._check_mixer_usage(address, chain_id)
        # findings += await self._check_wallet_age(address, chain_id)
        # findings += await self._check_counterparty_risk(address, chain_id)
        # findings += await self._check_approval_exposure(address, chain_id)

        score = self._aggregate_score(findings)
        grade, label = self._score_to_grade(score)

        return WalletRiskResult(
            address=address,
            chain_id=chain_id,
            score=score,
            grade=grade,
            label=label,
            findings=findings,
        )

    # ------------------------------------------------------------------
    # Sub-checks (stubs)
    # ------------------------------------------------------------------

    async def _check_sanctions(self, address: str) -> list[WalletFinding]:
        """
        Query sanctions lists (OFAC, TRM Labs, Chainalysis).

        Returns a CRITICAL finding if the address appears on any list.
        """
        # TODO: implement API calls to TRM Labs and Chainalysis
        return []

    async def _check_exploit_interactions(
        self, address: str, chain_id: int
    ) -> list[WalletFinding]:
        """
        Check transaction history for interactions with known exploit contracts,
        drainers, and hack-associated addresses.

        Data sources: on-chain tx history + curated exploit address database.
        """
        # TODO: implement using chain_client.get_transactions() + exploit DB
        return []

    async def _check_mixer_usage(
        self, address: str, chain_id: int
    ) -> list[WalletFinding]:
        """
        Detect direct or indirect interactions with mixer services
        (Tornado Cash, Blender, etc.).
        """
        # TODO: implement mixer address set lookup
        return []

    async def _check_wallet_age(
        self, address: str, chain_id: int
    ) -> list[WalletFinding]:
        """
        Calculate wallet age from the first transaction.
        Very new wallets (< 7 days) receive a LOW-severity flag.
        """
        # TODO: implement using chain_client.get_first_tx_timestamp()
        return []

    async def _check_counterparty_risk(
        self, address: str, chain_id: int
    ) -> list[WalletFinding]:
        """
        Analyse recent counterparties for risk associations.
        Flags if > N% of recent counterparties are themselves high-risk.
        """
        # TODO: implement recursive risk propagation
        return []

    async def _check_approval_exposure(
        self, address: str, chain_id: int
    ) -> list[WalletFinding]:
        """
        Enumerate outstanding ERC-20 and NFT approvals granted by this wallet.
        Flags unlimited approvals to unverified or risky spenders.
        """
        # TODO: implement using chain_client.get_approvals()
        return []

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def _aggregate_score(self, findings: list[WalletFinding]) -> int:
        """
        Aggregate individual finding weights into a final 0–100 score.

        Severity weights:
          CRITICAL = 40
          HIGH     = 20
          MEDIUM   = 10
          LOW      =  5
          INFO     =  0
        """
        weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 0}
        total = sum(weights.get(f.severity, 0) for f in findings)
        return min(total, 100)

    def _score_to_grade(self, score: int) -> tuple[str, str]:
        """Map a numeric score to a (grade, label) tuple."""
        for threshold, grade, label in self.SCORE_GRADES:
            if score <= threshold:
                return grade, label
        return "F", "Critical"
