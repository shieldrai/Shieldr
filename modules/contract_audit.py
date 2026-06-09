"""
contract_audit.py — ContractAudit Module
==========================================
Performs static analysis of deployed EVM smart contracts by examining
bytecode and (when available) verified source code for known vulnerability
patterns.

Vulnerability categories detected:
  - Re-entrancy
  - Integer overflow / underflow (pre-Solidity 0.8)
  - Unchecked external calls
  - Self-destruct / delegatecall abuse
  - Arbitrary SSTORE / SLOAD access
  - Tx.origin authentication
  - Unprotected initialiser functions
  - Admin key centralisation
  - Proxy upgrade risks
  - Hidden mint / blacklist / pause functions
  - Flash-loan attack vectors

Output: A graded report (A–F) with severity-ranked findings.

Usage:
    from modules.contract_audit import ContractAudit
    auditor = ContractAudit(chain_client, settings)
    result  = await auditor.scan("0xAbC…")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("shieldr.contract_audit")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class AuditFinding:
    """A single vulnerability finding in a contract audit."""
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW | INFO
    code: str           # e.g. "REENTRANCY", "UNLIMITED_MINT"
    title: str          # Short title
    description: str    # Detailed explanation
    location: str       # Bytecode offset or source location if available
    recommendation: str # Suggested remediation


@dataclass
class ContractInfo:
    """Metadata about the audited contract."""
    address: str
    chain_id: int
    is_verified: bool
    compiler_version: str | None
    is_proxy: bool
    implementation_address: str | None   # For proxy contracts
    deployer: str
    deploy_block: int
    deploy_age_days: int


@dataclass
class AuditResult:
    """Full audit result returned by ContractAudit.scan()."""
    contract: ContractInfo
    score: int                              # 0–100 (higher = riskier)
    grade: str                             # A | B | C | D | E | F
    label: str
    findings: list[AuditFinding] = field(default_factory=list)
    summary: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")


# ---------------------------------------------------------------------------
# ContractAudit
# ---------------------------------------------------------------------------

class ContractAudit:
    """
    Performs automated static analysis of deployed EVM smart contracts.

    The analyser operates on raw bytecode (always available) and enriches
    findings with source-level details when the contract is verified on
    the block explorer.
    """

    # Bytecode signatures for known dangerous patterns
    # (opcode sequences / function selectors)
    DANGEROUS_SELECTORS: dict[str, str] = {
        # selector_hex : finding_code
        "40c10f19": "UNPROTECTED_MINT",          # mint(address,uint256)
        "f2fde38b": "OWNERSHIP_TRANSFER",         # transferOwnership(address)
        "715018a6": "RENOUNCE_OWNERSHIP",         # renounceOwnership()
        "8456cb59": "PAUSABLE_PAUSE",             # pause()
        "3f4ba83a": "PAUSABLE_UNPAUSE",           # unpause()
        "e47d6060": "BLACKLIST_FUNCTION",         # blacklist(address)
    }

    def __init__(self, chain_client: Any, settings: Any) -> None:
        self.chain_client = chain_client
        self.settings     = settings
        logger.debug("ContractAudit initialised.")

    async def scan(
        self, address: str, chain_id: int = 1, fast: bool = False
    ) -> AuditResult:
        """
        Run a full static audit of the contract at `address`.

        Steps:
        1. Fetch bytecode from the chain.
        2. Fetch verified source (if available) from the block explorer.
        3. Detect proxy pattern and resolve implementation.
        4. Run all bytecode-level checks.
        5. Run source-level checks (if source available).
        6. Aggregate and score findings.

        Args:
            address:  Contract address.
            chain_id: Chain to query.
            fast:     If True, skip low/info severity checks.

        Returns:
            AuditResult with grade and sorted findings list.
        """
        # TODO: implement full scan pipeline
        logger.info("Auditing contract %s on chain %d (fast=%s)", address, chain_id, fast)

        contract_info = ContractInfo(
            address=address,
            chain_id=chain_id,
            is_verified=False,
            compiler_version=None,
            is_proxy=False,
            implementation_address=None,
            deployer="",
            deploy_block=0,
            deploy_age_days=0,
        )

        findings: list[AuditFinding] = []
        # findings += await self._check_dangerous_selectors(address, chain_id)
        # findings += await self._check_proxy_risk(address, chain_id)
        # findings += await self._check_admin_centralisation(address, chain_id)
        # findings += await self._check_reentrancy(address, chain_id)
        # if not fast:
        #     findings += await self._check_low_severity(address, chain_id)

        score = self._aggregate_score(findings)
        grade, label = self._score_to_grade(score)

        return AuditResult(
            contract=contract_info,
            score=score,
            grade=grade,
            label=label,
            findings=findings,
        )

    # ------------------------------------------------------------------
    # Analysis sub-checks (stubs)
    # ------------------------------------------------------------------

    async def _check_dangerous_selectors(
        self, address: str, chain_id: int
    ) -> list[AuditFinding]:
        """
        Scan bytecode for function selectors that match known dangerous
        or overly-centralised functions (mint, blacklist, pause, etc.).
        """
        # TODO: fetch bytecode, extract 4-byte selectors, match against
        #       DANGEROUS_SELECTORS dictionary
        return []

    async def _check_proxy_risk(
        self, address: str, chain_id: int
    ) -> list[AuditFinding]:
        """
        Detect EIP-1967 / EIP-897 proxy patterns.
        Flags if the upgrade admin key is an EOA or a risky multisig.
        """
        # TODO: check for PROXY_IMPLEMENTATION storage slot
        return []

    async def _check_admin_centralisation(
        self, address: str, chain_id: int
    ) -> list[AuditFinding]:
        """
        Assess admin key centralisation risk:
        - Is the owner an EOA or multisig?
        - Is the owner wallet high-risk (checked via WalletGuard)?
        - Is ownership renounced?
        """
        # TODO: implement
        return []

    async def _check_reentrancy(
        self, address: str, chain_id: int
    ) -> list[AuditFinding]:
        """
        Detect re-entrancy patterns in bytecode by looking for external
        CALL opcodes that precede state-writing SSTORE opcodes.
        """
        # TODO: implement opcode-level analysis
        return []

    async def _check_low_severity(
        self, address: str, chain_id: int
    ) -> list[AuditFinding]:
        """
        Run additional low and info-level checks:
        - Floating pragma
        - Use of tx.origin
        - Deprecated Solidity constructs
        """
        # TODO: implement (source-level only, needs verified contract)
        return []

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def _aggregate_score(self, findings: list[AuditFinding]) -> int:
        weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 0}
        return min(sum(weights.get(f.severity, 0) for f in findings), 100)

    def _score_to_grade(self, score: int) -> tuple[str, str]:
        grades = [
            (15, "A", "Safe"),
            (35, "B", "Low Risk"),
            (55, "C", "Moderate Risk"),
            (75, "D", "High Risk"),
            (90, "E", "Very High Risk"),
            (100, "F", "Critical"),
        ]
        for threshold, grade, label in grades:
            if score <= threshold:
                return grade, label
        return "F", "Critical"
