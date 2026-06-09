"""
report_builder.py — ReportBuilder Module
==========================================
Formats raw analysis results from Shieldr sub-modules into clean,
human-readable report strings for delivery via Bankr.bot.

All reports follow the standard Shieldr report layout:

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    🛡️  SHIELDR REPORT
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Target  : <address or url>  (<type>)
    Chain   : <chain name>
    Checked : <timestamp> UTC

    RISK SCORE   : <score> / 100  (<grade> — <label>)

    FINDINGS
      [SEVERITY]  <message>
      …

    RECOMMENDATION
      <one-line recommended action>

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("shieldr.report_builder")

# Report divider line
DIV = "━" * 44


class ReportBuilder:
    """
    Converts structured analysis results into formatted report strings.
    """

    def __init__(self) -> None:
        logger.debug("ReportBuilder initialised.")

    # ------------------------------------------------------------------
    # Public build methods (one per report type)
    # ------------------------------------------------------------------

    def build_wallet_report(self, result: Any, brief: bool = False) -> str:
        """
        Format a WalletRiskResult into a readable wallet report.

        Args:
            result: WalletRiskResult from WalletGuard.
            brief:  If True, return a compact one-liner instead.
        """
        # TODO: implement full formatter
        if brief:
            return (
                f"🛡️ Wallet `{result.address}` — "
                f"Score: **{result.score}/100** ({result.grade} · {result.label})"
            )
        return self._stub_report("Wallet", result.address, result.score, result.grade, result.label)

    def build_tx_report(self, result: Any) -> str:
        """Format a TxSimResult into a pre-flight transaction report."""
        # TODO: include token deltas, approval grants, and findings
        return self._stub_report("Transaction", result.tx_hash_or_hex[:20] + "…", result.risk_score, result.grade, result.label)

    def build_approve_report(self, result: Any) -> str:
        """Format an approval analysis result."""
        # TODO: highlight unlimited approvals prominently
        return self._stub_report("Approval", result.tx_hash_or_hex, result.risk_score, result.grade, result.label)

    def build_audit_report(self, result: Any) -> str:
        """Format a ContractAuditResult into a graded contract report."""
        # TODO: show findings grouped by severity
        return self._stub_report("Contract", result.contract.address, result.score, result.grade, result.label)

    def build_token_report(self, result: Any) -> str:
        """Format a TokenRadarResult into a token safety report."""
        # TODO: include honeypot result, liquidity, holder concentration
        return self._stub_report("Token", result.token_address, result.score, result.grade, result.label)

    def build_url_report(self, result: Any) -> str:
        """Format a UrlThreatResult into a phishing verdict report."""
        # TODO: list matched feeds and heuristic findings
        verdict = "🚨 MALICIOUS" if result.is_malicious else "✅ Clean"
        return (
            f"{DIV}\n"
            f"🎣  SHIELDR — URL CHECK\n"
            f"{DIV}\n"
            f"  URL     : {result.url}\n"
            f"  Verdict : {verdict}\n"
            f"  Feeds   : {', '.join(result.matched_feeds) or 'None flagged'}\n"
            f"{DIV}"
        )

    def build_sig_report(self, result: Any) -> str:
        """Format a SignatureRiskResult into a signature risk report."""
        # TODO: show decoded fields and plain-English explanation
        risk_label = "⚠️ RISKY" if result.is_risky else "✅ Appears safe"
        return (
            f"{DIV}\n"
            f"✍️  SHIELDR — SIGNATURE ANALYSIS\n"
            f"{DIV}\n"
            f"  Type    : {result.sig_type}\n"
            f"  Verdict : {risk_label}\n"
            f"  Score   : {result.risk_score}/100\n"
            f"{DIV}"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _stub_report(
        self, target_type: str, target: str, score: int, grade: str, label: str
    ) -> str:
        """Generate a generic stub report (used until full formatters are built)."""
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
        score_emoji = self._score_emoji(score)
        return (
            f"{DIV}\n"
            f"🛡️  SHIELDR REPORT\n"
            f"{DIV}\n"
            f"  Target  : {target}  ({target_type})\n"
            f"  Checked : {now} UTC\n\n"
            f"  RISK SCORE   : {score_emoji} {score} / 100  ({grade} — {label})\n\n"
            f"  FINDINGS\n"
            f"    (full analysis coming in next release)\n\n"
            f"  RECOMMENDATION\n"
            f"    {'Proceed normally.' if score <= 15 else 'Review flagged items before proceeding.'}\n"
            f"{DIV}"
        )

    @staticmethod
    def _score_emoji(score: int) -> str:
        """Return an emoji indicator for the given score."""
        if score <= 15:  return "✅"
        if score <= 35:  return "🟢"
        if score <= 55:  return "🟡"
        if score <= 75:  return "🟠"
        if score <= 90:  return "🔴"
        return "🚨"
