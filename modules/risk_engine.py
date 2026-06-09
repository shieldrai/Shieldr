"""
risk_engine.py — RiskEngine Module
=====================================
Central scoring aggregator that normalises findings from all Shieldr
sub-modules into a consistent 0–100 risk score.

The engine applies configurable weights per finding type and severity,
ensuring that the final score is comparable across wallets, tokens,
contracts, and transactions.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("shieldr.risk_engine")


class RiskEngine:
    """
    Aggregates findings from Shieldr sub-modules into a normalised risk score.
    """

    # Default severity weights — can be overridden in settings.yaml
    DEFAULT_WEIGHTS: dict[str, int] = {
        "CRITICAL": 40,
        "HIGH":     20,
        "MEDIUM":   10,
        "LOW":       5,
        "INFO":      0,
    }

    # Score-to-grade mapping: (max_score, grade, label)
    GRADE_THRESHOLDS: list[tuple[int, str, str]] = [
        (15,  "A", "Safe"),
        (35,  "B", "Low Risk"),
        (55,  "C", "Moderate Risk"),
        (75,  "D", "High Risk"),
        (90,  "E", "Very High Risk"),
        (100, "F", "Critical"),
    ]

    def __init__(self, settings: Any) -> None:
        self.settings = settings
        # TODO: allow weight overrides from settings
        self.weights  = dict(self.DEFAULT_WEIGHTS)
        logger.debug("RiskEngine initialised.")

    def compute(self, findings: list[dict]) -> tuple[int, str, str]:
        """
        Compute a final risk score from a list of finding dicts.

        Each finding must contain a `severity` key with one of:
        CRITICAL | HIGH | MEDIUM | LOW | INFO

        Args:
            findings: List of finding dicts from any sub-module.

        Returns:
            Tuple of (score: int, grade: str, label: str).
        """
        total = sum(self.weights.get(f.get("severity", "INFO"), 0) for f in findings)
        score = min(total, 100)
        grade, label = self._score_to_grade(score)
        return score, grade, label

    def _score_to_grade(self, score: int) -> tuple[str, str]:
        """Map a numeric score to (grade, label)."""
        for threshold, grade, label in self.GRADE_THRESHOLDS:
            if score <= threshold:
                return grade, label
        return "F", "Critical"
