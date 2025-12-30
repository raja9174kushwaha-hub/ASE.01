from collections import defaultdict
from typing import Dict, List

from logging_utils import get_logger
from models import CategoryScore, Finding, RiskSummary

logger = get_logger(__name__)


def create_finding(
    *,
    id: str,
    title: str,
    category: str,
    description: str,
    recommendation: str,
    likelihood: int,
    impact: int,
    source: str,
) -> Finding:
    """Helper to create a Finding with computed raw_score and severity."""
    # Updated to 5x5 Risk Matrix
    likelihood = max(1, min(5, likelihood))
    impact = max(1, min(5, impact))
    
    raw_score = likelihood * impact
    severity = _severity_from_raw(raw_score)
    
    finding = Finding(
        id=id,
        title=title,
        category=category,
        severity=severity,
        description=description,
        recommendation=recommendation,
        likelihood=likelihood,
        impact=impact,
        raw_score=raw_score,
        source=source,
    )
    logger.info("Finding created: %s (%s, raw=%d)", id, severity, raw_score)
    return finding


def _severity_from_raw(raw: int) -> str:
    """
    Standard OWASP-style 5x5 Risk Mapping
    Max Score = 25 (5x5)
    """
    if raw >= 16:
        return "Critical"
    if raw >= 9:
        return "High"
    if raw >= 4:
        return "Medium"
    return "Low"  # 1-3


def aggregate_risk(findings: List[Finding]) -> RiskSummary:
    """Aggregate findings into category scores and an overall score (0–10)."""
    if not findings:
        logger.info("No findings; returning baseline low risk summary.")
        return RiskSummary(
            overall_score=0.0,
            overall_severity="Low",
            category_scores=[],
        )

    cat_raw: Dict[str, int] = defaultdict(int)
    total_raw = 0
    for f in findings:
        cat_raw[f.category] += f.raw_score
        total_raw += f.raw_score

    logger.info("Total raw risk before normalization: %d", total_raw)

    # Normalize to 0-10 scale
    # With 5x5 matrix, a single Critical is 25 points.
    # We want a score of 10.0 to represent "Very High Risk" (e.g. ~4 Criticals or mixed Highs)
    max_considered = 100.0 
    
    overall_score = min(10.0, (total_raw / max_considered) * 10.0)
    overall_severity = _severity_from_score(overall_score)

    category_scores: List[CategoryScore] = []
    for cat, raw in cat_raw.items():
        # Category scores use a local normalization
        # 1 Critical (25) in a category should push it to High/Critical range
        cat_score = min(10.0, (raw / 25.0) * 10.0) 
        cat_sev = _severity_from_score(cat_score)
        category_scores.append(
            CategoryScore(category=cat, score=cat_score, severity=cat_sev)
        )

    logger.info(
        "Aggregate risk: overall_score=%.2f, severity=%s",
        overall_score,
        overall_severity,
    )

    return RiskSummary(
        overall_score=overall_score,
        overall_severity=overall_severity,
        category_scores=category_scores,
    )


def _severity_from_score(score: float) -> str:
    """Maps 0-10 score to text severity."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"
