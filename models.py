from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str  # Low, Medium, High
    description: str
    recommendation: str
    likelihood: int  # 1–3
    impact: int  # 1–3
    raw_score: int  # likelihood * impact
    source: str  # "json", "url", "simulation"


@dataclass
class CategoryScore:
    category: str
    score: float  # 0–10
    severity: str  # Low, Medium, High


@dataclass
class RiskSummary:
    overall_score: float  # 0–10
    overall_severity: str
    category_scores: List[CategoryScore] = field(default_factory=list)


@dataclass
class URLScanResult:
    original_url: str
    final_url: str
    https: bool
    status_code: int
    headers: Dict[str, Any]
    elapsed_ms: float
    redirect_chain: List[str] = field(default_factory=list)


# --- RBAC Models ---
from enum import Enum

class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"

@dataclass
class User:
    id: str
    name: str
    email: str
    role: UserRole
    provider: str = "local"
    permissions: List[str] = field(default_factory=list)
