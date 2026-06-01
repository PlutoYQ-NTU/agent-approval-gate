"""Shared models for command classification."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import StrEnum

class RiskLevel(StrEnum):
    READ_ONLY = "read_only"
    WRITE_WORKSPACE = "write_workspace"
    RUN_EXPENSIVE = "run_expensive"
    NETWORK = "network"
    DELETE = "delete"
    CREDENTIAL_RISK = "credential_risk"
    DANGEROUS = "dangerous"
    UNKNOWN = "unknown"

class Decision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"

RISK_SEVERITY = {
    RiskLevel.UNKNOWN: 0,
    RiskLevel.READ_ONLY: 10,
    RiskLevel.WRITE_WORKSPACE: 20,
    RiskLevel.RUN_EXPENSIVE: 30,
    RiskLevel.NETWORK: 40,
    RiskLevel.DELETE: 50,
    RiskLevel.CREDENTIAL_RISK: 60,
    RiskLevel.DANGEROUS: 70,
}
DECISION_SEVERITY = {Decision.ALLOW: 10, Decision.REQUIRE_APPROVAL: 20, Decision.BLOCK: 30}
DEFAULT_DECISIONS = {
    RiskLevel.READ_ONLY: Decision.ALLOW,
    RiskLevel.WRITE_WORKSPACE: Decision.REQUIRE_APPROVAL,
    RiskLevel.RUN_EXPENSIVE: Decision.REQUIRE_APPROVAL,
    RiskLevel.NETWORK: Decision.REQUIRE_APPROVAL,
    RiskLevel.DELETE: Decision.REQUIRE_APPROVAL,
    RiskLevel.CREDENTIAL_RISK: Decision.BLOCK,
    RiskLevel.DANGEROUS: Decision.BLOCK,
    RiskLevel.UNKNOWN: Decision.REQUIRE_APPROVAL,
}

@dataclass(frozen=True)
class RuleMatch:
    name: str
    risk: RiskLevel
    decision: Decision
    reason: str

@dataclass(frozen=True)
class ClassificationResult:
    command: str
    risk: RiskLevel
    decision: Decision
    reasons: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    strict: bool = False
    workspace: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "command": self.command,
            "risk": self.risk.value,
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "matched_rules": list(self.matched_rules),
            "strict": self.strict,
            "workspace": self.workspace,
        }