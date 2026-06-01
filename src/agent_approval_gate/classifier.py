"""Transparent rule-based command classifier."""
from __future__ import annotations
from pathlib import Path
from typing import Iterable
from .models import DEFAULT_DECISIONS, DECISION_SEVERITY, RISK_SEVERITY, ClassificationResult, Decision, RiskLevel, RuleMatch
from .rules import BUILTIN_RULES, Rule, load_custom_rules, match_rules
from .shell_utils import normalize_command, resolve_workspace

def classify_command(
    command: str,
    *,
    rules_path: str | Path | None = None,
    workspace: str | None = None,
    strict: bool = False,
    allow_network: bool = False,
    allow_expensive: bool = False,
    custom_rules: Iterable[Rule] | None = None,
) -> ClassificationResult:
    """Classify a command string without executing it."""
    normalized = normalize_command(command)
    resolved_workspace = resolve_workspace(workspace)
    rules: list[Rule] = list(BUILTIN_RULES)
    if custom_rules is not None:
        rules.extend(custom_rules)
    if rules_path is not None:
        rules.extend(load_custom_rules(rules_path))
    matches = match_rules(normalized, rules)
    if not matches:
        decision = Decision.BLOCK if strict else DEFAULT_DECISIONS[RiskLevel.UNKNOWN]
        reason = "unknown command blocked by strict mode" if strict else "command could not be classified confidently"
        return ClassificationResult(normalized, RiskLevel.UNKNOWN, decision, [reason], [], strict, resolved_workspace)
    chosen_risk = _highest_risk(matches)
    chosen_matches = [match for match in matches if match.risk == chosen_risk]
    decision = _decision_for_risk(chosen_risk, chosen_matches)
    if chosen_risk == RiskLevel.NETWORK and decision == Decision.REQUIRE_APPROVAL and allow_network:
        decision = Decision.ALLOW
    elif chosen_risk == RiskLevel.RUN_EXPENSIVE and decision == Decision.REQUIRE_APPROVAL and allow_expensive:
        decision = Decision.ALLOW
    return ClassificationResult(
        command=normalized,
        risk=chosen_risk,
        decision=decision,
        reasons=_unique(match.reason for match in chosen_matches),
        matched_rules=_unique(match.name for match in chosen_matches),
        strict=strict,
        workspace=resolved_workspace,
    )

def _highest_risk(matches: Iterable[RuleMatch]) -> RiskLevel:
    return max((match.risk for match in matches), key=lambda risk: RISK_SEVERITY[risk])

def _decision_for_risk(risk: RiskLevel, matches: Iterable[RuleMatch]) -> Decision:
    default = DEFAULT_DECISIONS[risk]
    return max([default, *(match.decision for match in matches)], key=lambda decision: DECISION_SEVERITY[decision])

def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result