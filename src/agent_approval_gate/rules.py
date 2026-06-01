"""Built-in and custom rule definitions."""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
import tomllib
from .models import Decision, RiskLevel, RuleMatch
from .shell_utils import normalize_command

@dataclass(frozen=True)
class Rule:
    name: str
    risk: RiskLevel
    decision: Decision
    patterns: tuple[str, ...]
    reason: str

    def matches(self, command: str) -> bool:
        normalized = normalize_command(command)
        lowered = normalized.casefold()
        for pattern in self.patterns:
            if pattern.startswith("re:"):
                if re.search(pattern[3:], normalized, flags=re.IGNORECASE):
                    return True
            elif pattern.casefold() in lowered:
                return True
        return False

    def match(self, command: str) -> RuleMatch | None:
        if not self.matches(command):
            return None
        return RuleMatch(self.name, self.risk, self.decision, self.reason)

def _rule(name: str, risk: RiskLevel, decision: Decision, reason: str, *patterns: str) -> Rule:
    return Rule(name, risk, decision, tuple(patterns), reason)

BUILTIN_RULES: tuple[Rule, ...] = (
    _rule("dangerous_root_delete", RiskLevel.DANGEROUS, Decision.BLOCK, "root or drive deletion detected",
          r"re:^\s*(sudo\s+)?rm\s+-[^\n]*(r|f)[^\n]*(r|f)[^\n]*\s+(/|/[*.]?|[a-z]:\\?)\s*$",
          r"re:^\s*(sudo\s+)?rm\s+-rf\s+(/|[a-z]:\\?)\s*$"),
    _rule("pipe_to_shell", RiskLevel.DANGEROUS, Decision.BLOCK, "download piped directly to a shell detected",
          r"re:\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(bash|sh)\b",
          r"re:\b(Invoke-WebRequest|iwr)\b[^|]*\|\s*iex\b"),
    _rule("dangerous_disk_operation", RiskLevel.DANGEROUS, Decision.BLOCK, "disk formatting or raw disk operation detected",
          r"re:^\s*format\s+[a-z]:", r"re:^\s*diskpart\b", r"re:^\s*mkfs(\.|\s|$)", r"re:^\s*dd\s+.*\bif="),
    _rule("dangerous_recursive_permissions", RiskLevel.DANGEROUS, Decision.BLOCK, "recursive permission or ownership change detected",
          r"re:\bchmod\s+-R\s+777\s+/", r"re:\bchown\s+-R\b"),
    _rule("credential_environment_dump", RiskLevel.CREDENTIAL_RISK, Decision.BLOCK, "environment variable dump may expose credentials",
          r"re:^\s*(printenv|env|set)\s*$", r"re:^\s*(Get-ChildItem|gci)\s+Env:"),
    _rule("credential_file_read", RiskLevel.CREDENTIAL_RISK, Decision.BLOCK, "credential or secret file read detected",
          r"re:^\s*(cat|type|head|tail|more|less)\b.*(\.env|id_rsa|id_dsa|id_ed25519|\.pem\b|\.key\b|token|secret)",
          r"re:^\s*(Get-Content|gc)\b.*(\.env|id_rsa|id_dsa|id_ed25519|\.pem\b|\.key\b|token|secret)"),
    _rule("credential_search", RiskLevel.CREDENTIAL_RISK, Decision.BLOCK, "recursive secret search may expose credentials",
          r"re:^\s*(grep|rg)\b.*\b(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)\b"),
    _rule("delete_recursive", RiskLevel.DELETE, Decision.REQUIRE_APPROVAL, "recursive deletion detected",
          r"re:^\s*rm\s+-[^\n]*(r|f)[^\n]*(r|f)\b", r"re:^\s*Remove-Item\b.*\s-(Recurse|r)\b", r"re:^\s*git\s+clean\s+-[a-z]*f[a-z]*d"),
    _rule("delete_file_or_directory", RiskLevel.DELETE, Decision.REQUIRE_APPROVAL, "file or directory deletion detected",
          r"re:^\s*rm\s+[^-]", r"re:^\s*del\s+", r"re:^\s*erase\s+", r"re:^\s*rmdir\s+", r"re:^\s*Remove-Item\s+"),
    _rule("network_download_or_remote", RiskLevel.NETWORK, Decision.REQUIRE_APPROVAL, "network access detected",
          r"re:^\s*(curl|wget)\b", r"re:^\s*git\s+clone\b", r"re:^\s*(ssh|scp|rsync)\b", r"re:^\s*docker\s+pull\b"),
    _rule("network_package_install", RiskLevel.NETWORK, Decision.REQUIRE_APPROVAL, "package installation may access the network",
          r"re:^\s*(python\s+-m\s+)?pip\s+install\b", r"re:^\s*npm\s+install\b", r"re:^\s*poetry\s+install\b"),
    _rule("run_expensive_test_or_build", RiskLevel.RUN_EXPENSIVE, Decision.REQUIRE_APPROVAL, "test, build, or training command may be long-running",
          r"re:^\s*python\s+(-m\s+)?pytest\b", r"re:^\s*pytest\b(?!.*--version)", r"re:^\s*npm\s+(test|run\s+test)\b",
          r"re:^\s*cargo\s+(build|test)\b", r"re:^\s*docker\s+build\b", r"re:^\s*python\s+.*train.*\.py\b", r"re:^\s*tox\b"),
    _rule("workspace_write_filesystem", RiskLevel.WRITE_WORKSPACE, Decision.REQUIRE_APPROVAL, "workspace file modification detected",
          r"re:^\s*(touch|mkdir|md|New-Item)\b", r"re:^\s*(cp|copy|Copy-Item|mv|move|Move-Item)\b", r"re:^\s*python\s+.*(write|format|fix).*\.py\b"),
    _rule("workspace_write_formatters", RiskLevel.WRITE_WORKSPACE, Decision.REQUIRE_APPROVAL, "formatter or fixer may modify workspace files",
          r"re:^\s*npm\s+run\s+format\b", r"re:^\s*ruff\b.*--fix\b", r"re:^\s*black\b", r"re:^\s*prettier\b.*--write\b"),
    _rule("workspace_write_git_index", RiskLevel.WRITE_WORKSPACE, Decision.REQUIRE_APPROVAL, "git index or history modification detected", r"re:^\s*git\s+(add|commit)\b"),
    _rule("read_repository_state", RiskLevel.READ_ONLY, Decision.ALLOW, "command appears to read repository state", r"re:^\s*git\s+(status|diff|log|show)\b"),
    _rule("read_filesystem_state", RiskLevel.READ_ONLY, Decision.ALLOW, "command appears to read filesystem state",
          r"re:^\s*(ls|dir|pwd|cat|type|head|tail|grep|rg|find)\b", r"re:^\s*(Get-ChildItem|gci|Get-Content|gc)\b"),
    _rule("read_version_info", RiskLevel.READ_ONLY, Decision.ALLOW, "version check is read-only",
          r"re:^\s*(python|py|node|pytest)\s+--version\s*$", r"re:^\s*(python|py)\s+-V\s*$"),
)

def load_custom_rules(path: str | Path) -> list[Rule]:
    rule_path = Path(path)
    try:
        data = tomllib.loads(rule_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"rules file not found: {rule_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid TOML rules file: {exc}") from exc
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError("rules file must contain [[rules]] entries")
    return [_parse_custom_rule(raw_rule, index) for index, raw_rule in enumerate(raw_rules, 1)]

def _parse_custom_rule(raw_rule: dict[str, Any], index: int) -> Rule:
    if not isinstance(raw_rule, dict):
        raise ValueError(f"rule #{index} must be a table")
    try:
        name = str(raw_rule["name"])
        risk = RiskLevel(str(raw_rule["risk"]))
        decision = Decision(str(raw_rule["decision"]))
        patterns_raw = raw_rule["patterns"]
        reason = str(raw_rule["reason"])
    except KeyError as exc:
        raise ValueError(f"rule #{index} missing required field: {exc.args[0]}") from exc
    except ValueError as exc:
        raise ValueError(f"rule #{index} has invalid risk or decision") from exc
    if not isinstance(patterns_raw, list) or not all(isinstance(item, str) for item in patterns_raw):
        raise ValueError(f"rule #{index} patterns must be a list of strings")
    if not name.strip() or not reason.strip():
        raise ValueError(f"rule #{index} name and reason cannot be empty")
    return Rule(name, risk, decision, tuple(patterns_raw), reason)

def match_rules(command: str, rules: Iterable[Rule]) -> list[RuleMatch]:
    return [match for rule in rules if (match := rule.match(command)) is not None]