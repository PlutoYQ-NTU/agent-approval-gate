from pathlib import Path
from agent_approval_gate import classify_command
from agent_approval_gate.rules import load_custom_rules


def test_custom_rules_file_works(tmp_path: Path):
    rules_path = tmp_path / "rules.toml"
    rules_path.write_text('''
[[rules]]
name = "block_deploy"
risk = "dangerous"
decision = "block"
patterns = ["deploy production"]
reason = "production deploy blocked"
'''.lstrip(), encoding="utf-8")
    result = classify_command("deploy production", rules_path=rules_path)
    assert result.risk == "dangerous"
    assert result.decision == "block"
    assert result.matched_rules == ["block_deploy"]


def test_custom_regex_rule_works(tmp_path: Path):
    rules_path = tmp_path / "rules.toml"
    rules_path.write_text(r'''
[[rules]]
name = "block_force_prod"
risk = "dangerous"
decision = "block"
patterns = ['re:\bprod\b.*--force']
reason = "forced production operation blocked"
'''.lstrip(), encoding="utf-8")
    result = classify_command("deploy prod --force", rules_path=rules_path)
    assert result.risk == "dangerous"
    assert result.decision == "block"


def test_load_custom_rules_rejects_invalid_file(tmp_path: Path):
    rules_path = tmp_path / "rules.toml"
    rules_path.write_text("rules = {}", encoding="utf-8")
    try:
        load_custom_rules(rules_path)
    except ValueError as exc:
        assert "[[rules]]" in str(exc)
    else:
        raise AssertionError("expected ValueError")