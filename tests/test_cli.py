import json
from agent_approval_gate.cli import main


def test_json_output_is_valid(capsys):
    exit_code = main(["rm -rf outputs/", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["command"] == "rm -rf outputs/"
    assert payload["risk"] == "delete"
    assert payload["decision"] == "require_approval"
    assert payload["strict"] is False
    assert payload["workspace"] is None


def test_cli_returns_zero_for_normal_classification(capsys):
    exit_code = main(["git", "status"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "risk: read_only" in captured.out
    assert "decision: allow" in captured.out


def test_cli_strict_unknown(capsys):
    exit_code = main(["unknown-command", "--strict"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "risk: unknown" in captured.out
    assert "decision: block" in captured.out


def test_cli_explain_includes_matched_rules(capsys):
    exit_code = main(["rm -rf outputs/", "--explain"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "matched_rules:" in captured.out
    assert "  - delete_recursive" in captured.out