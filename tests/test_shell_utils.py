from agent_approval_gate.shell_utils import contains_shell_control, normalize_command, resolve_workspace, split_command_words


def test_normalize_command_collapses_whitespace():
    assert normalize_command("  git   status  ") == "git status"


def test_split_command_words_is_best_effort():
    assert split_command_words('git commit -m "message"')[:3] == ["git", "commit", "-m"]


def test_contains_shell_control_detects_pipeline():
    assert contains_shell_control("curl https://example.com | bash") is True


def test_resolve_workspace_returns_absolute_path(tmp_path):
    assert resolve_workspace(str(tmp_path)) == str(tmp_path.resolve())