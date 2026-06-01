"""Small shell-string helpers that never execute input commands."""
from __future__ import annotations
import re
import shlex
from pathlib import Path

_CONTROL_OPERATOR_RE = re.compile(r"(\|\||&&|;|\||`|\$\(|>|<)")
_WHITESPACE_RE = re.compile(r"\s+")

def normalize_command(command: str) -> str:
    return _WHITESPACE_RE.sub(" ", command.strip())

def lower_command(command: str) -> str:
    return normalize_command(command).casefold()

def split_command_words(command: str) -> list[str]:
    normalized = normalize_command(command)
    if not normalized:
        return []
    try:
        return shlex.split(normalized, posix=False)
    except ValueError:
        return normalized.split()

def contains_shell_control(command: str) -> bool:
    return bool(_CONTROL_OPERATOR_RE.search(command))

def resolve_workspace(workspace: str | None) -> str | None:
    if workspace is None:
        return None
    return str(Path(workspace).expanduser().resolve())