"""Configuration helpers for CLI classification."""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class ClassifierConfig:
    rules_path: str | None = None
    workspace: str | None = None
    strict: bool = False
    allow_network: bool = False
    allow_expensive: bool = False