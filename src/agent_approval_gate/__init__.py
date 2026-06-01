"""Public API for agent-approval-gate."""
from .classifier import classify_command
from .models import ClassificationResult, Decision, RiskLevel

__all__ = ["ClassificationResult", "Decision", "RiskLevel", "classify_command"]
__version__ = "0.1.0"