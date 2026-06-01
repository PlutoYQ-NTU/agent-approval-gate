"""JSON output helpers."""
from __future__ import annotations
import json
from .models import ClassificationResult

def result_to_dict(result: ClassificationResult) -> dict[str, object]:
    return result.to_dict()

def result_to_json(result: ClassificationResult) -> str:
    return json.dumps(result_to_dict(result), indent=2, sort_keys=False)