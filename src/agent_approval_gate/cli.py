"""Command line interface for agent-approval-gate."""
from __future__ import annotations
import argparse
from collections.abc import Sequence
from . import __version__
from .classifier import classify_command
from .config import ClassifierConfig
from .json_writer import result_to_json

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-approval-gate", description="Classify shell command risk before a local coding agent executes it.")
    parser.add_argument("command", nargs="*", metavar="COMMAND", help="command string to classify")
    parser.add_argument("--json", action="store_true", help="output JSON instead of text")
    parser.add_argument("--rules", metavar="PATH", help="optional TOML custom rules file")
    parser.add_argument("--workspace", metavar="PATH", help="optional workspace path for path-sensitive context")
    parser.add_argument("--strict", action="store_true", help="treat unknown commands as block")
    parser.add_argument("--allow-network", action="store_true", help="allow non-dangerous network commands")
    parser.add_argument("--allow-expensive", action="store_true", help="allow expensive commands")
    parser.add_argument("--explain", action="store_true", help="include matched rules and all reasons in text output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser

def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = " ".join(args.command).strip()
    if not command:
        parser.error("COMMAND is required")
    config = ClassifierConfig(args.rules, args.workspace, args.strict, args.allow_network, args.allow_expensive)
    try:
        result = classify_command(command, rules_path=config.rules_path, workspace=config.workspace, strict=config.strict, allow_network=config.allow_network, allow_expensive=config.allow_expensive)
    except ValueError as exc:
        parser.exit(2, f"agent-approval-gate: error: {exc}\n")
    print(result_to_json(result) if args.json else _format_text(result, explain=args.explain))
    return 0

def _format_text(result, *, explain: bool) -> str:
    if explain:
        lines = [f"command: {result.command}", f"risk: {result.risk.value}", f"decision: {result.decision.value}", "matched_rules:"]
        if result.matched_rules:
            lines.extend(f"  - {rule}" for rule in result.matched_rules)
        else:
            lines.append("  - none")
        lines.append("reasons:")
        lines.extend(f"  - {reason}" for reason in result.reasons)
        return "\n".join(lines)
    reason = result.reasons[0] if result.reasons else "no reason provided"
    return "\n".join([f"risk: {result.risk.value}", f"decision: {result.decision.value}", f"reason: {reason}"])

if __name__ == "__main__":
    raise SystemExit(main())