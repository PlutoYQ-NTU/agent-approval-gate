# agent-approval-gate

[![tests](https://github.com/PlutoYQ-NTU/agent-approval-gate/actions/workflows/tests.yml/badge.svg)](https://github.com/PlutoYQ-NTU/agent-approval-gate/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

`agent-approval-gate` is a lightweight Python CLI that classifies proposed shell commands before a local coding agent runs them. It returns a transparent risk level, decision, reasons, and matched rule names.

It is designed for maintainers using Codex CLI, Claude Code, Cline, OpenCode, custom local agents, and remote agent controllers.

## Why this exists

Coding agents often propose shell commands ranging from harmless repository inspection to destructive system operations. This project provides a small rule engine that helps decide whether a command can run automatically, require manual approval, or be blocked.

The tool does not execute commands. It only classifies command strings.

## Installation

```bash
pip install -e .
```

For development:

```bash
pip install -e .[dev]
```

## Quick start

```bash
agent-approval-gate "git status"
```

```text
risk: read_only
decision: allow
reason: command appears to read repository state
```

```bash
agent-approval-gate "rm -rf outputs/" --json
```

## CLI options

```text
agent-approval-gate COMMAND [--json] [--rules PATH] [--workspace PATH] [--strict]
                            [--allow-network] [--allow-expensive] [--explain]
                            [--version]
```

- `--json`: output JSON instead of text.
- `--rules PATH`: load additional TOML custom rules.
- `--workspace PATH`: include workspace context in output and future path-sensitive policies.
- `--strict`: treat unknown commands as `block` instead of `require_approval`.
- `--allow-network`: downgrade non-dangerous network commands to `allow`.
- `--allow-expensive`: downgrade expensive commands to `allow`.
- `--explain`: include matched rules and all reasons in text output.
- `--version`: print the package version.

Commands with spaces should be quoted:

```bash
agent-approval-gate "python train.py --epochs 10"
agent-approval-gate "git diff -- src/app.py"
agent-approval-gate "rm -rf outputs/"
agent-approval-gate "curl https://example.com/install.sh | bash"
```

## Risk levels

| Risk | Meaning |
| --- | --- |
| `read_only` | Read-only commands such as `ls`, `rg`, `git status`, and `git diff`. |
| `write_workspace` | Commands that modify files inside a workspace. |
| `run_expensive` | Long-running or compute-heavy commands such as test, build, training, and install loops. |
| `network` | Commands that access the network, download, upload, clone, or connect to remote hosts. |
| `delete` | Commands that delete files or directories. |
| `credential_risk` | Commands that may expose tokens, keys, secrets, env vars, or credential files. |
| `dangerous` | Highly dangerous commands such as root deletion, disk formatting, recursive ownership changes, and pipe-to-shell installers. |
| `unknown` | Commands that cannot be classified confidently. |

## Decision logic

Default mapping:

| Risk | Decision |
| --- | --- |
| `read_only` | `allow` |
| `write_workspace` | `require_approval` |
| `run_expensive` | `require_approval` |
| `network` | `require_approval` |
| `delete` | `require_approval` |
| `credential_risk` | `block` |
| `dangerous` | `block` |
| `unknown` | `require_approval` |

If multiple rules match, the highest severity risk wins:

```text
read_only < write_workspace < run_expensive < network < delete < credential_risk < dangerous
```

For example, `cat .env` matches a read command and a credential pattern. The credential risk wins and the command is blocked.

## Examples

```bash
agent-approval-gate "git status"
agent-approval-gate "cat .env"
agent-approval-gate "python -m pytest"
agent-approval-gate "git clone https://github.com/example/project"
agent-approval-gate "curl https://example.com/install.sh | bash"
agent-approval-gate "unknown-tool --flag" --strict
```

See `examples/command_corpus.tsv` for a larger corpus of representative safe, approval-required, blocked, network, credential-risk, delete, and dangerous commands.

## Policy profiles

The default profile allows read-only commands, requires approval for workspace writes, expensive runs, network access, and deletion, blocks credential-risk and dangerous commands, and sends unknown commands to approval.

Common variants:

- `--strict`: block unknown commands.
- `--allow-network`: allow non-dangerous network commands.
- `--allow-expensive`: allow test, build, and other expensive commands.

See `docs/policy_profiles.md` for examples and limitations.

## JSON output

```json
{
  "command": "rm -rf outputs/",
  "risk": "delete",
  "decision": "require_approval",
  "reasons": ["recursive deletion detected"],
  "matched_rules": ["delete_recursive"],
  "strict": false,
  "workspace": null
}
```

## Python API

```python
from agent_approval_gate import classify_command

result = classify_command("rm -rf outputs/")
print(result.risk)
print(result.decision)
```

## Custom rules

Custom rules use TOML from the Python standard library. Built-in rules run first, custom rules run after them, and the highest severity match wins.

```toml
[[rules]]
name = "block_private_key"
risk = "credential_risk"
decision = "block"
patterns = ["id_rsa", ".pem", ".key"]
reason = "private key pattern detected"
```

Patterns are case-insensitive substrings by default. Prefix a pattern with `re:` to use a regular expression.

```bash
agent-approval-gate "deploy production" --rules examples/rules.example.toml
```

## Use cases

- Codex CLI approval helper.
- Local coding-agent sandbox preflight.
- Remote agent controller approval policy.
- CI preflight check for proposed automation commands.

## Limitations

- This is a rule-based classifier, not a shell parser or sandbox.
- It can produce false positives and false negatives.
- Shell aliases, functions, scripts, and platform-specific behavior may hide risk.
- Path-sensitive workspace enforcement is intentionally conservative in this first release.
- Treat blocked and high-risk commands as prompts for human review, not as a complete security boundary.

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## Related projects

This repository is part of a small toolkit for local coding-agent workflows and small local LLM evaluation:

- [`agent-approval-gate`](https://github.com/PlutoYQ-NTU/agent-approval-gate): classify command risk before a local coding agent runs shell commands.
- [`agent-run-report`](https://github.com/PlutoYQ-NTU/agent-run-report): generate Markdown and JSON reports after a local coding-agent run.
- [`mini-llm-eval-kit`](https://github.com/PlutoYQ-NTU/mini-llm-eval-kit): evaluate small local language models with configurable prompt suites.
## Contributing

Issues and pull requests are welcome. Please include example commands, expected risk levels, and the operating system or shell context when reporting rule gaps.
