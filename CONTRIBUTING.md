# Contributing

Thanks for helping improve `agent-approval-gate`. Keep changes small, explainable, and covered by tests because policy changes can alter whether commands are allowed, reviewed, or blocked.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## Policy changes

- Add or update tests for every new rule or classification change.
- Include safe and adversarial examples, including quoting and shell-composition variants.
- Avoid real credentials, private paths, or organization-specific commands in fixtures.
- Describe false-allow and false-block tradeoffs in the pull request.

Security-sensitive findings should follow [SECURITY.md](SECURITY.md) instead of being posted publicly.
