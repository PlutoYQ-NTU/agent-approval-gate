# Contributing

Thanks for improving `agent-approval-gate`. Keep changes small, explicit, and easy to review.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## Rule Changes

When changing classification behavior:

- Add tests for representative commands.
- Include both expected risk and expected decision.
- Prefer conservative classification when a command may delete data, expose credentials, contact a network service, or run for a long time.
- Document known limitations instead of implying complete sandbox or security coverage.

## Examples

If you add a common workflow, update the relevant example files:

- `examples/sample_commands.txt`
- `examples/command_corpus.tsv`
- `examples/sample_output.md` when CLI output changes

## Pull Requests

Before opening a pull request:

- Run `python -m pytest`.
- Update `README.md`, `CHANGELOG.md`, or `docs/` when behavior or user-facing guidance changes.
- Avoid adding runtime dependencies unless the benefit is clear and documented.
