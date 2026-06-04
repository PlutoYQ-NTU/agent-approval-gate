# Policy Profiles

`agent-approval-gate` exposes a small set of CLI flags that can be combined into practical policy profiles. These profiles are conventions for local agent controllers and scripts; they are not a sandbox and do not enforce operating-system permissions.

## Default

Use this when a human can approve non-read-only actions:

```bash
agent-approval-gate "git status"
agent-approval-gate "python -m pytest"
```

Default behavior:

- `read_only`: `allow`
- `write_workspace`, `run_expensive`, `network`, and `delete`: `require_approval`
- `credential_risk` and `dangerous`: `block`
- `unknown`: `require_approval`

## Strict

Use this when unknown commands should not proceed without policy updates:

```bash
agent-approval-gate "custom-tool --flag" --strict
```

Strict mode changes only `unknown` commands from `require_approval` to `block`.

## Network-Friendly

Use this only for trusted workflows where non-dangerous network access is expected:

```bash
agent-approval-gate "git pull --ff-only" --allow-network
```

This downgrades `network` commands to `allow`. It does not allow commands that are classified as `credential_risk` or `dangerous`, such as pipe-to-shell installers.

## Expensive-Friendly

Use this for trusted CI-like loops where tests and builds are expected:

```bash
agent-approval-gate "python -m pytest" --allow-expensive
```

This downgrades `run_expensive` commands to `allow`. It does not allow network, deletion, credential-risk, or dangerous commands.

## Custom Rules

Custom TOML rules can tighten or extend a profile:

```bash
agent-approval-gate "deploy production" --rules examples/rules.example.toml --strict
```

Built-in rules and custom rules are both evaluated. The highest severity risk wins.

## Limitations

- Profiles classify command strings; they do not execute, sandbox, or authorize commands.
- Shell aliases, scripts, functions, environment variables, and platform-specific parsing can hide risk.
- Treat these profiles as one approval signal alongside OS permissions, isolated workspaces, backups, and human review.
