# Security Policy

`agent-approval-gate` does not execute commands. It only classifies command strings.

This project is not a sandbox, not an operating-system permission layer, and not a complete security boundary. It is a transparent rule-based preflight check intended to help humans and local agent controllers decide when a proposed command needs approval.

The classifier can produce false positives and false negatives. Dangerous commands should still be reviewed manually, especially when they involve deletion, credentials, network downloads, pipe-to-shell installers, disk operations, privilege escalation, or recursive permission changes.

Use this tool alongside stronger controls such as OS user permissions, containers or virtual machines, Git worktrees or disposable checkouts, backups, explicit command allowlists, and human approval for destructive or credential-touching operations.