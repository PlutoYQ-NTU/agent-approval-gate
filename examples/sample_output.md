# Sample output

```text
$ agent-approval-gate "git status"
risk: read_only
decision: allow
reason: command appears to read repository state
```

```text
$ agent-approval-gate "cat .env"
risk: credential_risk
decision: block
reason: credential or secret file read detected
```

```text
$ agent-approval-gate "rm -rf outputs/" --explain
command: rm -rf outputs/
risk: delete
decision: require_approval
matched_rules:
  - delete_recursive
reasons:
  - recursive deletion detected
```