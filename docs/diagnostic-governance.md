# Diagnostic and Error Governance

Coding Tools treats mistakes, failures, and broken processes as evidence for a
later root-cause and performance-improvement loop.

## Universal rule

When an error is encountered, create a durable diagnostic incident rather than
letting the observation disappear with the current chat, terminal, or process.

Automatic incidents are created for:

- MCP/tool failures (`ok: false`)
- invalid or unknown tool requests
- non-zero `exec_command` / observed `write_stdin` exits
- command timeouts or abnormal termination
- unexpected internal exceptions

Use `record_diagnostic` when the defect is discovered by inspection rather than
thrown by Coding Tools itself, including application errors, failed tests,
upstream protocol/schema drift, corrupted state, recurring warnings, performance
pathologies, or workflow/process defects.

## Durable record

Each occurrence creates:

1. an immutable per-incident JSON report;
2. one append-only `errors.jsonl` ledger entry;
3. a stable fingerprint for grouping recurring failures; and
4. a `diagnostic_receipt` returned to the caller.

The report remains `open` for a later `debug_and_performance_review` task. That
review should determine root cause (or record the evidence gap), identify
recurrence by fingerprint, repair the flawed workflow/process where justified,
run regression/performance verification, and then close or explicitly escalate
the incident.

## Privacy and security boundary

The durable record intentionally does **not** persist raw stdout/stderr, patch or
file content, command bodies, stdin, positional command arguments, or environment
values. Sensitive-looking keys and common secret/token formats are redacted.
Output sizes, exit status, signal, timing, structured diagnostic codes, and
bounded non-content metadata are retained so later analysis can still correlate
failures without turning the diagnostic store into a secret archive.

Default location:

- Windows: `%LOCALAPPDATA%/coding-tools-mcp/diagnostics/<workspace-key>/`
- POSIX: `$XDG_STATE_HOME/coding-tools-mcp/diagnostics/<workspace-key>/`, or
  `~/.local/state/coding-tools-mcp/diagnostics/<workspace-key>/`
- Hermetic runtimes with no resolvable user-state/home directory fall back to a
  workspace-adjacent `.coding-tools-mcp-diagnostics/<workspace-key>/` store.

Configuration:

- `CODING_TOOLS_MCP_DIAGNOSTIC_DIR`: override the diagnostic root.
- `CODING_TOOLS_MCP_DIAGNOSTICS=off`: explicit opt-out.

`server_info` exposes the resolved diagnostic policy and paths.
