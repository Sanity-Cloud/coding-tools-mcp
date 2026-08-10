# Troubleshooting Exec Command

`exec_command` preserves raw `stdout`, `stderr`, and `exit_code`. It may also return `diagnostics` with common failure codes.

Common codes:

- `DEV_NULL_DENIED`: Landlock special device rules are wrong for `/dev/null`.
- `TMPDIR_NOT_WRITABLE`: the configured temp directory is not writable.
- `HOME_NOT_WRITABLE`: the configured home directory is not writable.
- `DNS_RESOLUTION_FAILED`: resolver configuration or network/DNS failed.
- `NETWORK_PERMISSION_REQUIRED`: safe mode blocked a network-looking command.
- `SHELL_EXPANSION_PERMISSION_REQUIRED`: safe mode blocked shell expansion.
- `INLINE_SCRIPT_PERMISSION_REQUIRED`: safe mode blocked inline interpreter or shell code.
- `LANDLOCK_READ_ROOT_BLOCKED`: a toolchain file path is missing from read roots.
- `SECRET_ENV_REJECTED`: secret-looking or loader/startup env was rejected.
- `EXECUTABLE_NOT_FOUND`: direct `argv` execution could not resolve `argv[0]`; PowerShell cmdlets/functions must use `powershell_script` or `cmd` rather than being passed as executables.
- `EXECUTABLE_ACCESS_DENIED`: the executable exists but Windows/OS process creation denied access.
- `EXEC_START_FAILED`: process creation failed before the command could run.
- `COMMAND_TIMED_OUT`: the command exceeded `timeout_ms`.
- `OUTPUT_TRUNCATED`: stdout or stderr exceeded output limits.

## Windows profile and PowerShell environment

On Windows, the default `core` environment includes the session identity paths
that native applications expect: `USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`,
`USERNAME`, `APPDATA`, and `LOCALAPPDATA`. If CodingTools itself was launched
from another restricted CodingTools command and those variables are missing,
the server recovers them directly from `HKCU\Volatile Environment`; it does not
invoke `cmd.exe` or Windows PowerShell to reconstruct them.

By default on Windows, `HOME` is aligned with the authenticated `USERPROFILE`.
This keeps POSIX-style Windows CLIs (OpenSSH, Git helpers, language tools, etc.)
on the same user identity as native applications instead of silently hiding
`~/.ssh`, `~/.gitconfig`, and other user-owned CLI state behind a temporary
CodingTools home. Runtime storage itself remains private under `runtime_dir`;
`TEMP`, `TMP`, and `TMPDIR` continue to use that private runtime directory.

Operators that require the historical isolated command home can set:

```text
CODING_TOOLS_MCP_WINDOWS_HOME_MODE=isolated
```

The default is `host`. `server_info` and `check_exec_environment` report both
the effective command `home` and the private `runtime_home`.

Windows string commands are executed by PowerShell 7 (`pwsh.exe`). Windows
PowerShell 5.1 (`powershell.exe`) is rejected rather than used as a fallback.
When a recursively launched CodingTools server inherits a prior CodingTools
private `TEMP`, runtime storage is re-anchored at the authenticated user's
LocalAppData temp directory to avoid recursively nested runtime paths.

Windows currently reports `tty_supported=false` / `tty_backend=none`. Callers
should not request `tty=true` until a ConPTY backend is available; this is a
declared capability limitation rather than a generic command failure.

## Intentional probes and expected failures

Diagnostic commands often use non-zero exits or timeouts on purpose. To keep
those probes out of the durable incident ledger without hiding the raw result,
use one of the explicit execution expectations:

- `expected_exit_codes: [1, 2, ...]` for known non-zero probe results;
- `expected_timeout: true` when a timeout is the expected observation;
- `diagnostic_mode: "probe"` for a bounded diagnostic command where failure is
  itself the measurement.

The command still returns its real `exit_code`, timeout state, and output. An
expected failing outcome is annotated with `outcome_expected=true` and an
`expectation_reason`; only automatic incident creation is suppressed.

Useful explicit probes:

```bash
dd if=/dev/null of=/dev/null bs=1 count=0
echo hi >/dev/null
printf ok > "$HOME/coding-tools-write-test"
printf ok > "$TMPDIR/coding-tools-write-test"
cat /etc/resolv.conf && getent hosts repo.maven.apache.org
```

## Wrong Toolchain Version (nvm, pyenv, rbenv, asdf)

Symptom: `node --version` in your terminal prints v24, but the same command
through `exec_command` prints the system Node (for example v18).

Cause: version managers only prepend their shim/bin directories to `PATH` in
*interactive shell rc files* (`~/.zshrc`, `~/.bashrc`). When the MCP host that
spawned the server was launched from a GUI (desktop app, IDE), it inherited the
minimal system `PATH`, and `exec_command` — which inherits `PATH` from the
server process under the default `core` policy — resolves `node` to the system
copy.

Fixes, in preference order:

1. **Resolve the login-shell `PATH` in your launcher.** If you control the
   process that spawns the server, ask the user's login shell for its `PATH`
   once at startup (the same trick VS Code and kimi-code use) and spawn the
   server with it, so nvm-selected toolchains work no matter how the host app
   was launched.
2. **Pass the PATH explicitly** in your MCP host config `env` block, or start
   the server with an absolute command path (for example the nvm-versioned
   `.../versions/node/v24.x/bin/node`).
3. **Broaden inheritance** with `--shell-env-inherit all` /
   `CODING_TOOLS_MCP_SHELL_ENV_INHERIT=all` when commands also need variables
   beyond the core set (`NVM_DIR`, `GOPATH`, `JAVA_HOME`, …). Sensitive-looking
   variables are still filtered outside dangerous mode. This mirrors Codex's
   `shell_environment_policy.inherit = "all"` default while keeping this
   server's stricter `core` default.
