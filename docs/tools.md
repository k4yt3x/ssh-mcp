# Tools

## Connecting

- **Credentials:** `private_key` or `private_key_file` (with `private_key_passphrase` if it is
  encrypted), optionally `certificate` or `certificate_file`, and `password` for password and
  keyboard-interactive login. Methods are tried as the server offers them, so two-step logins work.
- **Host key:** `host_key_fingerprint`, `known_hosts_file` or `accept_new_host_key`; see
  [security](security.md).
- **`via`:** the token of another connection to use as a jump host. Disconnecting the jump host
  closes the connections through it.
- **`allow_legacy_algorithms`:** also offers SHA-1 key exchange and MACs, CBC and 3DES ciphers, DSA
  keys and NIST-curve key exchange. `ssh-rsa` host keys are accepted without it, as a last choice.
- **`idle_timeout_seconds`:** closes a connection nobody has used for this long (default 3600, 0
  for never).

## Shells

- A program that answers the POSIX shell setup (sh, bash, zsh, dash, ash) is *managed*:
  `shell_run` reports exit codes, results say when it is at its prompt, and pagers are `cat`.
- Anything else (fish, REPLs, device CLIs), or `raw: true`, is a plain terminal driven with
  `shell_send` and `shell_read`.
- A command still running after `wait_seconds` keeps running; `shell_read` reports how it ended.
- A command left incomplete (an unclosed quote or here-document) is canceled.
- A call the client cancels interrupts nothing; its output waits for `shell_read`.
- Each result returns only new output. Full-screen programs are shown as the rendered screen.

## Files

- Remote paths that are relative or start with `~/` start at the login directory. Local paths must
  be absolute or start with `~/`.
- `write_file` and `edit_file` write in place, keeping the owner, permissions and symlinks.
- `upload` and `download` copy folders recursively, with permissions and symlinks. Each file is
  written under a temporary name and renamed into place. An existing destination needs `overwrite`.
- Sockets, devices and pipes are skipped.

## Limits

- `exec` sends TERM, then KILL, at its timeout; processes it started in the background may survive.
  It stops a command after 64 MiB of output, and returns 1 second after the command exits even if
  a background process still holds its output open.
- A shell keeps at most 16 MiB of unread output. `shell_close` returns at most 64 KiB.
- `read_file` and `edit_file` take files up to 64 MiB; `read_file` returns 256 KiB at a time.
- `download` refuses a folder with more than 100,000 entries.
- Servers cap channels per connection (OpenSSH's `MaxSessions`, 10 by default). Each shell,
  running command and SFTP session uses one; a folder download uses two.
- A forwarded connection whose local end stops reading can stall the whole SSH connection.
- If the server's SFTP process dies, the file tools fail until the agent reconnects.
- The host key is checked on the first key exchange only, not when keys are renegotiated.
