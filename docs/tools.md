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
  keys and NIST-curve key exchange, and signs with an RSA key using SHA-1 for a server that lists no
  SHA-2 RSA signatures. `ssh-rsa` host keys are accepted without it, as a last choice.
- **`idle_timeout_seconds`:** closes a connection nobody has used for this long (default 3600, 0
  for never).

## Shells

- A program that answers the POSIX shell setup (sh, bash, zsh, dash, ash) is *managed*:
  `shell_run` reports exit codes, and results say when it is at its prompt.
- The setup is one line `shell_open` types into the shell. It turns off echo, line editing and
  history expansion, makes the prompts invisible markers, clears the hooks run around each command
  and prompt (bash's `PROMPT_COMMAND` and `DEBUG` trap, zsh's `precmd`, `preexec` and
  `zshaddhistory`), unsets `HISTFILE` so no history is saved, and sets the pagers to `cat`. Prompt
  themes, and tools hooked there such as atuin or direnv in bash, do not run.
- Anything else (fish, REPLs, device CLIs), or `raw: true`, is a plain terminal driven with
  `shell_send` and `shell_read`. With `raw: true`, nothing is typed into it.
- A command still running after `wait_seconds` keeps running; `shell_read` reports how it ended.
- A command left incomplete (an unclosed quote or here-document) is canceled.
- A call the client cancels interrupts nothing; its output waits for `shell_read`.
- Each result returns only new output. Full-screen programs are shown as the rendered screen, cut
  to `max_output_bytes`.

## Files

- Remote paths that are relative or start with `~/` start at the login directory. Local paths must
  be absolute or start with `~/`.
- `write_file` and `edit_file` write in place, keeping the owner, permissions and symlinks. On one
  connection they run one at a time, so edits sent together all apply.
- In a file whose lines end in `\r\n`, `edit_file` also matches `\n` line breaks and writes them as
  `\r\n`.
- `upload` and `download` copy folders recursively, with permissions and symlinks. Each file is
  written under a temporary name and renamed into place. An existing destination needs `overwrite`,
  and its parent folder must exist. Folders that already exist keep their permissions.
- Sockets, devices and pipes are skipped inside folders and refused on their own, including by
  `write_file`.
- A canceled `upload`, `download`, `write_file` or `edit_file` stops before its next change.
- `upload` refuses a folder holding a name that is not UTF-8, before it writes anything.

## Limits

- `exec` sends TERM, then KILL, at its timeout; processes it started in the background may survive.
  It stops a command after 64 MiB of output. After the command exits, it returns once output has
  paused for 1 second, and at most 10 seconds later, even if a background process still holds its
  output open.
- A shell keeps at most 16 MiB of unread output. `shell_close` returns at most 64 KiB.
- A server that makes `HISTFILE` read-only, as audit setups do, keeps the whole history, the setup
  line and command wrappers included. zsh set to save each line as it is entered
  (`INC_APPEND_HISTORY`, `SHARE_HISTORY`) saves the setup line unless `HIST_IGNORE_SPACE` is also
  set, and busybox ash may save it too. ksh, which opens its history file at startup, may save
  every line.
- `read_file` and `edit_file` take files up to 64 MiB; `read_file` returns 256 KiB at a time.
- `download` refuses a folder with more than 100,000 entries.
- Servers cap channels per connection (OpenSSH's `MaxSessions`, 10 by default). Each shell,
  running command and SFTP session uses one; a folder download uses two.
- A forwarded connection whose local end stops reading can stall the whole SSH connection.
  `forward_close` stops new connections; those already open go on until they close.
- If the server's SFTP process dies, the file tools fail until the agent reconnects.
- The host key is checked on the first key exchange only, not when keys are renegotiated.
