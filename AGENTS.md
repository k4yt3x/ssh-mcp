# AGENTS.md

Guidance for AI agents working in this repository: general principles, Rust practice, then the rules
specific to ssh-mcp.

---

# General principles

## Code

- Correctness and clarity first. Speed and efficiency are secondary unless stated otherwise.
- Comments explain *why*, never *what*: a constraint from outside this file, or why an
  obvious-looking alternative is wrong. Not history and not user documentation; `git log`, the
  README and `docs/` hold those. If it restates the code, delete it.
- Add functionality to existing files unless it is genuinely a new component. Avoid many small files.
- No creative additions beyond what was asked.
- Full words in names, no abbreviations.

## Enumerate the doors

Most defects that survive review are one rule enforced at one entry point and not at its siblings.
Before writing a guard, list every path that reaches the thing being guarded and decide for each.
Place the check where those paths converge, give an invariant asked in more than one place a single
named predicate, and put a guard ahead of every side effect it protects.

## Verification

Per change: the build, the test suite and the exact CI lint gate below. Fake-guard every test written
to protect a fix: neuter the fix, confirm the test fails, restore. Reproduce a defect before fixing
it and re-run the reproduction after. A test earns its place by being able to fail.

## Whose fact is it

If another system owns a fact, ask it or let the caller state it; never encode it. Here that means
an SSH server's facts (its algorithms, its paths, its defaults) are asked of the server, and the
agent's facts (keys, passwords, expected host keys) arrive as tool arguments.

## Changelog

- Update `CHANGELOG.md` for every change a user can notice, under `[Unreleased]`.
- [Keep a Changelog 2.0.0](https://keepachangelog.com/en/2.0.0/): only Added, Changed, Deprecated,
  Removed, Fixed and Security, in that order.
- Written for users: what they will see, break on or must do, one line per entry under 100
  characters. No internal names or module paths. Breaking changes get an inline `**Breaking:**`
  prefix.
- Short enough to read: not a commit log. Group related fixes into one entry, and leave out wording
  tweaks and fixes nobody would notice.
- A release is a tag named by the bare version (`0.1.0`, no `v`). Before tagging, set the version in
  `Cargo.toml` (and `Cargo.lock`), move `[Unreleased]` under `## [<version>] - <date>`, and update
  the compare links at the end. The release workflow drafts the GitHub release from that section
  and fails without it.

## Documentation

- Keep the README short: what it is, how to install and add it, the flags and the tools, and links.
- Details a user must know (behavior, security, limits, harness setup) go in `docs/`, as short
  bullets rather than paragraphs.

## Prose style

- American spelling everywhere.
- No em dashes. Prefer a colon, a comma or parentheses.

---

# Rust practice

## Safety

- Avoid panicking calls (`unwrap()`, `expect()`, unchecked indexing). Propagate with `?`. The lints
  are `warn` in `Cargo.toml` and relaxed under `cfg(test)`, where panicking on failure is the point.
- Never discard errors with `let _ =` outside tests. Propagate, log the decision to ignore, or
  handle with `match` / `if let Err(..)`.

## Layout and style

- No `mod.rs`. Use `src/some_module.rs`; a module's tests may live in `src/some_module/tests.rs`.
- Module imports form a graph with no cycles: `server` uses everything; `connection` uses `client`,
  `host_key`, `shell`, `forward`, `sftp` and `paths`; `exec`, `shell`, `forward` and `sftp` use
  `client`; `client` uses `host_key`; any module may use `paths`, which uses only `output`, and
  `output`, which uses no other module. Helpers several modules share (locking, random hex, signal
  names) live in `output`.
- Never hand-wrap comments. One line per paragraph; `cargo +nightly fmt` wraps them.
- `pub(crate)` for anything another module reads, never bare `pub` in this binary crate.
- Every `pub(crate)` item has a `///` comment, except a tool's argument struct (its field comments
  are the schema).
- Test names read as sentences, never a `test_` prefix.
- Time is a `Duration` constant; sizes are `_BYTES`.

## Build gate

Run after editing: `cargo +nightly fmt` and `cargo sort -w`. CI denies warnings and runs:

```
cargo +nightly fmt --check
cargo sort -w --check
cargo clippy --locked --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --document-private-items
cargo test --locked
cargo check --locked --all-targets   # on the MSRV in Cargo.toml's rust-version
```

After `fmt`, `awk 'length>100 && /^[[:space:]]*\/\//'` the changed files: `fmt --check` does not
enforce `comment_width`, so reword what it prints.

---

# ssh-mcp

## Standing design rules

These are the owner's decisions. Do not re-raise them without new facts.

- **Standalone.** Nothing from the host's `~/.ssh` (config, keys, agent, known_hosts) is used unless
  the agent names a file in a tool argument.
- **No configuration file and no stored state.** Settings are tool arguments with built-in defaults
  and the four command-line flags. The only state is what is open, in memory.
- **No local writes except `download`,** which writes only under the `local_path` it is given.
  `--disable-sftp` removes it with the other SFTP tools. Any new local write is a design change.
- **Credentials are tool arguments.** A password or private key passed in a call is valid; it must
  never appear in a result, an error message or a log line. A key file that is not a key is refused
  without quoting its contents.
- **Host keys are checked or explicitly accepted.** `connect` refuses unless a fingerprint or a
  known_hosts file checks the key or `accept_new_host_key` accepts it; a known host with a different
  key is always refused, and so is a host only an `@cert-authority` line covers. Every connect and
  every host key refusal shows the presented key.
- **A connection is reached only through its token.** No tool lists connections, and the refusal
  for an unknown token reads the same whatever the reason.
- **Port forwarding is off by default,** each kind behind its own flag. Local listeners bind
  127.0.0.1 only.
- **Harness-neutral.** Nothing may depend on one MCP client; meka is one user among several.

## Tool text

A model reads every tool description and argument comment on every turn. State facts: what it does,
its default, what it cannot do. A refusal carries its own remedy, so descriptions do not list
refusals. Tool names have no `ssh_` prefix because harnesses namespace them.

## Read-only hints

`readOnlyHint` is true for tools that only look (`connection_status`, `shell_read`, `read_file`) and
for the closers (`disconnect`, `shell_close`, `forward_close`), which end only what this server
opened. Everything that changes the remote host or touches local files says so, and so does
`connect`, which reads key and known_hosts files anywhere on this machine and reaches any host.
Keep the hints honest: harnesses grant permissions from them.

## Cancellation

A client may cancel any call (meka does at its tool timeout, 10 minutes by default), and MCP then
drops the result unread. A canceled call must therefore change nothing the agent has not seen: shell
tools return without consuming output or outcomes and without interrupting the command. `exec` is
the exception, and stops its command, since nothing could read its output later. Every wait on the
server (channel opens and requests, writes, signals, closes, SFTP requests) has a timeout or watches
the call's cancellation: russh queues every send behind the connection's outgoing data, so one
stalled connection would otherwise hold a call forever. `client::bounded` and
`client::best_effort` wrap the sends. The file tools call `sftp::stop_if_canceled` before every
change they make, so a canceled transfer or write stops at the next file, folder or rename, and the
forward tools check before they keep a forward open.

## Tests

`src/testing.rs` holds the fixtures: an in-process russh server with scripted commands, real
terminals for shells (Unix, with an empty home and no history file), forwarding, and configurable
logins; and a real OpenSSH `sshd` for this user where one is installed, used for SFTP and exec. A
test that needs `sshd` skips when it cannot run, unless `SSH_MCP_REQUIRE_SSHD` is set, as CI sets it
on Linux; then it fails. End-to-end tests in `src/server/tests.rs` call
the tools through an MCP client. Shell tests run against the in-process server because unprivileged
`sshd` cannot allocate a terminal inside some sandboxes.
