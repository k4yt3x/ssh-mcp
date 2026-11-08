# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/2.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-08

### Changed

- Managed shells save no history and skip prompt and command hooks, such as atuin's.
- Merging a folder with `overwrite` keeps the permissions of folders that already exist.
- `allow_legacy_algorithms` also lets RSA keys log in to servers that only take SHA-1.

### Fixed

- Commands containing `!` work in managed bash and zsh shells.
- Managed mode works on servers that make `HISTFILE` read-only.
- RSA certificate logins work against OpenSSH 8.8 and later.
- `upload` and `write_file` refuse pipes and devices instead of hanging.
- Edits sent together on one connection no longer overwrite each other.
- A canceled transfer, file edit or forward makes no further changes.
- A server without SFTP is reported at once instead of after two minutes.
- `exec` keeps output that arrives after the exit status and no longer misreports timeouts.
- Errors for missing folders, CRLF files, encrypted keys and SFTP failures say how to fix them.

### Security

- A host key no longer passes as new when known_hosts has tab-separated or unreadable lines.
- A private key passed by mistake as `private_key_file` is no longer quoted back in errors.

## [0.1.0] - 2026-11-08

### Added

- An MCP server over stdio for SSH; each connection is reached only through its token.
- Login by private key (text or file, optionally encrypted), OpenSSH certificate, or password.
- Host key checks by fingerprint or known_hosts file, and `accept_new_host_key` for unknown hosts.
- Jump hosts through `via`, and `allow_legacy_algorithms` for old servers.
- `exec` for one-off commands with separate stdout and stderr, stdin, and a timeout.
- Persistent shells that report exit codes, keep long commands running and render full screens.
- A shell call the client cancels interrupts nothing; its output and outcome wait for `shell_read`.
- SFTP tools to read, write, edit, upload and download files; `--disable-sftp` removes them.
- Local, remote and dynamic (SOCKS5) port forwarding, each enabled by its own flag.

[Unreleased]: https://github.com/k4yt3x/ssh-mcp/compare/0.1.1...HEAD
[0.1.1]: https://github.com/k4yt3x/ssh-mcp/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/k4yt3x/ssh-mcp/releases/tag/0.1.0
