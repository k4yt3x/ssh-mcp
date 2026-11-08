# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/2.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/k4yt3x/ssh-mcp/compare/0.1.0...HEAD
[0.1.0]: https://github.com/k4yt3x/ssh-mcp/releases/tag/0.1.0
