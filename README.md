# ssh-mcp

An [MCP](https://modelcontextprotocol.io) server that gives an AI agent SSH: persistent
connections, commands, interactive shells, SFTP file transfer and port forwarding. It speaks MCP
over stdio, so any MCP client can run it.

It is standalone: nothing from `~/.ssh` is used, there is no config file, and nothing is stored.
The agent passes the key or password, and a host key check, when it connects.

## Install

Download a build for Linux, macOS or Windows from
[Releases](https://github.com/k4yt3x/ssh-mcp/releases), or build it with Rust 1.89 or newer:

```console
$ cargo install --locked --git https://github.com/k4yt3x/ssh-mcp
```

## Use

```console
$ meka mcp add ssh ssh-mcp
$ claude mcp add ssh -- ssh-mcp
```

| Flag | Effect |
|---|---|
| `--disable-sftp` | Removes the file tools. |
| `--enable-local-forwarding` | Adds `forward_local` (like `ssh -L`). |
| `--enable-remote-forwarding` | Adds `forward_remote` (like `ssh -R`). |
| `--enable-dynamic-forwarding` | Adds `forward_dynamic` (like `ssh -D`). |

Logs go to stderr; set `RUST_LOG=debug` for more.

## Tools

| Tool | What it does |
|---|---|
| `connect`, `connection_status`, `disconnect` | Open, inspect and close connections. |
| `exec` | Run one command; separate stdout and stderr, exact exit code. |
| `shell_open`, `shell_run`, `shell_send`, `shell_read`, `shell_close` | Persistent shells. |
| `read_file`, `write_file`, `edit_file` | Remote text files. |
| `upload`, `download` | Copy files and folders. |
| `forward_local`, `forward_remote`, `forward_dynamic`, `forward_close` | Port forwarding. |

## Docs

- [Tools](docs/tools.md): connecting, shells, files and limits.
- [Security](docs/security.md): host keys, tokens and what it touches on this machine.
- [meka](docs/meka.md): permissions for read-only sessions, timeouts and logs.

## License

MIT
