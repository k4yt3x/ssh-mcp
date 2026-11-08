# Using ssh-mcp with meka

```console
$ meka mcp add ssh ssh-mcp
```

meka's options go before `ssh-mcp`; anything after it is passed to ssh-mcp, such as
`--enable-local-forwarding`.

## Permissions

meka runs tools marked read-only at `read` and the rest at `unrestricted`. The read-only tools are
`connection_status`, `shell_read`, `read_file` and the closers `disconnect`, `shell_close` and
`forward_close`, so a `read` session holding a token can close that connection's shells.

To use the server from a read-only session, run it at `read` and keep the tools that touch local
files at `unrestricted`:

```console
$ meka mcp add ssh --permission read --tool-permission upload=unrestricted --tool-permission download=unrestricted ssh-mcp
```

Or in `config.toml`:

```toml
[[mcp.servers]]
name = "ssh"
transport = "stdio"
command = "ssh-mcp"
permission = "read"

[mcp.servers.tool_permissions]
upload = "unrestricted"
download = "unrestricted"
```

- This also runs `connect` at `read`, and `connect` can read key files anywhere and reach any host.
  Add `connect = "unrestricted"` to require approval for it.
- With forwarding enabled, add the `forward_` tools too: meka's `network` setting does not cover
  MCP servers.
- `workspace` would not confine where `download` writes.

## Timeouts and logs

- meka cancels an MCP call after 10 minutes; `MEKA_MCP_TOOL_TIMEOUT` (such as `30m`) changes that.
  A canceled shell call interrupts nothing, a canceled `exec` stops its command, and a canceled
  file tool stops before its next change.
- meka starts servers with a minimal environment. To debug, set `env = { RUST_LOG = "debug" }` in
  the server's entry.
