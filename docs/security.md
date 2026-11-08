# Security

## Host keys

`connect` refuses a host whose key is neither checked nor explicitly accepted:

- `host_key_fingerprint`: one or more `SHA256:` fingerprints or public key lines.
- `known_hosts_file`: read, never written. Hashed names, `[host]:port`, wildcards, negation and
  `@revoked` work. A host covered by `@cert-authority` is refused, since host certificates are not
  checked.
- `accept_new_host_key`: accepts a host that cannot be checked. A host the file lists with a
  different key is still refused.

Every connect and every host key refusal shows the key, with a known_hosts line to record.

## Tokens

A connection is reachable only by the token `connect` returns, and no tool lists connections. Two
agents cannot use each other's connections unless one hands its token over. A lost token cannot be
recovered; its connection closes when idle.

## This machine

- Reads only files named in arguments: keys, certificates, known_hosts files and `upload` sources.
- Writes only where `download` is told to. A download refuses names that would leave the
  destination, and drops setuid, setgid and sticky bits.
- Never reads `~/.ssh` or uses an SSH agent.
- Forwarding listeners bind 127.0.0.1, but any local program can use them while they are open.

## Credentials

Passwords and keys never appear in results, errors or logs. They are tool arguments, though, so the
client's conversation log holds them.
