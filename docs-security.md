# Security Notes

- Bind Motehold to a private interface, not `0.0.0.0`.
- Keep `.env`, local TOML, databases, uploads, and logs out of Git.
- Use a password hash in configuration, not a plaintext password.
- Configure a stable `MOTEHOLD_COOKIE_SECRET` of at least 32 decoded bytes for
  authenticated deployments and share it across instances. Missing or invalid
  values create an ephemeral key that invalidates sessions and OIDC flows on
  restart and is unsuitable for multi-instance operation.
- Managed OIDC is alpha. Keep the local password as break-glass access, use
  HTTPS outside loopback, and do not treat this pilot as enterprise-ready.
- OIDC state is one-time, browser-bound, and short lived. App session tokens
  are opaque and only their HMAC-SHA256 digests are stored in SQLite.
- OIDC discovery refuses redirects and rejects non-HTTPS endpoints except for
  explicit loopback HTTP dogfood URLs. Token client authentication is selected
  from provider metadata and limited to `client_secret_post` or
  `client_secret_basic`.
- Dogfood-alpha dependency risk: `openidconnect` currently brings in
  `rsa 0.9.10`, which `cargo audit` flags as RUSTSEC-2023-0071 with no fixed
  release. This relying-party app holds no RSA private key, and the LinuxMice
  identity pilot uses Ed25519, so the vulnerable private-key operation is not
  expected on this path. The unresolved audit remains a production-readiness
  blocker and must be reassessed before wider deployment.
- Uploaded images are stored in the SQLite database; keep the database private.
- Run `cargo run -- audit-public` before publishing. It checks tracked files
  for ignored private paths, common secret markers, Tailscale-style private
  IPs, private key material, and optional local denylist terms.
- Install local Git hooks with `cargo run -- audit-public --install-hook`.

Host-specific denylist terms can be stored in ignored files:

```text
docs/private/audit-denylist.txt
.motehold/audit-denylist.txt
```
