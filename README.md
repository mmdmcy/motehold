# Motehold

Motehold is a tiny private channel-based note board for a trusted local network. It serves one HTML page, a small JSON API, server-sent events for live updates, and a SQLite database for stored messages.

It is designed for personal use on a private LAN, VPN, or tailnet. It does not include authentication, so do not expose it directly to the public internet.

## Features

- Single-file Python server with no package dependencies.
- SQLite message storage.
- Create and delete channels.
- Store messages inside specific channels.
- Attach PNG, JPEG, GIF, or WebP images up to 5 MB.
- Collapsible channel sidebar.
- Live updates with server-sent events.
- Copy and delete actions for each note.
- Confirm dialog before deleting messages or channels.
- Gray dark theme for phone readability.

## Run

```sh
cp .env.example .env
python3 server.py
```

By default, Motehold binds to your Tailscale IPv4 address if the `tailscale` CLI is available. If no Tailscale address is found, it falls back to `127.0.0.1`.

Open the printed URL from another device on the same trusted network.

## Configuration

Local configuration lives in `.env`, which is intentionally ignored by Git.

```sh
MOTEHOLD_HOST=127.0.0.1
MOTEHOLD_PORT=8787
MOTEHOLD_DB=.local/messages.db
MOTEHOLD_LOG_REQUESTS=0
```

You can also pass the same settings as command-line flags:

```sh
python3 server.py --host 127.0.0.1 --port 8787 --db .local/messages.db
```

Use a private interface or VPN address for trusted-network access. Binding to `0.0.0.0` exposes the app on every network interface.

## Public Release Notes

The repository ignores local runtime state, including `.env`, `.local/`, SQLite databases, logs, PID files, and Python bytecode caches. Do not commit your personal database or logs.
