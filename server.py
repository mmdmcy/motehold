#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import queue
import sqlite3
import subprocess
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
MAX_BODY_BYTES = 256 * 1024
MAX_CHANNEL_NAME_CHARS = 40
DEFAULT_CHANNEL_NAME = "general"
CSP = (
    "default-src 'self'; "
    "connect-src 'self'; "
    "img-src 'self' data:; "
    "script-src 'self'; "
    "style-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'"
)


def load_env_file(path: Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeError(f"Could not read env file: {path}") from exc

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]
        os.environ.setdefault(key, value)


def env_file_path() -> Path:
    configured = os.environ.get("MOTEHOLD_ENV_FILE")
    if not configured:
        return APP_DIR / ".env"

    path = Path(configured).expanduser()
    if not path.is_absolute():
        path = APP_DIR / path
    return path


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(APP_DIR))
    except ValueError:
        return str(path)


def resolve_app_path(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = APP_DIR / path
    return path.resolve()


def utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def normalize_channel_name(value: str) -> str:
    return " ".join(value.strip().split())


class MessageStore:
    def __init__(self, db_path: Path) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._migrate()

    def _migrate(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS channels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    created_at TEXT NOT NULL
                )
                """
            )
            default_channel_id = self._ensure_default_channel_locked()
            message_columns = {
                row["name"]
                for row in self._conn.execute("PRAGMA table_info(messages)").fetchall()
            }

            if not message_columns:
                self._conn.execute(
                    """
                    CREATE TABLE messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        channel_id INTEGER NOT NULL,
                        body TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
                    )
                    """
                )
            elif "channel_id" not in message_columns:
                self._conn.execute("ALTER TABLE messages ADD COLUMN channel_id INTEGER")
                self._conn.execute(
                    "UPDATE messages SET channel_id = ? WHERE channel_id IS NULL",
                    (default_channel_id,),
                )

            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_channel_id ON messages(channel_id)"
            )

    def _ensure_default_channel_locked(self) -> int:
        row = self._conn.execute(
            "SELECT id FROM channels WHERE name = ?",
            (DEFAULT_CHANNEL_NAME,),
        ).fetchone()
        if row:
            return int(row["id"])

        cursor = self._conn.execute(
            "INSERT INTO channels (name, created_at) VALUES (?, ?)",
            (DEFAULT_CHANNEL_NAME, utc_timestamp()),
        )
        return int(cursor.lastrowid)

    def _channel_exists_locked(self, channel_id: int) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM channels WHERE id = ?",
            (channel_id,),
        ).fetchone()
        return row is not None

    def default_channel_id(self) -> int:
        with self._lock:
            return self._ensure_default_channel_locked()

    def list_channels(self) -> list[dict[str, object]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    c.id,
                    c.name,
                    c.created_at,
                    COUNT(m.id) AS message_count
                FROM channels c
                LEFT JOIN messages m ON m.channel_id = c.id
                GROUP BY c.id
                ORDER BY c.id ASC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def create_channel(self, name: str) -> tuple[dict[str, object] | None, str | None]:
        normalized = normalize_channel_name(name)
        if not normalized:
            return None, "empty_channel_name"
        if len(normalized) > MAX_CHANNEL_NAME_CHARS:
            return None, "channel_name_too_long"

        with self._lock:
            try:
                cursor = self._conn.execute(
                    "INSERT INTO channels (name, created_at) VALUES (?, ?)",
                    (normalized, utc_timestamp()),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                return None, "channel_exists"

            row = self._conn.execute(
                """
                SELECT
                    c.id,
                    c.name,
                    c.created_at,
                    COUNT(m.id) AS message_count
                FROM channels c
                LEFT JOIN messages m ON m.channel_id = c.id
                WHERE c.id = ?
                GROUP BY c.id
                """,
                (cursor.lastrowid,),
            ).fetchone()
        return dict(row), None

    def delete_channel(self, channel_id: int) -> str | None:
        with self._lock:
            if not self._channel_exists_locked(channel_id):
                return "not_found"

            channel_count = self._conn.execute(
                "SELECT COUNT(*) AS count FROM channels",
            ).fetchone()["count"]
            if int(channel_count) <= 1:
                return "last_channel"

            with self._conn:
                self._conn.execute(
                    "DELETE FROM messages WHERE channel_id = ?",
                    (channel_id,),
                )
                self._conn.execute(
                    "DELETE FROM channels WHERE id = ?",
                    (channel_id,),
                )
        return None

    def list_messages(
        self,
        channel_id: int,
        limit: int = 200,
    ) -> tuple[list[dict[str, object]] | None, str | None]:
        with self._lock:
            if not self._channel_exists_locked(channel_id):
                return None, "channel_not_found"

            rows = self._conn.execute(
                """
                SELECT id, channel_id, body, created_at
                FROM messages
                WHERE channel_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (channel_id, limit),
            ).fetchall()
        return [dict(row) for row in rows], None

    def create_message(
        self,
        body: str,
        channel_id: int,
    ) -> tuple[dict[str, object] | None, str | None]:
        with self._lock:
            if not self._channel_exists_locked(channel_id):
                return None, "channel_not_found"

            cursor = self._conn.execute(
                """
                INSERT INTO messages (channel_id, body, created_at)
                VALUES (?, ?, ?)
                """,
                (channel_id, body, utc_timestamp()),
            )
            self._conn.commit()
            row = self._conn.execute(
                """
                SELECT id, channel_id, body, created_at
                FROM messages
                WHERE id = ?
                """,
                (cursor.lastrowid,),
            ).fetchone()
        return dict(row), None

    def delete_message(self, message_id: int) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM messages WHERE id = ?",
                (message_id,),
            )
            self._conn.commit()
        return cursor.rowcount > 0


class EventHub:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: set[queue.Queue[str]] = set()

    def subscribe(self) -> queue.Queue[str]:
        client: queue.Queue[str] = queue.Queue(maxsize=20)
        with self._lock:
            self._clients.add(client)
        return client

    def unsubscribe(self, client: queue.Queue[str]) -> None:
        with self._lock:
            self._clients.discard(client)

    def publish(self, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, separators=(",", ":"))
        with self._lock:
            clients = list(self._clients)
        stale: list[queue.Queue[str]] = []
        for client in clients:
            try:
                client.put_nowait(encoded)
            except queue.Full:
                stale.append(client)
        if stale:
            with self._lock:
                for client in stale:
                    self._clients.discard(client)


def make_handler(store: MessageStore, events: EventHub, log_requests: bool):
    class Handler(BaseHTTPRequestHandler):
        def end_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", CSP)
            super().end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            if not log_requests:
                return
            print(f"{self.address_string()} - {fmt % args}")

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/":
                self._serve_file(APP_DIR / "index.html", cache=False)
            elif path == "/api/channels":
                self._send_json({"channels": store.list_channels()}, cache=False)
            elif path == "/api/messages":
                self._send_messages(parsed.query)
            elif path == "/events":
                self._serve_events()
            elif path == "/health":
                self._send_json({"ok": True}, cache=False)
            elif path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
            elif path.startswith("/static/"):
                self._serve_static(path)
            else:
                self._send_json({"error": "not_found"}, status=404, cache=False)

        def do_HEAD(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/":
                self._serve_file(APP_DIR / "index.html", cache=False, head_only=True)
            elif path == "/api/channels":
                self._send_json({"channels": store.list_channels()}, cache=False, head_only=True)
            elif path == "/api/messages":
                self._send_messages(parsed.query, head_only=True)
            elif path == "/health":
                self._send_json({"ok": True}, cache=False, head_only=True)
            elif path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
            elif path.startswith("/static/"):
                self._serve_static(path, head_only=True)
            else:
                self._send_json({"error": "not_found"}, status=404, cache=False, head_only=True)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path == "/api/channels":
                data = self._read_json()
                if data is None:
                    return

                name = data.get("name")
                if not isinstance(name, str):
                    self._send_json({"error": "name_must_be_text"}, status=400, cache=False)
                    return

                channel, error = store.create_channel(name)
                if error:
                    status = 409 if error == "channel_exists" else 422
                    self._send_json({"error": error}, status=status, cache=False)
                    return

                events.publish({"type": "channel_created", "channel": channel})
                self._send_json({"channel": channel}, status=201, cache=False)
                return

            if path != "/api/messages":
                self._send_json({"error": "not_found"}, status=404, cache=False)
                return

            data = self._read_json()
            if data is None:
                return

            body = data.get("body")
            if not isinstance(body, str):
                self._send_json({"error": "body_must_be_text"}, status=400, cache=False)
                return
            if not body.strip():
                self._send_json({"error": "empty_message"}, status=422, cache=False)
                return

            channel_id = self._channel_id_from_payload(data)
            if channel_id is None:
                return

            message, error = store.create_message(body, channel_id)
            if error:
                self._send_json({"error": error}, status=404, cache=False)
                return

            events.publish(
                {
                    "type": "message_created",
                    "channel_id": channel_id,
                    "message": message,
                }
            )
            self._send_json({"message": message}, status=201, cache=False)

        def do_DELETE(self) -> None:
            path = urlparse(self.path).path
            channel_prefix = "/api/channels/"
            if path.startswith(channel_prefix):
                channel_id = self._resource_id(path, channel_prefix, "invalid_channel_id")
                if channel_id is None:
                    return

                error = store.delete_channel(channel_id)
                if error == "not_found":
                    self._send_json({"error": "not_found"}, status=404, cache=False)
                    return
                if error == "last_channel":
                    self._send_json({"error": "cannot_delete_last_channel"}, status=409, cache=False)
                    return

                events.publish({"type": "channel_deleted", "id": channel_id})
                self._send_json({"ok": True}, cache=False)
                return

            message_prefix = "/api/messages/"
            if not path.startswith(message_prefix):
                self._send_json({"error": "not_found"}, status=404, cache=False)
                return

            message_id = self._resource_id(path, message_prefix, "invalid_message_id")
            if message_id is None:
                return

            deleted = store.delete_message(message_id)
            if not deleted:
                self._send_json({"error": "not_found"}, status=404, cache=False)
                return

            events.publish({"type": "message_deleted", "id": message_id})
            self._send_json({"ok": True}, cache=False)

        def _send_messages(self, query: str, head_only: bool = False) -> None:
            channel_id = self._channel_id_from_query(query)
            if channel_id is None:
                return

            messages, error = store.list_messages(channel_id)
            if error:
                self._send_json({"error": error}, status=404, cache=False, head_only=head_only)
                return

            self._send_json({"messages": messages}, cache=False, head_only=head_only)

        def _channel_id_from_query(self, query: str) -> int | None:
            params = parse_qs(query)
            raw_values = params.get("channel_id", [])
            if not raw_values or raw_values[0] == "":
                return store.default_channel_id()
            return self._positive_int(raw_values[0], "invalid_channel_id")

        def _channel_id_from_payload(self, payload: dict[str, object]) -> int | None:
            raw_id = payload.get("channel_id")
            if raw_id is None or raw_id == "":
                return store.default_channel_id()
            return self._positive_int(raw_id, "invalid_channel_id")

        def _resource_id(self, path: str, prefix: str, error: str) -> int | None:
            raw_id = path[len(prefix) :]
            return self._positive_int(raw_id, error)

        def _positive_int(self, value: object, error: str) -> int | None:
            if isinstance(value, bool):
                self._send_json({"error": error}, status=400, cache=False)
                return None

            try:
                parsed = int(value)
            except (TypeError, ValueError):
                self._send_json({"error": error}, status=400, cache=False)
                return None

            if parsed < 1:
                self._send_json({"error": error}, status=400, cache=False)
                return None
            return parsed

        def _read_json(self) -> dict[str, object] | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json({"error": "bad_content_length"}, status=400, cache=False)
                return None

            if length > MAX_BODY_BYTES:
                self._send_json({"error": "message_too_large"}, status=413, cache=False)
                return None

            raw = self.rfile.read(length)
            try:
                decoded = json.loads(raw.decode("utf-8") if raw else "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json({"error": "bad_json"}, status=400, cache=False)
                return None

            if not isinstance(decoded, dict):
                self._send_json({"error": "json_object_required"}, status=400, cache=False)
                return None
            return decoded

        def _serve_static(self, request_path: str, head_only: bool = False) -> None:
            relative = request_path.removeprefix("/static/").lstrip("/")
            target = (STATIC_DIR / relative).resolve()
            if not target.is_relative_to(STATIC_DIR) or not target.is_file():
                self._send_json({"error": "not_found"}, status=404, cache=False)
                return
            self._serve_file(target, cache=True, head_only=head_only)

        def _serve_file(self, path: Path, cache: bool, head_only: bool = False) -> None:
            try:
                body = path.read_bytes()
            except OSError:
                self._send_json({"error": "not_found"}, status=404, cache=False)
                return

            content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "max-age=3600" if cache else "no-store")
            self.end_headers()
            if not head_only:
                self.wfile.write(body)

        def _serve_events(self) -> None:
            client = events.subscribe()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            try:
                self.wfile.write(b'data: {"type":"hello"}\n\n')
                self.wfile.flush()
                while True:
                    try:
                        payload = client.get(timeout=20)
                        body = f"data: {payload}\n\n".encode("utf-8")
                    except queue.Empty:
                        body = b": keepalive\n\n"
                    self.wfile.write(body)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass
            finally:
                events.unsubscribe(client)

        def _send_json(
            self,
            payload: dict[str, object],
            status: int = 200,
            cache: bool = False,
            head_only: bool = False,
        ) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "max-age=30" if cache else "no-store")
            self.end_headers()
            if not head_only:
                self.wfile.write(body)

    return Handler


def detect_tailscale_ip() -> str | None:
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None

    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            return line
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tiny network-local notes app.")
    parser.add_argument(
        "--host",
        default=os.environ.get("MOTEHOLD_HOST"),
        help="Host/IP to bind. Defaults to the Tailscale IPv4 address, then 127.0.0.1.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("MOTEHOLD_PORT", "8787")),
        help="Port to listen on. Defaults to 8787.",
    )
    parser.add_argument(
        "--db",
        default=os.environ.get("MOTEHOLD_DB", str(APP_DIR / ".local" / "messages.db")),
        help="SQLite database path. Defaults to ./.local/messages.db.",
    )
    parser.add_argument(
        "--log-requests",
        action="store_true",
        default=env_flag("MOTEHOLD_LOG_REQUESTS"),
        help="Log HTTP request lines. Disabled by default to avoid storing client IPs.",
    )
    return parser.parse_args()


def main() -> None:
    load_env_file(env_file_path())
    args = parse_args()
    host = args.host or detect_tailscale_ip() or "127.0.0.1"
    db_path = resolve_app_path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    store = MessageStore(db_path)
    events = EventHub()
    server = ThreadingHTTPServer(
        (host, args.port),
        make_handler(store, events, log_requests=args.log_requests),
    )

    print(f"Motehold listening on http://{host}:{args.port}/")
    print(f"Database: {display_path(db_path)}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Motehold.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
