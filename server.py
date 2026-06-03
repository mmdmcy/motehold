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
from urllib.parse import urlparse


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
MAX_BODY_BYTES = 256 * 1024
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


class MessageStore:
    def __init__(self, db_path: Path) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    body TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    def list_messages(self, limit: int = 200) -> list[dict[str, object]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, body, created_at
                FROM messages
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def create_message(self, body: str) -> dict[str, object]:
        created_at = (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO messages (body, created_at) VALUES (?, ?)",
                (body, created_at),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT id, body, created_at FROM messages WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
        return dict(row)

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
            path = urlparse(self.path).path
            if path == "/":
                self._serve_file(APP_DIR / "index.html", cache=False)
            elif path == "/api/messages":
                self._send_json({"messages": store.list_messages()}, cache=False)
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
            path = urlparse(self.path).path
            if path == "/":
                self._serve_file(APP_DIR / "index.html", cache=False, head_only=True)
            elif path == "/api/messages":
                self._send_json({"messages": store.list_messages()}, cache=False, head_only=True)
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

            message = store.create_message(body)
            events.publish({"type": "created", "message": message})
            self._send_json({"message": message}, status=201, cache=False)

        def do_DELETE(self) -> None:
            path = urlparse(self.path).path
            prefix = "/api/messages/"
            if not path.startswith(prefix):
                self._send_json({"error": "not_found"}, status=404, cache=False)
                return

            raw_id = path[len(prefix) :]
            if not raw_id.isdigit():
                self._send_json({"error": "invalid_message_id"}, status=400, cache=False)
                return

            message_id = int(raw_id)
            deleted = store.delete_message(message_id)
            if not deleted:
                self._send_json({"error": "not_found"}, status=404, cache=False)
                return

            events.publish({"type": "deleted", "id": message_id})
            self._send_json({"ok": True}, cache=False)

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
