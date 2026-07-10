#!/usr/bin/env python3
import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote


BASE_DIR = Path(__file__).resolve().parent
ALLOWED_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "TXT", "SRV", "CAA"}
NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.:\-]+$")


def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_name(value, field):
    if not isinstance(value, str):
        raise ValueError(f"{field} is required")
    value = value.strip()
    if not value:
        raise ValueError(f"{field} is required")
    if len(value) > 253:
        raise ValueError(f"{field} is too long")
    if not NAME_PATTERN.match(value):
        raise ValueError(f"{field} contains invalid characters")
    return value


def build_dig_command(payload):
    server = validate_name(payload.get("server", ""), "Relay server")
    domain = validate_name(payload.get("domain", ""), "Domain")

    try:
        port = int(payload.get("port", 1053))
    except (TypeError, ValueError):
        raise ValueError("Port must be a number")
    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535")

    qtype = str(payload.get("type", "A")).upper().strip()
    if qtype not in ALLOWED_TYPES:
        raise ValueError("Unsupported record type")

    cmd = ["dig", f"@{server}", "-p", str(port)]
    if qtype == "PTR" and is_ip_address(domain):
        cmd.extend(["-x", domain])
    else:
        cmd.extend([domain, qtype])
    cmd.extend(["+time=5", "+tries=1"])
    return cmd


def parse_answer_records(stdout):
    records = []
    in_answer_section = False

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if line == ";; ANSWER SECTION:":
            in_answer_section = True
            continue
        if in_answer_section and (not line or line.startswith(";;")):
            break
        if not in_answer_section or line.startswith(";"):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        name, ttl, dns_class, record_type = parts[:4]
        value = " ".join(parts[4:])
        record = {
            "name": name,
            "ttl": ttl,
            "class": dns_class,
            "type": record_type,
            "value": value,
            "address": value if record_type in {"A", "AAAA"} else "",
        }
        records.append(record)

    return records


class ClientHandler(SimpleHTTPRequestHandler):
    server_version = "DNSRelayClient/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def do_GET(self):
        path = unquote(self.path.split("?", 1)[0])
        if path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        if self.path != "/api/query":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length).decode("utf-8")
            payload = json.loads(raw_body or "{}")
            response = self.run_query(payload)
            self.send_json(HTTPStatus.OK, response)
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
        except json.JSONDecodeError:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid JSON"})

    def run_query(self, payload):
        if shutil.which("dig") is None:
            raise ValueError("dig command not found. Install dnsutils first.")

        cmd = build_dig_command(payload)
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=8,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "command": " ".join(cmd),
                "duration_ms": 8000,
                "stdout": "",
                "stderr": "dig timed out after 8 seconds",
                "returncode": 124,
                "answers": [],
            }

        duration_ms = int((time.perf_counter() - started) * 1000)
        return {
            "ok": completed.returncode == 0,
            "command": " ".join(cmd),
            "duration_ms": duration_ms,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "returncode": completed.returncode,
            "answers": parse_answer_records(completed.stdout),
        }

    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="DNS Relay client query frontend")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), ClientHandler)
    print(f"DNS Relay Client: http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
