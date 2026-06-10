#!/usr/bin/env python3
import json
import os
import re
import shlex
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = Path(os.environ.get("LOG_DIR", "/tmp/frer-ebpf-xdp"))
HOST = os.environ.get("FRER_DASHBOARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("FRER_DASHBOARD_PORT", "8080"))
VID = os.environ.get("VID", "100")

ACTION_LOG = []
ACTION_LOCK = threading.Lock()
RUNNING_ACTIONS = {}
RUNNING_LOCK = threading.Lock()

STATS_RE = re.compile(
    r"rx=(?P<rx>\d+)\s+replicated=(?P<replicated>\d+)\s+passed=(?P<passed>\d+)\s+"
    r"duplicates=(?P<duplicates>\d+)\s+malformed=(?P<malformed>\d+)\s+no_config=(?P<no_config>\d+)"
)


def append_action(line):
    stamp = time.strftime("%H:%M:%S")
    with ACTION_LOCK:
        ACTION_LOG.append(f"[{stamp}] {line.rstrip()}")
        del ACTION_LOG[:-250]


def run_command(action, cmd, timeout=None):
    with RUNNING_LOCK:
        if RUNNING_ACTIONS.get(action):
            append_action(f"{action} is already running")
            return
        RUNNING_ACTIONS[action] = True

    try:
        append_action(f"$ {shlex.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        try:
            for line in proc.stdout or []:
                append_action(line)
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGTERM)
            code = proc.wait()
            append_action(f"command timed out after {timeout}s")

        append_action(f"{action} finished with exit code {code}")
    except FileNotFoundError as exc:
        append_action(f"missing command: {exc}")
    except Exception as exc:
        append_action(f"{action} failed: {exc}")
    finally:
        with RUNNING_LOCK:
            RUNNING_ACTIONS.pop(action, None)


def start_action(action, cmd, timeout=None):
    thread = threading.Thread(target=run_command, args=(action, cmd, timeout), daemon=True)
    thread.start()


def read_tail(path, lines=80):
    try:
        text = path.read_text(errors="replace").splitlines()
    except FileNotFoundError:
        return []
    return text[-lines:]


def command_output(cmd):
    try:
        out = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2,
        )
        return out.returncode, out.stdout.strip(), out.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def link_state(name):
    code, out, _ = command_output(["ip", "-br", "link", "show", name])
    if code != 0 or not out:
        return {"name": name, "exists": False, "state": "missing", "raw": ""}
    parts = out.split()
    state = parts[1] if len(parts) > 1 else "unknown"
    return {"name": name, "exists": True, "state": state, "raw": out}


def namespace_exists(name):
    code, out, _ = command_output(["ip", "netns", "list"])
    return code == 0 and any(line.split()[0] == name for line in out.splitlines() if line.strip())


def pid_status():
    pids_path = LOG_DIR / "pids"
    pids = []
    for line in read_tail(pids_path, 20):
        line = line.strip()
        if not line.isdigit():
            continue
        alive = Path(f"/proc/{line}").exists()
        pids.append({"pid": int(line), "alive": alive})
    return pids


def parse_log_stats(lines):
    latest = None
    for line in lines:
        match = STATS_RE.search(line)
        if match:
            latest = {key: int(value) for key, value in match.groupdict().items()}
    return latest


def collect_logs():
    names = ["fwd-replicate", "fwd-eliminate", "rev-replicate", "rev-eliminate"]
    logs = {}
    for name in names:
        lines = read_tail(LOG_DIR / f"{name}.log", 80)
        logs[name] = {"lines": lines, "stats": parse_log_stats(lines)}
    return logs


def collect_status():
    build_ok = (ROOT / "build/frerctl").exists() and (ROOT / "build/frer_kern.o").exists()
    links = [link_state(name) for name in ["pc1-a", "pc2-b", "ab0", "ab1", "ba0", "ba1"]]
    pids = pid_status()
    logs = collect_logs()
    with ACTION_LOCK:
        action_log = list(ACTION_LOG)
    with RUNNING_LOCK:
        running = sorted(RUNNING_ACTIONS.keys())
    return {
        "root": str(ROOT),
        "isRoot": os.geteuid() == 0,
        "vid": VID,
        "buildOk": build_ok,
        "namespaces": {"pc1": namespace_exists("pc1"), "pc2": namespace_exists("pc2")},
        "links": links,
        "frerRunning": any(item["alive"] for item in pids),
        "pids": pids,
        "logs": logs,
        "actionLog": action_log,
        "runningActions": running,
    }


def action_command(action):
    commands = {
        "build": (["make"], 60),
        "setup": (["./scripts/setup-veth-demo.sh"], 30),
        "start_frer": (["./scripts/run-veth-frer.sh"], 20),
        "ping": (["ping", "-I", f"pc1-a.{VID}", "-c", "5", "10.0.0.2"], 15),
        "fail_ab0": (["ip", "link", "set", "ab0", "down"], 10),
        "recover_ab0": (["ip", "link", "set", "ab0", "up"], 10),
        "fail_both": (["sh", "-c", "ip link set ab0 down && ip link set ab1 down"], 10),
        "recover_both": (["sh", "-c", "ip link set ab0 up && ip link set ab1 up"], 10),
        "cleanup": (["./scripts/cleanup-veth-demo.sh"], 30),
    }
    return commands.get(action)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            self.send_json(collect_status())
            return

        if parsed.path in ("/", "/index.html"):
            self.send_file(ROOT / "dashboard" / "index.html", "text/html; charset=utf-8")
            return
        if parsed.path == "/styles.css":
            self.send_file(ROOT / "dashboard" / "styles.css", "text/css; charset=utf-8")
            return
        if parsed.path == "/app.js":
            self.send_file(ROOT / "dashboard" / "app.js", "application/javascript; charset=utf-8")
            return
        self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/action":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "invalid json")
            return
        action = payload.get("action")
        item = action_command(action)
        if not item:
            self.send_error(400, "unknown action")
            return
        cmd, timeout = item
        if action != "build" and os.geteuid() != 0:
            append_action("privileged demo actions need root. Start with: sudo make dashboard")
            self.send_json({"ok": False, "error": "Start dashboard with sudo for network/XDP actions."}, status=403)
            return
        start_action(action, cmd, timeout)
        self.send_json({"ok": True, "action": action})

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path, content_type):
        try:
            body = path.read_bytes()
        except FileNotFoundError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def main():
    append_action(f"Dashboard ready at http://{HOST}:{PORT}")
    append_action(f"Project root: {ROOT}")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"FRER dashboard: http://{HOST}:{PORT}")
    print("Use sudo make dashboard on Linux for setup, XDP attach, path failure, and cleanup actions.")
    server.serve_forever()


if __name__ == "__main__":
    main()
