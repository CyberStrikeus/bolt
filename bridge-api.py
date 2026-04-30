#!/usr/bin/env python3
"""
HTTP wrapper around ollama-bridge.sh.

Endpoints:
  GET  /health          quick reachability check (ollama + bolt + bridge script)
  POST /scan            run a recon job, return final assistant answer

POST /scan body (JSON):
  {
    # User prompt — provide ONE of:
    "prompt":        "Recon acme.com end-to-end…",   # raw, used verbatim
    # OR auto-build from these fields:
    "target":       "acme.com",                      # required if 'prompt' not set.
                                                     # String form, for tools whose schema takes
                                                     # a single host (nmap, httpx, sslscan, ...).
    "targets":      ["acme.com", "api.acme.com"],    # optional. Array form, for tools that
                                                     # accept a list (mass nuclei, batch httpx).
                                                     # If both 'target' and 'targets' are given,
                                                     # both are surfaced in the prompt — the model
                                                     # picks the right shape per tool.
    "iocs":         ["1.2.3.4", "evil.example.com"], # optional
    "infra":        "AWS account 123456, primary domain acme.com, ASN 12345",
    "instructions": "focus on subdomain takeover risk",

    # Optional overrides for this request only:
    "system_prompt": "You are a CVE triage analyst…",   # full text; overrides agent role
    "model":         "qwen2.5:7b-bolt",
    "max_steps":     30,
    "timeout":       900,                            # seconds, default 900 (15 min)
    "verbose":       false                           # include tool-call trace?
  }

Response 200:
  { "ok": true, "output": "...", "duration_ms": 12345, "model": "..." }

Response 4xx/5xx:
  { "ok": false, "error": "..." }

Run:
  python3 bridge-api.py                # listens on 0.0.0.0:8080
  PORT=9000 HOST=127.0.0.1 python3 bridge-api.py

Stdlib only. No extra deps.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.join(HERE, "ollama-bridge.sh")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
DEFAULT_TIMEOUT = int(os.environ.get("DEFAULT_TIMEOUT", "900"))
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s).replace("\r", "")


def build_prompt(body: dict) -> str:
    target = (body.get("target") or "").strip()
    targets = body.get("targets") or []
    if isinstance(targets, list):
        targets = [str(t).strip() for t in targets if str(t).strip()]
    else:
        targets = []
    iocs = body.get("iocs") or []
    infra = (body.get("infra") or "").strip()
    extra = (body.get("instructions") or "").strip()

    parts = []
    if target:
        parts.append(f"Target (single host, string form): {target}")
    if targets:
        parts.append("Targets (list form, JSON array): " + json.dumps(targets))
    if target and targets:
        parts.append(
            "Note: when calling a tool whose schema takes a single host "
            "(e.g. nmap, httpx, sslscan, nuclei), pass the string form. "
            "When calling a tool whose schema takes a list, pass the array form. "
            "Match the tool's parameter type — do not coerce."
        )
    if iocs:
        parts.append("IoCs: " + ", ".join(str(i) for i in iocs))
    if infra:
        parts.append(f"Infrastructure context: {infra}")
    if extra:
        parts.append(f"Additional instructions: {extra}")
    parts.append("Recon this target now. Begin with a tool call.")
    return "\n".join(parts)


def run_bridge(prompt: str, model: Optional[str], max_steps: Optional[int],
               verbose: bool, timeout: int,
               system_prompt: Optional[str]) -> Tuple[bool, str, int, str]:
    env = os.environ.copy()
    if model:
        env["MODEL"] = model
    if max_steps is not None:
        env["MAX_STEPS"] = str(max_steps)

    sp_file = None
    if system_prompt:
        # Write to tempfile so we don't hit env-var size limits and so
        # mcphost reads it as a file (it accepts text or path; file is safer).
        sp_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8")
        sp_file.write(system_prompt)
        sp_file.flush()
        sp_file.close()
        env["SYSTEM_PROMPT"] = sp_file.name

    cmd = [BRIDGE, "--compact", "-p", prompt]
    if not verbose:
        cmd.append("--quiet")

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        if sp_file:
            os.unlink(sp_file.name)
        return False, "", int((time.monotonic() - started) * 1000), f"timeout after {timeout}s"
    finally:
        if sp_file and os.path.exists(sp_file.name):
            os.unlink(sp_file.name)

    duration_ms = int((time.monotonic() - started) * 1000)
    out = strip_ansi(proc.stdout).strip()
    err = strip_ansi(proc.stderr).strip()
    if proc.returncode != 0:
        return False, out, duration_ms, err or f"exit {proc.returncode}"
    return True, out, duration_ms, ""


def health() -> Tuple[bool, dict]:
    checks = {}
    try:
        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3).read()
        checks["ollama"] = "ok"
    except Exception as e:
        checks["ollama"] = f"unreachable: {e}"
    try:
        urllib.request.urlopen("http://localhost:3001/health", timeout=3).read()
        checks["bolt"] = "ok"
    except Exception as e:
        checks["bolt"] = f"unreachable: {e}"
    checks["bridge_script"] = "ok" if os.access(BRIDGE, os.X_OK) else f"missing/not-executable: {BRIDGE}"
    ok = all(v == "ok" for v in checks.values())
    return ok, checks


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] {self.address_string()} {fmt % args}\n")

    def _json(self, status: int, body: dict):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            ok, checks = health()
            return self._json(200 if ok else 503, {"ok": ok, "checks": checks})
        return self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path != "/scan":
            return self._json(404, {"ok": False, "error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception as e:
            return self._json(400, {"ok": False, "error": f"bad json: {e}"})
        if "targets" in body and not isinstance(body["targets"], list):
            return self._json(400, {"ok": False, "error": "'targets' must be an array of strings"})
        raw_prompt = (body.get("prompt") or "").strip()
        has_targets = isinstance(body.get("targets"), list) and len(body["targets"]) > 0
        if not raw_prompt and not body.get("target") and not has_targets:
            return self._json(400, {"ok": False, "error": "either 'prompt', 'target', or 'targets' is required"})

        prompt = raw_prompt or build_prompt(body)
        timeout = int(body.get("timeout") or DEFAULT_TIMEOUT)
        ok, out, ms, err = run_bridge(
            prompt=prompt,
            model=body.get("model"),
            max_steps=body.get("max_steps"),
            verbose=bool(body.get("verbose", False)),
            timeout=timeout,
            system_prompt=body.get("system_prompt"),
        )
        return self._json(
            200 if ok else 500,
            {"ok": ok, "output": out, "duration_ms": ms,
             "model": body.get("model") or os.environ.get("MODEL", "default"),
             "error": err if not ok else None},
        )


def main():
    if not os.access(BRIDGE, os.X_OK):
        sys.exit(f"error: {BRIDGE} not found or not executable")
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f"bridge-api listening on http://{HOST}:{PORT}", flush=True)
    print(f"  POST /scan  – run a recon job", flush=True)
    print(f"  GET  /health – reachability check", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
