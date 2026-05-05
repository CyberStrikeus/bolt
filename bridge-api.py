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
  {
    "ok":          true,
    "output":      "...final assistant message...",
    "tool_calls":  [
      {
        "seq":    1,
        "tool":   "bolt__crtsh_crtsh",
        "args":   "domain:example.com",
        "status": "ok",                 # or "error"
        "result": "first ~500 chars of tool output…"
      },
      ...
    ],
    "duration_ms": 12345,
    "model":       "qwen2.5:7b-bolt"
    # if verbose: "raw_transcript": "...full ANSI-stripped mcphost output..."
  }

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
# mcphost --compact transcript markers:
#   single-line:   "[ bolt__nmap target:x ] Result <text>"
#   multi-line:    "[ bolt__nmap target:x"   then later "] Result <text>"
#   assistant:     "< model <streamed-token-running-buffer>"
TOOL_FULL_RE  = re.compile(r"^\s*\[\s+(bolt__\S+)\s+(.*?)\s+\]\s+(\S+)\s*(.*?)\s*$")
TOOL_OPEN_RE  = re.compile(r"^\s*\[\s+(bolt__\S+)\s*(.*?)\s*$")
TOOL_CLOSE_RE = re.compile(r"^\s*\]\s+(\S+)\s*(.*?)\s*$")
ASSISTANT_RE  = re.compile(r"^\s*<\s+\S+\s+(.*)$")
NOISE_RE      = re.compile(r"(Thinking\.\.\.|Executing\s+bolt__\S+\.\.\.|Loading Ollama model\.\.\.)")
RESULT_PREVIEW_CHARS = 500


def strip_ansi(s: str) -> str:
    # mcphost uses bare CR to overwrite the same TUI line per token. Replacing
    # CR with LF turns each redraw into its own line so the parser can see
    # markers that would otherwise be glued onto the end of a long spinner row.
    return ANSI_RE.sub("", s).replace("\r", "\n")


def _status_of(kind: str) -> str:
    return "error" if kind.lower().startswith("err") else "ok"


def _is_marker(line: str) -> bool:
    return bool(TOOL_FULL_RE.match(line) or TOOL_OPEN_RE.match(line)
                or TOOL_CLOSE_RE.match(line) or ASSISTANT_RE.match(line))


def _dewrap(lines: list) -> str:
    """Join word-wrapped lines from mcphost's TUI back into a single string.
    Heuristic: a line that ends with a hyphen followed by a line that starts
    with lowercase letters is a wrap split — fuse them. Otherwise keep the
    newline (preserves intentional markdown breaks).
    """
    if not lines:
        return ""
    out = [lines[0]]
    for nxt in lines[1:]:
        prev = out[-1]
        if prev.endswith("-") and nxt and nxt[0].islower():
            out[-1] = prev[:-1] + nxt        # fuse: "hello-from-" + "bridge"
        elif prev and not prev.endswith((".", "!", "?", ":", ";", ",", ")", "]", "}", "*", "`")) \
                and nxt and nxt[0].islower():
            out[-1] = prev + " " + nxt        # fuse: "responded with" + "hello"
        else:
            out.append(nxt)
    return "\n".join(out).strip()


def parse_mcphost_output(raw: str) -> Tuple[str, list, str]:
    """Walk mcphost's --compact transcript and pull out:
      - final assistant message (str)
      - structured list of tool calls
      - cleaned-up transcript (noise stripped) for verbose mode

    Real-world quirks handled:
      - mcphost token-streams assistant messages: each "< model …" line
        is a re-print of the running buffer.
      - the running buffer is word-wrapped to terminal width, so any frame
        spans multiple raw lines — the trailing lines have NO "<" prefix.
      - fast tools render open + close on a SINGLE line ("[ … ] Result …").
    """
    text = strip_ansi(raw)
    cleaned_lines = [l.rstrip() for l in text.split("\n") if not NOISE_RE.search(l)]
    cleaned = "\n".join(cleaned_lines)

    # ---- pass 1: tool_calls (also reset on each new "<") ----
    tool_calls: list = []
    state = "idle"
    cur: Optional[dict] = None
    seq = 0
    for line in cleaned_lines:
        m = TOOL_FULL_RE.match(line)
        if m:
            seq += 1
            tc = {"seq": seq, "tool": m.group(1), "args": m.group(2).strip(),
                  "status": _status_of(m.group(3)), "result": m.group(4).strip()}
            tool_calls.append(tc)
            cur = tc; state = "tool_result"; continue
        m = TOOL_OPEN_RE.match(line)
        if m and "]" not in line:
            seq += 1
            cur = {"seq": seq, "tool": m.group(1), "args": m.group(2).strip(),
                   "status": "pending", "result": ""}
            tool_calls.append(cur)
            state = "tool_open"; continue
        m = TOOL_CLOSE_RE.match(line)
        if m and cur is not None and state in ("tool_open", "tool_result"):
            cur["status"] = _status_of(m.group(1))
            extra = m.group(2).strip()
            cur["result"] = (cur["result"] + " " + extra).strip() if cur["result"] else extra
            state = "tool_result"; continue
        if ASSISTANT_RE.match(line):
            state = "assistant"; cur = None; continue
        bare = line.strip()
        if not bare:
            continue
        if state == "tool_open" and cur is not None:
            cur["args"] = (cur["args"] + " " + bare).strip()
        elif state == "tool_result" and cur is not None:
            cur["result"] = (cur["result"] + " " + bare).strip()

    # ---- pass 2: final assistant message ----
    # Walk from the end backwards; the LAST "<" line is the start of the
    # final streamed frame. Everything after it (until the next marker, which
    # there shouldn't be) is wrap continuation of that same frame.
    final_message = ""
    last_idx = None
    for i in range(len(cleaned_lines) - 1, -1, -1):
        if ASSISTANT_RE.match(cleaned_lines[i]):
            last_idx = i
            break
    if last_idx is not None:
        m = ASSISTANT_RE.match(cleaned_lines[last_idx])
        parts = [m.group(1).rstrip()]
        for j in range(last_idx + 1, len(cleaned_lines)):
            ln = cleaned_lines[j]
            if _is_marker(ln):
                break
            stripped = ln.strip()
            if stripped:
                parts.append(stripped)
            elif parts and parts[-1]:
                parts.append("")  # preserve paragraph breaks
        final_message = _dewrap(parts)

    # truncate giant tool results so the response stays sane
    for c in tool_calls:
        if len(c["result"]) > RESULT_PREVIEW_CHARS:
            c["result"] = c["result"][:RESULT_PREVIEW_CHARS] + "…"

    return final_message, tool_calls, cleaned.strip()


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
               system_prompt: Optional[str]) -> Tuple[bool, str, int, str, list, str]:
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

    # We always capture the full transcript so we can extract tool_calls.
    # `verbose` controls only whether the raw transcript is returned to the client.
    cmd = [BRIDGE, "--compact", "-p", prompt]

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        if sp_file:
            os.unlink(sp_file.name)
        return False, "", int((time.monotonic() - started) * 1000), f"timeout after {timeout}s", [], ""
    finally:
        if sp_file and os.path.exists(sp_file.name):
            os.unlink(sp_file.name)

    duration_ms = int((time.monotonic() - started) * 1000)
    final, tool_calls, transcript = parse_mcphost_output(proc.stdout)
    err = strip_ansi(proc.stderr).strip()
    if proc.returncode != 0:
        return False, final, duration_ms, err or f"exit {proc.returncode}", tool_calls, transcript
    return True, final, duration_ms, "", tool_calls, transcript


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
        verbose = bool(body.get("verbose", False))
        ok, out, ms, err, tool_calls, transcript = run_bridge(
            prompt=prompt,
            model=body.get("model"),
            max_steps=body.get("max_steps"),
            verbose=verbose,
            timeout=timeout,
            system_prompt=body.get("system_prompt"),
        )
        resp = {
            "ok": ok,
            "output": out,
            "tool_calls": tool_calls,
            "duration_ms": ms,
            "model": body.get("model") or os.environ.get("MODEL", "default"),
            "error": err if not ok else None,
        }
        if verbose:
            resp["raw_transcript"] = transcript
        return self._json(200 if ok else 500, resp)


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
