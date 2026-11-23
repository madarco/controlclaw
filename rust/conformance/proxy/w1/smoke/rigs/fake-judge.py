"""Fake inline AI judge for the smoke test (the mitm-agent's POST /judge). Decides by path so the
test can steer it, and records every payload it receives to /logs/judge.jsonl."""
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        payload = json.loads(body or b"{}")
        with open("/logs/judge.jsonl", "a") as fh:
            fh.write(json.dumps(payload) + "\n")
        path = payload.get("path", "")
        if path.startswith("/slow"):
            time.sleep(5)
        if path.startswith("/boom"):
            self.send_response(500)
            self.end_headers()
            return
        if payload.get("mode") == "approve":
            out = ({"decision": "allow", "category": "normal", "by": "ai"} if "/approve" in path
                   else {"decision": "ask", "category": "policy_mismatch"})
        elif path.startswith("/exfil"):
            out = {"decision": "block", "category": "data_exfiltration"}
        elif path.startswith("/ask"):
            out = {"decision": "ask", "category": "destructive_change"}
        else:
            out = {"decision": "allow", "category": "normal"}
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", 3101), Handler).serve_forever()
