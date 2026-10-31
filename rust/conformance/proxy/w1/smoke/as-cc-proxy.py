"""Rewrite a smoke compose file's `proxy` service to run cc-proxy instead of mitmproxy.

    python3 as-cc-proxy.py docker-compose.smoke.yml ...   (in place, in a copy of the smoke folder)

Only the proxy service changes: the image, the command, and the environment the Rust unit needs on
top of what the rig already sets. `--ssl-insecure` becomes MITM_DEV_INSECURE_UPSTREAM, the rigs'
stand-ins on Docker's private networks need MITM_DEV_PRIVATE_PASSTHROUGH, and the checks W2 has not
built yet are skipped with MITM_DEV_WITHOUT_CHECKS: dev flags, each named in MITM_ALLOW_DEV_FLAGS.
The content rules are an empty list baked into the image (the Dockerfile).
"""
import sys

import yaml

IMAGE = "controlclaw-cc-proxy-smoke:local"
EXTRA = {
    "MITM_CA_DIR": "/ca",
    # Only these three: run-smoke.sh checks that any other dev flag is still refused.
    "MITM_ALLOW_DEV_FLAGS": "MITM_DEV_INSECURE_UPSTREAM,MITM_DEV_PRIVATE_PASSTHROUGH,MITM_DEV_WITHOUT_CHECKS",
    "MITM_DEV_INSECURE_UPSTREAM": "1",
    "MITM_DEV_PRIVATE_PASSTHROUGH": "1",
    "MITM_DEV_WITHOUT_CHECKS": "1",
    # The firewall agent always writes content rules; the rigs (written for the addon) do not. With
    # none, W2's checks refuse every body they would read: an empty list from the image instead,
    # as rig.py gives its cases.
    "MITM_CONTENT_RULES_PATH": "/opt/cc-smoke/content-rules.json",
}

for path in sys.argv[1:]:
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    proxy = (doc.get("services") or {}).get("proxy")
    if proxy is None:
        continue
    if "image" in proxy or "command" in proxy:
        proxy["image"] = IMAGE
        # mitmproxy takes about two seconds to listen, and the scripts' "wait for proxy" loops count
        # on the stand-in servers being up by then (run-smoke.sh A8 reads the first record).
        proxy["command"] = ["sh", "-c", "sleep 2; exec cc-proxy --listen 0.0.0.0:8080"]
    env = proxy.get("environment") or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) for e in env)
    for k, v in EXTRA.items():
        env.setdefault(k, v)
    proxy["environment"] = env
    with open(path, "w") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False)
