# cc-proxy in place of the smoke rigs' mitmproxy image: the static binary on Ubuntu 24.04.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY cc-proxy /usr/local/bin/cc-proxy
# No content rules (the rigs write none; the firewall agent always does on a box).
RUN mkdir -p /opt/cc-smoke && echo '{"version": 1, "rules": []}' > /opt/cc-smoke/content-rules.json
