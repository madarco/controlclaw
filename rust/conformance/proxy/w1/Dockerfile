# The proxy rig: Ubuntu 24.04 with mitmproxy 12.2.2 in a venv (as the role installs it) and the
# tools the runner needs. The repository and the cc-proxy binary are mounted at run time (run.sh).
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl iproute2 \
      python3 python3-venv \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/mitm \
 && /opt/mitm/bin/pip install --no-cache-dir mitmproxy==12.2.2 pyyaml==6.0.2
ENV PATH=/opt/mitm/bin:$PATH
WORKDIR /repo/rust/conformance/proxy/w1
ENTRYPOINT ["python3", "rig.py"]
