# The proxy rig: Ubuntu 24.04 with the tools the runner needs (h2 and wsproto for the HTTP/2 and
# WebSocket steps, in a venv). The repository and the cc-proxy binary are mounted at run time (run.sh).
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl iproute2 \
      python3 python3-venv \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/mitm \
 && /opt/mitm/bin/pip install --no-cache-dir h2==4.2.0 wsproto==1.2.0 pyyaml==6.0.2
ENV PATH=/opt/mitm/bin:$PATH
WORKDIR /repo/rust/conformance/proxy/w1
ENTRYPOINT ["python3", "rig.py"]
