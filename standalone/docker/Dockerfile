# The ControlClaw firewall in one image: the firewall agent (mitm-agent), cc-proxy, the firewall's page
# assets (dist-ui/) and OpenConnector. Built by build.sh for linux/amd64 and linux/arm64 from the
# static musl binaries of rust/scripts/build-box.sh (bin/<arch>/ in the build context).
#
# The base is the OpenConnector image the Ansible role pins (same digest, multi-arch, Alpine with
# Node), flattened so its VOLUME and healthcheck do not come along. Its packages are what the digest
# holds; openssl (the CA at first start), tini, su-exec and dnsmasq (the agents' DNS) come from
# Alpine's archive on the day of the build.
#
# The entrypoint runs as root and starts each program as its own user: cc-proxy and the firewall
# agent as controlclaw (10001; the agent writes the proxy's files 0600, so they share it, as on a VM),
# OpenConnector as connector (10003). The connector's keys file is root's: only the connector and the
# firewall agent get them, in their environment.
ARG CONNECTOR_IMAGE=ghcr.io/oomol-lab/open-connector@sha256:f25207e6f71eabc70182c4f5db5c01db79091d0f4523a7495b35e649d5b6c006
FROM ${CONNECTOR_IMAGE} AS connector

FROM scratch
COPY --from=connector / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin NODE_ENV=production
RUN apk add --no-cache openssl tini su-exec dnsmasq wireguard-tools nftables socat \
 && addgroup -S -g 10001 controlclaw \
 && adduser -S -D -H -h /opt/controlclaw -u 10001 -G controlclaw controlclaw \
 && addgroup -S -g 10003 connector \
 && adduser -S -D -H -h /opt/controlclaw/connector -u 10003 -G connector connector \
 && mkdir -p /opt/controlclaw /run/mitm/config \
 && chmod 755 /opt/controlclaw \
 && chown controlclaw:controlclaw /run/mitm/config \
 && chmod 700 /run/mitm/config \
 && ln -s /usr/local/lib/controlclaw/mitm-agent /usr/local/bin/mitm-agent
ARG TARGETARCH
# The binaries with dist-ui/ next to mitm-agent, where it reads its page assets.
COPY bin/${TARGETARCH}/ /usr/local/lib/controlclaw/
COPY lib/firstrun.sh lib/wg-sync.sh lib/cc-proxy.env lib/mitm-agent.env lib/connector.env lib/dnsmasq.conf docker/entrypoint.sh /usr/local/lib/controlclaw/
# CC_HOSTNAME: the name a browser reaches the firewall's pages at (written to keys/vm_hostname), for
# the links `docker exec -u controlclaw <container> mitm-agent open logins` prints.
# The pages and webhooks listener: loopback on a VM (a reverse proxy on the host hands it requests),
# all addresses in a container, whose loopback the host cannot reach. Publish it to the host's
# loopback (compose.yaml).
ENV INGRESS_BIND=0.0.0.0
WORKDIR /opt/controlclaw
VOLUME /opt/controlclaw
# 8080 the proxy agents connect through, 3100 the firewall agent, 8790 the pages and webhooks,
# 3900 and 3940 the gates agents dial (with CONNECTOR_GATE_BIND set), 53 the agents' DNS, 8801 pairing,
# 8800 the local panel.
EXPOSE 8080 3100 8790 3900 3940 53/udp 53/tcp 8801 8800
ENTRYPOINT ["/sbin/tini", "-g", "--", "/bin/sh", "/usr/local/lib/controlclaw/entrypoint.sh"]
