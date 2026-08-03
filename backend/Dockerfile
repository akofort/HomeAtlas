FROM python:3.12-slim

# iproute2 -> `ip neigh` / `ip route` (ARP table and default gateway, the backbone of discovery)
# iputils-ping + traceroute -> the live diagnostics the assistant runs
# snmp -> snmpget/snmpwalk, for read-only SNMPv2c probing of switches (see probe_auth.probe_snmp)
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping traceroute snmp \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data
VOLUME ["/data"]

# Bound to loopback on purpose: the container runs with network_mode host (it has to, to see the
# real LAN), so binding 0.0.0.0 would publish the unauthenticated-by-default API on every
# interface of the Docker host. nginx sits in front and is the only thing that reaches it.
#
# The port is a variable for the same reason: on the host network this is the *host's* loopback,
# so it collides with anything else already listening there. 8000 is a common default for other
# apps, hence 8281 (next to the UI's 8280).
ENV HOMEATLAS_BIND=127.0.0.1
ENV HOMEATLAS_API_PORT=8281
EXPOSE 8281
CMD ["sh", "-c", "exec uvicorn app.main:app --host \"$HOMEATLAS_BIND\" --port \"$HOMEATLAS_API_PORT\""]
