FROM python:3.12-slim

# iproute2 -> `ip neigh` / `ip route` (ARP table and default gateway, the backbone of discovery)
# iputils-ping + traceroute -> the live diagnostics the assistant runs
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping traceroute \
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
ENV HOMEATLAS_BIND=127.0.0.1
EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn app.main:app --host \"$HOMEATLAS_BIND\" --port 8000"]
