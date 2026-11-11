FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv tcpdump nftables iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/idps
# Build context is the repo root (see lab/docker-compose.yml); .dockerignore keeps
# data, models, secrets and git history out of the image.
COPY pyproject.toml README.md ./
COPY idps ./idps
COPY soc ./soc
# Forwarding is enabled via the compose sysctl; the sensor routes attack_net <-> victim_net.
CMD ["sleep", "infinity"]
