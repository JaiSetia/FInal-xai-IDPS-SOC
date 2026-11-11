FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap hydra hping3 sqlmap curl iproute2 slowhttptest iputils-ping tcpreplay \
    && rm -rf /var/lib/apt/lists/*
# Build context is lab/ (see docker-compose.yml).
COPY attacker/entrypoint.sh /entrypoint.sh
COPY attacks /attacks
RUN chmod +x /entrypoint.sh /attacks/*.sh
ENTRYPOINT ["/entrypoint.sh"]
