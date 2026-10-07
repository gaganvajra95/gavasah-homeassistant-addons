ARG BUILD_FROM=alpine:3.19
FROM ${BUILD_FROM}

# Install essential dependencies
RUN apk add --no-cache \
    bash \
    curl \
    jq \
    python3 \
    py3-pip \
    py3-requests \
    py3-websocket-client \
    autossh \
    openssh-client \
    socat \
    iproute2 \
    net-tools \
    bind-tools \
    ca-certificates

# Copy rootfs files
COPY rootfs /

# Set executable permissions
RUN chmod +x /usr/bin/entrypoint.sh /usr/bin/heartbeat.py

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
