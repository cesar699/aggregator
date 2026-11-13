# Dedicated self-host image for the free-nodes pipeline.
# Build from the repository root with:
#   docker build -f free-nodes/Dockerfile -t csmp-free-nodes .

FROM python:3.11-slim-bookworm

ARG SINGBOX_VERSION=1.14.3
ARG TARGETARCH

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MIHOMO_BIN=/usr/local/bin/mihomo \
    SINGBOX_BIN=/usr/local/bin/sing-box

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*

COPY clash/clash-linux-amd /tmp/mihomo-amd64
COPY clash/clash-linux-arm /tmp/mihomo-arm64
COPY free-nodes /app/free-nodes

RUN set -eux; \
    target_arch="${TARGETARCH:-}"; \
    if [ -z "$target_arch" ]; then \
      case "$(uname -m)" in \
        x86_64) target_arch=amd64 ;; \
        aarch64|arm64) target_arch=arm64 ;; \
        *) echo "Unsupported build architecture: $(uname -m)" >&2; exit 1 ;; \
      esac; \
    fi; \
    case "$target_arch" in \
      amd64) archive_arch=amd64; install -m 0555 /tmp/mihomo-amd64 /usr/local/bin/mihomo ;; \
      arm64) archive_arch=arm64; install -m 0555 /tmp/mihomo-arm64 /usr/local/bin/mihomo ;; \
      *) echo "Unsupported target architecture: $target_arch (use amd64 or arm64)" >&2; exit 1 ;; \
    esac; \
    curl --fail --show-error --location --retry 3 --retry-delay 2 \
      "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${archive_arch}.tar.gz" \
      -o /tmp/sing-box.tar.gz; \
    tar -xzf /tmp/sing-box.tar.gz -C /tmp; \
    install -m 0555 "/tmp/sing-box-${SINGBOX_VERSION}-linux-${archive_arch}/sing-box" /usr/local/bin/sing-box; \
    /usr/local/bin/sing-box version; \
    rm -rf /tmp/mihomo-amd64 /tmp/mihomo-arm64 /tmp/sing-box.tar.gz "/tmp/sing-box-${SINGBOX_VERSION}-linux-${archive_arch}"

RUN pip install --no-cache-dir requests PyYAML

WORKDIR /app
CMD ["python", "free-nodes/run.py", "--publish", "local", "--out", "/data/run", "--publish-dir", "/data/published"]
