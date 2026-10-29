ARG GOLANG_VERSION=1.25
# Any Debian release published for both the golang and debian images works
# (e.g. --build-arg DEBIAN_RELEASE=bookworm).
ARG DEBIAN_RELEASE=trixie

FROM golang:${GOLANG_VERSION}-${DEBIAN_RELEASE} AS builder

WORKDIR /build

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=dev
ARG BUILD_DATE=unknown
ARG GIT_COMMIT=unknown

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux go build \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE} -X main.GitCommit=${GIT_COMMIT}" \
    -trimpath \
    -o heplify \
    ./src/cmd/heplify

# ──────────────────────────────────────────────────────
FROM debian:${DEBIAN_RELEASE}-slim

ARG VERSION=dev
ARG BUILD_DATE=unknown
ARG GIT_COMMIT=unknown

LABEL org.opencontainers.image.title="heplify" \
      org.opencontainers.image.description="HEP Agent and Collector for the SIPCAPTURE ecosystem" \
      org.opencontainers.image.url="https://github.com/sipcapture/heplify" \
      org.opencontainers.image.source="https://github.com/sipcapture/heplify" \
      org.opencontainers.image.licenses="AGPL-3.0" \
      org.opencontainers.image.vendor="SIPCAPTURE" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=builder /build/heplify /usr/local/bin/heplify

# libpcap0.8 was renamed libpcap0.8t64 in Debian 13 (time_t transition).
# Run as an unprivileged user: capture needs CAP_NET_RAW (AF_PACKET) and
# CAP_NET_ADMIN (promiscuous mode), granted to the binary as file capabilities.
# Both must therefore be in the container capability set (cap_add), or the
# binary cannot be executed. libcap2-bin is only needed for setcap.
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends ca-certificates libcap2-bin && \
    { apt-get install -y --no-install-recommends libpcap0.8t64 || \
      apt-get install -y --no-install-recommends libpcap0.8; } && \
    setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/heplify && \
    apt-get purge -y --auto-remove libcap2-bin && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    groupadd --system heplify && \
    useradd --system --gid heplify --home-dir /var/lib/heplify --no-create-home \
        --shell /usr/sbin/nologin heplify && \
    install -d -o heplify -g heplify /var/lib/heplify

COPY examples/heplify.json  /etc/heplify/heplify.json
COPY examples/example.lua   /etc/heplify/example.lua

ENV HEPLIFY_CONFIG=/etc/heplify/heplify.json

# Relative paths in the config (e.g. hep-buffer.dump) end up here.
WORKDIR /var/lib/heplify
USER heplify

ENTRYPOINT ["heplify"]
CMD ["-config", "/etc/heplify/heplify.json"]
