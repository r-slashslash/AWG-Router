# AWG Router — панель управления AmneziaWG: клиенты, сервер, каскадная маршрутизация.
# Собирает amneziawg-go и awg (AWG 3.1) из исходников Amnezia, hev-socks5-tunnel (выходы SOCKS5);
# lego берётся из официального образа.

ARG AWG_GO_REF=v3.1.20260828
ARG AWG_TOOLS_REF=v3.1.20260812
ARG LEGO_IMAGE=goacme/lego:v5.6.0
ARG HEV_REF=2.9.3

FROM ${LEGO_IMAGE} AS lego

FROM golang:1.26-alpine AS awg-go
ARG AWG_GO_REF
RUN apk add --no-cache git
RUN git clone --depth 1 --branch "${AWG_GO_REF}" https://github.com/amnezia-vpn/amneziawg-go /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/amneziawg-go .

FROM alpine:3.24 AS awg-tools
ARG AWG_TOOLS_REF
RUN apk add --no-cache git build-base linux-headers
# статическая сборка: этот же awg копируется на хост в режиме «AWG на хосте»
RUN git clone --depth 1 --branch "${AWG_TOOLS_REF}" https://github.com/amnezia-vpn/amneziawg-tools /src \
 && make -C /src/src -j"$(nproc)" LDFLAGS=-static \
 && install -D -m 0755 /src/src/wg /out/awg \
 && install -D -m 0755 /src/src/wg-quick/linux.bash /out/awg-quick

# hev-socks5-tunnel (MIT): TUN → SOCKS5 для выходов через прокси
FROM alpine:3.24 AS hev
ARG HEV_REF
RUN apk add --no-cache git make gcc musl-dev linux-headers
RUN git clone --depth 1 --branch "${HEV_REF}" --recurse-submodules --shallow-submodules \
      https://github.com/heiher/hev-socks5-tunnel /src \
 && make -C /src -j"$(nproc)" ENABLE_STATIC=1 \
 && install -D -m 0755 /src/bin/hev-socks5-tunnel /out/hev-socks5-tunnel

FROM python:3.13-alpine
# по этой метке GHCR связывает готовый образ с репозиторием
LABEL org.opencontainers.image.source="https://github.com/r-slashslash/AWG-Router"
RUN apk add --no-cache iproute2 iproute2-tc nftables util-linux-misc procps-ng ca-certificates openssl bash
COPY --from=awg-go /out/amneziawg-go /usr/bin/amneziawg-go
COPY --from=awg-tools /out/awg /usr/bin/awg
COPY --from=awg-tools /out/awg-quick /usr/bin/awg-quick
COPY --from=lego /lego /usr/bin/lego
COPY --from=hev /out/hev-socks5-tunnel /usr/bin/hev-socks5-tunnel
WORKDIR /opt/awg-router
COPY app ./app
ENV DATA_DIR=/data PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
VOLUME ["/data"]
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s CMD ["python3", "-m", "app.health"]
CMD ["python3", "-m", "app.main"]
