# AWG Router — панель управления AmneziaWG: клиенты, сервер, каскадная маршрутизация.
# Собирает amneziawg-go и awg (AWG 3.1) из исходников Amnezia, hev-socks5-tunnel (выходы SOCKS5);
# lego берётся из официального образа.
#
# Чужой код — только по отпечатку (с 1.22.0): исходники — по хешу коммита (название версии на чужой странице
# можно незаметно переставить на другой код), образы — по sha256. Не совпало — сборка останавливается.
# Обновляя программу, меняйте и название версии (*_REF, для людей), и отпечаток (*_SHA); версии AmneziaWG — те
# же, что в awg-server/Dockerfile (это проверяет ProjectRulesTest).

ARG AWG_GO_REF=v3.1.20261116
ARG AWG_GO_SHA=08fe3d33bbb116be09a6183d02609311b8b0c9e8
ARG AWG_TOOLS_REF=v3.1.20260812
ARG AWG_TOOLS_SHA=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
ARG LEGO_IMAGE=goacme/lego:v5.6.0@sha256:6f1583fc026a455ea46a7a5858c576105bb69c2e2de69db391cab7f14750350c
# 2.19.3 — последняя без замедления: в 2.20.0 выход SOCKS5 под пределом скорости давал ~2–12 Мбит/с вместо ~16
# (domains_socks_e2e, 1.22.0). Причина — обновление hev-socks5-core в коммите 8e3b4cd; до него всё как раньше
ARG HEV_REF=2.19.3
ARG HEV_SHA=c5584feca8f6df70ee53eb2879e034b849a3d15a

FROM ${LEGO_IMAGE} AS lego

FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS awg-go
ARG AWG_GO_SHA
RUN apk add --no-cache git
WORKDIR /src
RUN git init -q . && git remote add origin https://github.com/amnezia-vpn/amneziawg-go \
 && git fetch -q --depth 1 origin "${AWG_GO_SHA}" && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "${AWG_GO_SHA}"
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/amneziawg-go .

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS awg-tools
ARG AWG_TOOLS_SHA
RUN apk add --no-cache git build-base linux-headers
# статическая сборка: этот же awg копируется на хост в режиме «AWG на хосте»
WORKDIR /src
RUN git init -q . && git remote add origin https://github.com/amnezia-vpn/amneziawg-tools \
 && git fetch -q --depth 1 origin "${AWG_TOOLS_SHA}" && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "${AWG_TOOLS_SHA}" \
 && make -C /src/src -j"$(nproc)" LDFLAGS=-static \
 && install -D -m 0755 /src/src/wg /out/awg \
 && install -D -m 0755 /src/src/wg-quick/linux.bash /out/awg-quick

# hev-socks5-tunnel (MIT): TUN → SOCKS5 для выходов через прокси. Его части (подмодули git) закреплены
# самим коммитом hev: подменить их, не поменяв его хеш, нельзя.
# Стек сигналов детектора переполнения — 64 КБ вместо SIGSTKSZ (8 КБ): musl с 1.2.6 (alpine 3.24) сверяет размер
# с sysconf(_SC_MINSIGSTKSZ), а на процессорах Intel с AMX (Xeon 4-го поколения и новее) это ~13 КБ — sigaltstack
# отказывал, и hev молча завершался с кодом 254: выходы SOCKS5 не запускались вовсе
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS hev
ARG HEV_SHA
ARG HEV_SIGSTACK=third-part/hev-task-system/src/lib/misc/hev-task-stack-detector.c
RUN apk add --no-cache git make gcc musl-dev linux-headers
WORKDIR /src
RUN git init -q . && git remote add origin https://github.com/heiher/hev-socks5-tunnel \
 && git fetch -q --depth 1 origin "${HEV_SHA}" && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "${HEV_SHA}" \
 && git submodule -q update --init --recursive --depth 1 \
 && sed -i 's/SIGSTKSZ/(64 * 1024)/g' "/src/${HEV_SIGSTACK}" \
 && test "$(grep -c '(64 \* 1024)' "/src/${HEV_SIGSTACK}")" -eq 2 \
 && make -C /src -j"$(nproc)" ENABLE_STATIC=1 \
 && install -D -m 0755 /src/bin/hev-socks5-tunnel /out/hev-socks5-tunnel

FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e
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
# Байткод заранее. В образе Python нет .pyc даже у стандартной библиотеки, а PYTHONDONTWRITEBYTECODE не даёт их
# записать: каждый запуск панели (и каждая проверка здоровья) компилировал всё заново — на VPS с одним ядром это
# 3 секунды до того, как панель ставит свои правила (у контейнера приложения AmneziaVPN всё это время клиенты шли
# мимо выходов). Импорт панели в демо-режиме компилирует ровно то, что ей нужно из стандартной библиотеки.
RUN python3 -m compileall -q app \
 && DRY_RUN=1 DATA_DIR=/tmp/awgr-build PANEL_PASSWORD=build \
    python3 -c "import app.main, app.sniproxy, app.dnsproxy, app.probe, app.tgreq, app.webfront" \
 && rm -rf /tmp/awgr-build
ENV DATA_DIR=/data PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
VOLUME ["/data"]
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s CMD ["python3", "-m", "app.health"]
CMD ["python3", "-m", "app.main"]
