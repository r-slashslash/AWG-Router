# Сервер AmneziaWG в контейнере — так же, как его ставит приложение AmneziaVPN
# (контейнер amnezia-awg2, конфиги в /opt/amnezia/awg). Приложение AmneziaVPN
# увидит этот сервер при «сканировании», а AWG Router управляет им как обычно.
#
# С 1.22.0 образ собирается здесь, из тех же исходников, что amneziawg-go и awg в образе панели (раньше —
# готовый amneziavpn/amneziawg-go:latest на Alpine 3.19, без обновлений системы), и обновляется вместе с
# панелью (install.sh, refresh_own_server). Чужой код — только по отпечатку; версии AmneziaWG — те же, что в
# Dockerfile панели (это проверяет ProjectRulesTest).

ARG AWG_GO_REF=v3.1.20261116
ARG AWG_GO_SHA=08fe3d33bbb116be09a6183d02609311b8b0c9e8
ARG AWG_TOOLS_REF=v3.1.20260812
ARG AWG_TOOLS_SHA=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843

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
WORKDIR /src
RUN git init -q . && git remote add origin https://github.com/amnezia-vpn/amneziawg-tools \
 && git fetch -q --depth 1 origin "${AWG_TOOLS_SHA}" && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "${AWG_TOOLS_SHA}" \
 && make -C /src/src -j"$(nproc)" LDFLAGS=-static \
 && install -D -m 0755 /src/src/wg /out/awg \
 && install -D -m 0755 /src/src/wg-quick/linux.bash /out/awg-quick

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
LABEL maintainer="AWG Router" \
      org.opencontainers.image.source="https://github.com/r-slashslash/AWG-Router"
# iproute2 — awg-quick (ip link … type amneziawg, маршруты), iptables — NAT клиентов в start.sh, nftables — правила
# панели «до её запуска», kmod — загрузка модуля ядра из смонтированного /lib/modules
RUN apk add --no-cache bash dumb-init iproute2 iptables nftables kmod
COPY --from=awg-go /out/amneziawg-go /usr/bin/amneziawg-go
COPY --from=awg-tools /out/awg /usr/bin/awg
COPY --from=awg-tools /out/awg-quick /usr/bin/awg-quick
RUN mkdir -p /opt/amnezia/awg
COPY start.sh /opt/amnezia/start.sh
RUN chmod a+x /opt/amnezia/start.sh

ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
CMD [ "" ]
