# Сервер AmneziaWG в контейнере — так же, как его ставит приложение AmneziaVPN
# (контейнер amnezia-awg2, конфиги в /opt/amnezia/awg). Приложение AmneziaVPN
# увидит этот сервер при «сканировании», а AWG Router управляет им как обычно.
FROM amneziavpn/amneziawg-go:latest

LABEL maintainer="AWG Router"
RUN apk add --no-cache bash curl dumb-init iptables && apk --update upgrade --no-cache
RUN mkdir -p /opt/amnezia/awg
COPY start.sh /opt/amnezia/start.sh
RUN chmod a+x /opt/amnezia/start.sh

ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
CMD [ "" ]
