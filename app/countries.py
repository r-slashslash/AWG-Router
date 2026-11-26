"""Готовые правила для стран (1.22.0, решение владельца 2026-11-19): Россия, Китай, Иран — сайты страны напрямую по
адресам и по её доменам, со своим DNS страны. Один источник для кнопок «Применить для …» в «Обзоре», выбора страны в
правиле и запасного DNS на сервере для пути «напрямую» (когда шифрованный DNS из страны сервера не проходит)."""
from __future__ import annotations

# зоны — как их пишут люди (с точкой, своими буквами); в список доменов их разбирает domains.parse (в punycode)
# dns_enc — местные серверы с шифрованием (DoH и DoT; имена для TLS — dnsproxy.KNOWN_NAMES): запасной DNS пути
# «напрямую» спрашивает сначала их, и только если и они не отвечают — dns без шифрования (владелец 2026-11-26). У Ирана
# подтверждённого шифрованного местного DNS нет.
PRESETS: dict[str, dict] = {
    "ru": {"zones": (".ru", ".su", ".рф"), "dns": ("77.88.8.8", "77.88.8.1"),                  # Яндекс
           "dns_enc": ("77.88.8.8",)},
    "cn": {"zones": (".cn", ".中国", ".中國"), "dns": ("223.5.5.5", "223.6.6.6"),               # Alibaba
           "dns_enc": ("223.5.5.5", "1.12.12.12")},                                            # Alibaba, DNSPod
    "ir": {"zones": (".ir", ".ایران"), "dns": ("178.22.122.100", "185.51.200.2")},             # Shecan
}


def preset(cc) -> dict | None:
    return PRESETS.get(str(cc or "").lower())


def zones_text(cc: str) -> str:
    return "\n".join(PRESETS[cc]["zones"])


def local_dns(cc) -> list[str]:
    """Местный DNS страны сервера (код страны из проверки «напрямую», любой регистр); [] — не знаем такого."""
    p = preset(cc)
    return list(p["dns"]) if p else []


def local_dns_enc(cc) -> list[str]:
    """Местный DNS страны сервера с шифрованием (DoH/DoT); [] — нет такого."""
    p = preset(cc)
    return list(p.get("dns_enc") or ()) if p else []


def view() -> dict:
    """Для браузера: {код: {zones, dns}}."""
    return {cc: {"zones": list(p["zones"]), "dns": list(p["dns"])} for cc, p in PRESETS.items()}
