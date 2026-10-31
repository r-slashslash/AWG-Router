"""Сигнатурные пакеты I1–I5 (CPS, custom protocol signature): проверка и готовые шаблоны.

Перед каждым рукопожатием клиент отправляет до пяти UDP-пакетов I1…I5, сервер их выбрасывает.
Пакет собирается из тегов:
  <b 0xHEX>  фиксированные байты          <r N>   N случайных байт
  <rc N>     N случайных букв a–z, A–Z    <rd N>  N случайных цифр
  <t>        время, 4 байта (big-endian)
Только эти пять тегов понимают и amneziawg-go, и модуль ядра: <c> есть только в модуле ядра,
<d>/<ds>/<dz> — только в amneziawg-go, с чужим тегом сторона не запустится.

Шаблоны повторяют начало настоящих протоколов, а изменчивые поля (ID, имена, ключи) — случайные,
чтобы у DPI не было одинаковой строки байт на все рукопожатия.
"""
from __future__ import annotations

import re

from .i18n import Msg, MsgError

KEYS = ("I1", "I2", "I3", "I4", "I5")
PORTABLE = ("b", "r", "rc", "rd", "t")
ENGINE_ONLY = ("c", "d", "ds", "dz")
MAX_PACKET = 1400       # больше — пакет фрагментируется почти на любом пути (MTU 1500 − заголовки)
MAX_TAG = 1400
WARN_PACKET = 1200

TOKEN_RE = re.compile(r"<[^<>]*>|[^<>\s]+|[<>]")
HEX_RE = re.compile(r"^0x((?:[0-9a-fA-F]{2})+)$")


class CPSError(MsgError, ValueError):
    pass


def size(value: str, key: str = "I1") -> int:
    """Длина пакета в байтах; CPSError, если значение нельзя отдать клиенту."""
    total = 0
    for tok in TOKEN_RE.findall(value or ""):
        if not (tok.startswith("<") and tok.endswith(">") and len(tok) > 2):
            raise CPSError(Msg("srv.cps_text", key=key))
        name, _, arg = tok[1:-1].strip().partition(" ")
        name, arg = name.lower(), arg.strip()
        if name in ENGINE_ONLY:
            raise CPSError(Msg("srv.cps_unsupported", key=key, tag=f"<{name}>"))
        if name not in PORTABLE:
            raise CPSError(Msg("srv.cps_tag", key=key, tag=f"<{name}>"))
        if name == "b":
            m = HEX_RE.match(arg)
            if not m:
                raise CPSError(Msg("srv.cps_hex", key=key))
            total += len(m.group(1)) // 2
        elif name == "t":
            if arg:
                raise CPSError(Msg("srv.cps_num", key=key, tag="<t>"))
            total += 4
        else:
            if not arg.isdigit() or not 1 <= int(arg) <= MAX_TAG:
                raise CPSError(Msg("srv.cps_num", key=key, tag=f"<{name}>"))
            total += int(arg)
    if total > MAX_PACKET:
        raise CPSError(Msg("srv.cps_size", key=key, size=total, max=MAX_PACKET))
    return total


def validate(values: dict) -> dict[str, str]:
    """{I1..I5: значение} → нормализованные значения (пустое — пакета нет)."""
    out = {}
    for k in KEYS:
        v = " ".join(str(values.get(k) or "").split())
        if v:
            size(v, k)
        out[k] = v
    return out


# ------------------------------------------------------------------ шаблоны
def _b(raw: bytes | str) -> str:
    if isinstance(raw, str):
        raw = raw.encode()
    return f"<b 0x{raw.hex()}>"


def _quic() -> str:
    # RFC 9000, Initial: 0b11000011 (long header, Initial, номер пакета 4 байта), версия 1,
    # DCID 8 байт, SCID 0 (как у Chrome), токен 0, длина остатка (varint 2 байта) = 1182.
    # Дальше номер пакета и зашифрованные данные — на проводе это случайные байты.
    # Первый пакет клиента QUIC по стандарту не короче 1200 байт: короткий выдаёт подделку.
    rest = 1200 - 18
    return (_b(bytes.fromhex("c300000001") + b"\x08") + "<r 8>"
            + _b(b"\x00\x00" + (0x4000 | rest).to_bytes(2, "big")) + f"<r {rest}>")


def _dns() -> str:
    # RFC 1035 запрос A случайного имени .com + EDNS0 (RFC 6891, UDP 1232) с дополнением
    # (RFC 7830) до 128 байт, как у современных резолверов (RFC 8467).
    head = bytes.fromhex("0100" "0001" "0000" "0000" "0001")          # RD, 1 вопрос, 1 доп. запись
    pad = 128 - (2 + len(head) + 1 + 12 + 5 + 4 + 11 + 4)
    opt = (b"\x00" + bytes.fromhex("0029" "04d0" "00" "00" "0000") + (4 + pad).to_bytes(2, "big")
           + bytes.fromhex("000c") + pad.to_bytes(2, "big") + bytes(pad))
    return ("<r 2>" + _b(head + b"\x0c") + "<rc 12>" + _b(b"\x03com\x00" + bytes.fromhex("00010001") + opt))


def _sip() -> str:
    # RFC 3261 INVITE без тела; номера, домены, branch, tag и Call-ID — случайные
    crlf = "\r\n"
    return ("".join([
        _b("INVITE sip:"), "<rd 10>", _b("@"), "<rc 8>", _b(".com SIP/2.0" + crlf),
        _b("Via: SIP/2.0/UDP 192.168.1."), "<rd 2>", _b(":5060;branch=z9hG4bK"), "<rc 16>",
        _b(crlf + "Max-Forwards: 70" + crlf + "From: <sip:"), "<rd 10>", _b("@"), "<rc 8>",
        _b(".com>;tag="), "<rc 10>", _b(crlf + "To: <sip:"), "<rd 10>", _b("@"), "<rc 8>",
        _b(".com>" + crlf + "Call-ID: "), "<rc 24>",
        _b(crlf + "CSeq: 1 INVITE" + crlf + "Contact: <sip:"), "<rd 10>", _b("@192.168.1."), "<rd 2>",
        _b(":5060>" + crlf + "Content-Length: 0" + crlf + crlf)]))


def _stun() -> str:
    # RFC 8489/8445: Binding Request проверки ICE, как в WebRTC (звонки в браузере, мессенджерах).
    # Атрибуты: USERNAME «ufrag:ufrag» (9 байт + 3 выравнивания), ICE-CONTROLLING, PRIORITY,
    # MESSAGE-INTEGRITY, FINGERPRINT; ID транзакции и значения — случайные.
    attrs_len = (4 + 12) + (4 + 8) + (4 + 4) + (4 + 20) + (4 + 4)
    return (_b(bytes.fromhex("0001") + attrs_len.to_bytes(2, "big") + bytes.fromhex("2112a442")) + "<r 12>"
            + _b(bytes.fromhex("00060009")) + "<rc 4>" + _b(":") + "<rc 4>" + _b(bytes(3))
            + _b(bytes.fromhex("802a0008")) + "<r 8>"
            + _b(bytes.fromhex("00240004")) + "<r 4>"
            + _b(bytes.fromhex("00080014")) + "<r 20>"
            + _b(bytes.fromhex("80280004")) + "<r 4>")


AMNEZIA_I1 = ("<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c0001000100"
              "00105a00044d583737>")

# порядок — как в списке выбора
PRESETS: dict[str, dict[str, str]] = {
    "amnezia": {"I1": AMNEZIA_I1},
    "stun": {"I1": _stun()},
    "quic": {"I1": _quic()},
    "dns": {"I1": _dns()},
    "sip": {"I1": _sip()},
    "none": {},
}


def preset(name: str) -> dict[str, str]:
    p = PRESETS[name]
    return {k: p.get(k, "") for k in KEYS}


def for_client(entry) -> dict[str, str] | None:
    """Свои I1–I5 клиента (state["cps"][pk]) → значения; None — как на сервере."""
    if not isinstance(entry, dict):
        return None
    p = entry.get("preset")
    if p in PRESETS:
        return preset(p)
    if p == "custom":
        try:
            return validate(entry.get("values") or {})
        except CPSError:
            return None
    return None


def match(values: dict) -> str | None:
    """Какому шаблону равны значения (для подписи «как на сервере (QUIC)»)."""
    v = {k: " ".join(str(values.get(k) or "").split()) for k in KEYS}
    for name in PRESETS:
        if preset(name) == v:
            return name
    return None


def catalog() -> list[dict]:
    """Шаблоны для браузера: значения и размеры пакетов."""
    return [{"id": n, "values": preset(n), "sizes": {k: size(v, k) for k, v in preset(n).items() if v}}
            for n in PRESETS]
