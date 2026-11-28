"""Ж: копия tests/netns_e2e.py с другим правилом «замерзания после рукопожатия»: вместо порога «байты рукопожатия + 200»
(зависит от числа подтверждений TCP и пропускает короткий контрольный запрос на новом соединении) — отбрасывать пакеты
клиента, в которых начинается запись TLS с данными (тип 0x17: в TLS 1.3 это всё после рукопожатия, и запрос, и «. NS»).
Пустые подтверждения TCP и ClientHello (0x16) проходят. Запуск: python3 -I zh_freezefix.py tests/netns_e2e.py tests/netns_e2e_zh.py"""
import sys

src, dst = sys.argv[1], sys.argv[2]
s = open(src, encoding="utf-8").read()
old = 'f"ct original bytes > {hs + 200} drop"'
assert old in s, "правило не найдено"
s = s.replace(old, '"@ih,0,8 0x17 drop"')
open(dst, "w", encoding="utf-8").write(s)
print("patched", dst)
