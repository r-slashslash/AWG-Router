"""Е: копия app с отметками NFTADD в журнале dnsproxy.py (сколько команд nft, время и процессор каждой).
Запуск: python3 -I e_mkdbg.py <исходная app> <новая app>"""
import shutil, sys
src, dst = sys.argv[1], sys.argv[2]
shutil.rmtree(dst, ignore_errors=True)
shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
p = dst + "/dnsproxy.py"
s = open(p).read()
old = '''    @staticmethod
    def _nft_add(table: str, name: str, items: list) -> None:
'''
new = '''    @staticmethod
    def _nft_add(table: str, name: str, items: list) -> None:
        _t = time.monotonic(); _c = os.times()
        try:
            Proxy._nft_add0(table, name, items)
        finally:
            _c2 = os.times()
            print(f"NFTADD n={len(items)} wall={time.monotonic() - _t:.4f} child_cpu="
                  f"{(_c2.children_user + _c2.children_system) - (_c.children_user + _c.children_system):.4f}", flush=True)

    @staticmethod
    def _nft_add0(table: str, name: str, items: list) -> None:
'''
assert s.count(old) == 1
open(p, "w").write(s.replace(old, new))
