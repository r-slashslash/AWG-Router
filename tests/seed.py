"""До 1.22.0 новая установка начиналась со списков стран ru, cn, ir и правила r_geo «напрямую»; многие тесты на
них опираются. С 1.22.0 новая установка — без правил и списков (решение владельца 2026-11-19), и такие тесты кладут
эти списки сами: legacy_lists(store) или legacy(st) для снимка."""
COUNTRIES = ("ru", "cn", "ir")


def legacy(st: dict) -> dict:
    have = {l["id"] for l in st["lists"]}
    for cc in COUNTRIES:
        if cc not in have:
            st["lists"].append({"id": cc, "name": "", "kind": "country", "source": cc})
    return st


def legacy_lists(store) -> None:
    store.mutate(legacy)
