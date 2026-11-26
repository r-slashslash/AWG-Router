// Адреса сервера (1.25.0): «Напрямую — адрес» в выборе выхода, поля вкладки «Сервер», блок «Адреса сервера» на
// «Маршрутизации» и его окна (входящий адрес — галочки клиентов, исходящий — галочки мест «Напрямую» и выходов).
"use strict";

/* ================================================================ общее */
const isDirect = (v) => v === "direct" || (typeof v === "string" && v.startsWith("direct@"));
/** исходящие адреса для выбора выхода: [{v, ip, state}], основной первым; пусто — адрес один (просто «Напрямую») */
function directAddrs() {
  const A = S.addrs || {}, sys = (A.system || {}).ip || "", main = A.main || "";
  const extra = (A.out || []).filter((x) => x.state !== "bad");
  if (!extra.length) return [];
  const st = (ip) => (extra.find((x) => x.ip === ip) || {}).state || "checking";
  const out = [{ v: "direct", ip: main || sys, state: main ? st(main) : "ok" }];
  if (main) out.push({ v: "direct@system", ip: sys, state: "ok" });
  for (const x of extra) if (x.ip !== main) out.push({ v: "direct@" + x.ip, ip: x.ip, state: x.state });
  return out;
}
/** адрес «Напрямую» (direct — основной, direct@system — адрес системы) → IP для показа */
function addrOf(v) {
  const A = S.addrs || {};
  const a = !v || v === "direct" ? (A.main || "system") : v.slice(7);
  return a === "system" ? ((A.system || {}).ip || "") : a;
}
/** «Напрямую» или, когда исходящих адресов два и больше, «Напрямую — 198.51.100.7» */
function directName(v) {
  if (!directAddrs().length && (v === "direct" || v === "direct@system")) return t("out.direct");
  return t("out.direct_at", { addr: addrOf(v) || "?" });
}
/** один и тот же путь: «Напрямую» и «Напрямую — основной адрес» — одно и то же */
function sameOut(a, b) {
  return isDirect(a) && isDirect(b) ? addrOf(a) === addrOf(b) : a === b;
}
/** пункты «Напрямую» для outOptions: основной первым; неработающий — серый, «не работает» */
function directOptions(selected) {
  const list = directAddrs();
  if (!list.length) return [["direct", t("out.direct"), false]];
  const out = list.map((x) => [x.v, t("out.direct_at", { addr: x.ip || "?" }) + (x.state === "failed" ? " — " + t("out.addr_down") : ""),
    x.state === "failed" && !sameOut(x.v, selected)]);
  // выбран адрес, который так и не заработал (его нет в списке): показать его, а не молча «основной»
  if (typeof selected === "string" && selected.startsWith("direct@") && !list.some((x) => sameOut(x.v, selected)))
    out.push([selected, t("out.direct_at", { addr: addrOf(selected) }) + " — " + t("out.addr_down"), false]);
  return out;
}
/** подсказка под выбором выхода через другой сервер: с какого адреса он подключается (адрес там не выбирается) */
function bindHintHtml(v) {
  if (typeof v !== "string" || !v.startsWith("up:") || !directAddrs().length) return "";
  const u = upstreamById(v.slice(3));
  if (!u) return "";
  const ip = addrOf(u.bind ? "direct@" + u.bind : "direct");
  return th("addr.exit_from", { name: `<bdi>${esc(u.name)}</bdi>`, addr: `<bdi dir="ltr">${esc(ip)}</bdi>` });
}
/** «Сайты видят 203.0.113.5 · Германия» (lc — с маленькой буквы, внутри фразы) */
function seesHtml(seen, cc, lc = false) {
  if (!seen) return "";
  const c = cc ? " · " + esc(countryName(cc.toLowerCase())) : "";
  return `${th(lc ? "addr.sees_lc" : "addr.sees", { ip: `<bdi dir="ltr">${esc(seen)}</bdi>` })}${c}`;
}
/** состояние входящего адреса — строкой (окно входящего адреса и вкладка «Сервер») */
function inState(h) {
  const A = S.addrs || {};
  if (!/^[\d.]+$/.test(h)) return { cls: "muted", key: h.includes(":") ? "ra.in_v6" : "ra.in_domain" };
  const x = (A.in || []).find((o) => o.ip === h) || (A.out || []).find((o) => o.ip === h)
    || (h === (A.system || {}).ip || h === (A.system || {}).seen ? { state: "ok" } : null);
  if (!x || x.state === "checking") return { cls: "muted", key: "addr.checking" };
  return x.state === "ok" ? { cls: "ok-text", key: "ra.in_ok", dot: "ok" } : { cls: "bad-text", key: "ra.in_bad", dot: "bad", error: x.error };
}
/** «Открытые соединения переподключатся по новому пути» после сохранения, которое сменило путь */
function reconnectToast(r) { if (r && r.reconnect) toast(t("toast.reconnect")); }

/** «Подключаться с адреса» в окне выхода: основной первым (пусто), затем остальные исходящие адреса */
function bindOptions(cur) {
  return directAddrs().map((x, i) => {
    const v = i === 0 ? "" : x.v === "direct@system" ? "system" : x.ip;
    const sel = (cur || "") === v || (i === 0 && cur && addrOf("direct@" + cur) === x.ip);
    return `<option value="${esc(v)}" ${sel ? "selected" : ""} ${x.state === "failed" && !sel ? "disabled" : ""}>${esc(x.ip + (x.state === "failed" ? " — " + t("out.addr_down") : ""))}</option>`;
  }).join("");
}

/* ================================================================ вкладка «Сервер» */
/** входящие адреса для выбора: найденные IPv4 и IPv6, дополнительные и выбранный сейчас */
function inChoices() {
  const A = SRV.addrs || {}, out = [];
  const add = (v) => { if (v && !out.includes(v)) out.push(v); };
  add(A.v4);
  (A.v6 || []).forEach(add);
  (SRV.extra_hosts || []).forEach(add);
  add(SRV.client_host);
  return out;
}
function inOptions() {
  const cur = SRV.client_host || "";
  return inChoices().map((v) => `<option value="${esc(v)}" ${v === cur ? "selected" : ""}>${esc(v)}</option>`).join("");
}
/** исходящие адреса для выбора основного: адрес системы и дополнительные, которые работали */
function outMainOptions() {
  const A = S.addrs || {}, cur = SRV.out_main || "", sys = (A.system || {}).ip || "";
  const opts = [["", sys || "—"]];
  for (const x of A.out || []) if (x.state !== "bad" || x.ip === cur) opts.push([x.ip, x.ip]);
  return opts.map(([v, l]) => `<option value="${esc(v)}" ${v === cur ? "selected" : ""}>${esc(l)}</option>`).join("");
}
/** строка «адрес — что с ним» под полем дополнительных адресов */
function addrLine(x, out) {
  const ip = `<bdi dir="ltr">${esc(x.ip)}</bdi>`;
  const err = esc(x.error ? tm(x.error) : "—");
  if (x.state === "ok") {
    const s = out ? th("addr.st_works", { ip, sees: seesHtml(x.seen, x.cc, true) }) : th(x.ours ? "addr.st_added" : "addr.st_here", { ip });
    return `<div class="small addr-st ok">✓ ${s}</div>`;
  }
  if (!out && (x.state === "failed" || x.state === "bad")) return `<div class="small addr-st bad">✕ ${th("addr.st_in_bad", { ip, error: err })}</div>`;
  if (x.state === "failed") return `<div class="small addr-st bad">✕ ${th("addr.st_failed", { ip, error: err })}</div>`;
  if (x.state === "bad") return `<div class="small addr-st bad">✕ ${th("addr.st_bad", { ip, error: err })}</div>`;
  return `<div class="small addr-st muted">… ${th("addr.st_checking", { ip })}</div>`;
}
/** состояния входящих (kind "in") или исходящих ("out") адресов — опрос обновляет их (drawAddrStatus) */
function addrStatusHtml(kind) {
  const A = S.addrs || {};
  const lines = [];
  if (kind === "in") {
    // только дополнительные: IP — есть ли он на сервере (адрес и исходящий — его проверка), домен и IPv6 — как есть
    for (const h of (SRV && SRV.extra_hosts) || []) {
      const x = (A.in || []).find((o) => o.ip === h) || (A.out || []).find((o) => o.ip === h);
      if (x) { lines.push(addrLine(x, false)); continue; }
      const ip = `<bdi dir="ltr">${esc(h)}</bdi>`;
      const key = h.includes(":") ? "addr.st_v6" : /^[\d.]+$/.test(h) ? "addr.st_checking" : "addr.st_domain";
      lines.push(`<div class="small addr-st muted">${key === "addr.st_checking" ? "…" : "•"} ${th(key, { ip })}</div>`);
    }
  } else {
    (A.out || []).forEach((x) => lines.push(addrLine(x, true)));
  }
  return `<div id="addr-st-${kind}" class="addr-sts">${lines.join("")}</div>`;
}
/** опрос: строки состояния адресов на вкладке «Сервер» (поля не трогаются) */
function drawAddrStatus() {
  for (const kind of ["in", "out"]) {
    const el = $("#addr-st-" + kind);
    if (!el) continue;
    const tpl = document.createElement("template");
    tpl.innerHTML = addrStatusHtml(kind).trim();
    const fresh = tpl.content.firstElementChild;
    if (fresh && fresh.outerHTML !== el.outerHTML) el.replaceWith(fresh);
  }
  const sees = $("#s-out-sees");
  if (sees) sees.innerHTML = outMainSees($("#s-out-main") ? $("#s-out-main").value : "");
}
/** «Сайты видят …» под выбором основного исходящего адреса */
function outMainSees(v) {
  const A = S.addrs || {};
  const x = v ? (A.out || []).find((o) => o.ip === v) : { ...(A.system || {}), state: "ok" };
  if (!x) return "";
  if (x.state === "failed") return `<span class="bad-text">${esc(t("ra.down"))}</span>`;
  return x.seen ? `<span class="ok-text">${seesHtml(x.seen, x.cc)}</span>` : "";
}
function srvAddrFields() {
  return `
    <label class="field"><span>${esc(t("srv.in_host"))}</span><select data-field="client_host" id="s-in">${inOptions()}</select>
      <span class="hint" id="s-in-hint">${clientHostHint(SRV.client_host)}</span></label>
    <label class="field"><span>${esc(t("srv.in_extra"))}</span><input type="text" data-field="extra_hosts" id="s-extra" dir="ltr" placeholder="203.0.113.20, vpn2.example.com" value="${esc((SRV.extra_hosts || []).join(", "))}">
      <span class="hint">${esc(t("srv.in_extra_hint"))}</span>${addrStatusHtml("in")}</label>
    <label class="field"><span>${esc(t("srv.out_host"))}</span><select data-field="out_main" id="s-out-main">${outMainOptions()}</select>
      <span class="small" id="s-out-sees">${outMainSees(SRV.out_main || "")}</span><span class="hint">${esc(t("srv.out_host_hint"))}</span></label>
    <label class="field"><span>${esc(t("srv.out_extra"))}</span><input type="text" data-field="out_hosts" id="s-out" dir="ltr" placeholder="198.51.100.7, 198.51.100.8" value="${esc((SRV.out_hosts || []).join(", "))}">
      <span class="hint">${esc(t("srv.out_extra_hint"))}</span>${addrStatusHtml("out")}</label>`;
}
/** «Да / Нет» перед сохранением адресов: что переедет на новый основной, что стоит на убранном, кому новый конфиг */
function addrConfirmText(c) {
  const parts = [];
  const more = (n, shown) => (n > shown ? " " + t("ra.more", { n: n - shown }) : "");
  if (c.moved) parts.push(t("addr.confirm_move", { from: c.from === "system" ? addrOf("direct@system") : c.from,
    to: c.to === "system" ? addrOf("direct@system") : c.to, where: tm(c.moved) + more(c.moved_n, c.moved.length) }));
  if (c.removed) parts.push(t("addr.confirm_removed", { where: tm(c.removed) + more(c.removed_n, c.removed.length) }));
  if (c.clients) parts.push(t("addr.confirm_clients", { where: tm(c.clients) + more(c.clients_n, c.clients.length) }));
  parts.push(t("addr.confirm_q"));
  return parts.join("\n\n");
}

/* ================================================================ «Маршрутизация» → «Адреса сервера» */
function addrCount(n) { return n ? t("ra.in_count", { n }) : t("ra.in_nobody"); }
function serverAddrsHtml() {
  const A = S.addrs || {};
  if (!S.hosts) return "";
  const main = S.hosts.default || "";
  const ins = [main, ...(S.hosts.choices || []).filter((h) => h !== main)].filter(Boolean);
  const chev = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" class="chev"><path d="M9 6l6 6-6 6"/></svg>`;
  const inCards = ins.map((h) => {
    const who = S.clients.filter((c) => (c.host || main) === h);
    const names = h === main ? "" : who.map((c) => c.name || c.ip).slice(0, 4).join(sep("list")) + (who.length > 4 ? " " + t("ra.more", { n: who.length - 4 }) : "");
    const dom = !/^[\d.]+$/.test(h) && !h.includes(":");
    return `<button type="button" class="panel addr-card" data-addr-in="${esc(h)}">
      <span class="addr-main"><span><b dir="ltr" class="mono">${esc(h)}</b>${h === main ? ` <span class="pill">${esc(t("ra.main"))}</span>` : ""}${dom ? ` <span class="pill">${esc(t("ra.domain"))}</span>` : ""}</span>
        <span class="small muted">${esc(names ? t("ra.in_with", { count: addrCount(who.length), names }) : addrCount(who.length))}</span></span>${chev}</button>`;
  }).join("");
  const outs = [{ ip: (A.system || {}).ip || "", key: "system", state: "ok", seen: (A.system || {}).seen, cc: (A.system || {}).cc },
    ...(A.out || []).filter((x) => x.state !== "bad").map((x) => ({ ...x, key: x.ip }))];
  const mainKey = A.main || "system";
  const outCards = (A.out || []).length ? outs.map((x) => {
    const u = (A.uses || {})[x.key] || { direct: [], direct_n: 0, exits: [] };
    const where = [];
    if (u.direct_n) where.push(t("ra.direct_where", { where: tm(u.direct) + (u.direct_n > u.direct.length ? " " + t("ra.more", { n: u.direct_n - u.direct.length }) : "") }));
    if (u.exits.length) where.push(t("ra.exits_from", { n: u.exits.length, names: u.exits.join(sep("list")) }));
    if (A.own_src && x.key === A.own_src) where.push(t("ref.own_src"));
    const down = x.state === "failed";
    return `<button type="button" class="panel addr-card ${down ? "down" : ""}" data-addr-out="${esc(x.key)}">
      <span class="addr-main"><span><b dir="ltr" class="mono">${esc(x.ip || "—")}</b>${x.key === mainKey ? ` <span class="pill">${esc(t("ra.main"))}</span>` : ""}</span>
        <span class="small ${down ? "bad-text" : x.state === "ok" ? "ok-text" : "muted"}"><span class="dot ${down ? "bad" : x.state === "ok" ? "ok" : ""}"></span>${down ? esc(t("ra.down")) : seesHtml(x.seen, x.cc) || esc(t("addr.checking"))}</span>
        ${where.length ? `<span class="small muted">${esc(where.join(" · "))}</span>` : ""}</span>${chev}</button>`;
  }).join("") : `<p class="muted small" style="margin:0">${esc(t("ra.out_none"))}</p>`;
  return `<section class="section" id="ra-sec">
    <div class="section-head"><div><h2>${esc(t("ra.title"))}</h2><p class="muted small">${esc(t("ra.sub"))}</p></div></div>
    <div class="addr-grp small muted">${esc(t("ra.in"))}</div><div class="addr-cards">${inCards}</div>
    <div class="addr-grp small muted">${esc(t("ra.out"))}</div><div class="addr-cards">${outCards}</div>
  </section>`;
}
/** опрос: блок «Адреса сервера» — по новому состоянию (адрес перестал работать, клиента перенесли) */
function drawServerAddrs() {
  const el = $("#ra-sec");
  if (!el) return;
  const tpl = document.createElement("template");
  tpl.innerHTML = serverAddrsHtml().trim();
  const fresh = tpl.content.firstElementChild;
  if (fresh && fresh.outerHTML !== el.outerHTML) { el.replaceWith(fresh); bindServerAddrs(); }
}
function bindServerAddrs() {
  $$("[data-addr-in]").forEach((b) => b.onclick = () => openAddrIn(b.dataset.addrIn));
  $$("[data-addr-out]").forEach((b) => b.onclick = () => openAddrOut(b.dataset.addrOut));
}
/** окно входящего адреса: галочка — клиент подключается к нему (адрес в его конфиге), снятая — к основному */
function openAddrIn(h) {
  const main = S.hosts.default || "";
  const isMain = h === main;
  const rows = S.clients.map((c) => {
    const cur = c.host || main, on = cur === h;
    return `<label class="check addr-row" data-q="${esc(((c.name || "") + " " + (c.ip || "")).toLowerCase())}"><input type="checkbox" data-pk="${esc(c.public_key)}" ${on ? "checked" : ""} ${isMain && on ? "disabled" : ""}>
      <span><bdi>${esc(c.name || c.ip)}</bdi> <span class="muted small" dir="ltr">${esc(c.ip || "")}</span>${on ? "" : `<span class="small muted addr-now">${th("ra.now", { addr: `<bdi dir="ltr">${esc(cur)}</bdi>` })}</span>`}</span></label>`;
  }).join("");
  const s = inState(h);
  const body = `<div class="addr-head"><b dir="ltr" class="mono">${esc(h)}</b>
      <div class="small ${s.cls}">${s.dot ? `<span class="dot ${s.dot}"></span>` : ""}${esc(t(s.key, { error: s.error ? tm(s.error) : "—" }))}</div></div>
    <p class="small muted">${th(isMain ? "ra.in_text_main" : "ra.in_text", { main: `<bdi dir="ltr">${esc(main)}</bdi>` })}</p>
    <p class="small addr-note">${esc(t("ra.in_note"))}</p>
    <label class="field"><span>${esc(t("ra.find"))}</span><input type="search" id="ra-q" placeholder="${esc(t("ra.find_ph"))}"></label>
    <div id="ra-rows">${rows || `<p class="muted small">${esc(t("cl.empty"))}</p>`}</div>
    <p class="small muted">${esc(t("ra.in_same", { field: t("cl.host") }))}</p>`;
  openModal(t("ra.in_title"), body, `<button class="btn ghost" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="ra-ok">${esc(t("btn.save"))}</button>`);
  $("#ra-q").oninput = (e) => {
    const q = e.target.value.trim().toLowerCase();
    $$("#ra-rows [data-q]").forEach((r) => { r.hidden = q && !r.dataset.q.includes(q); });
  };
  $("#ra-ok").onclick = async () => {
    const clients = $$("#ra-rows input[data-pk]").filter((i) => i.checked).map((i) => i.dataset.pk);
    $("#ra-ok").disabled = true;
    try {
      const r = await api("PUT", "addr-in", { host: h, clients });
      closeModal();
      toast(r.moved && r.moved.length ? t("ra.in_moved", { names: r.moved.slice(0, 6).join(sep("list")) }) : t("toast.settings_saved"));
      refresh();
    } catch (e) { toast(e.message, true); $("#ra-ok").disabled = false; }
  };
}
/** окно исходящего адреса: «Напрямую» у каждого свой адрес; выход через другой сервер — один адрес на выход */
async function openAddrOut(key) {
  let P;
  try { P = await api("GET", "addr-places"); } catch (e) { toast(e.message, true); return; }
  const A = S.addrs || {};
  const x = key === "system" ? { ip: (A.system || {}).ip, ...(A.system || {}), state: "ok" } : (A.out || []).find((o) => o.ip === key) || { ip: key };
  const isMain = key === (P.main || "system");
  const ipOf = (a) => (a === "system" ? (A.system || {}).ip || "" : a);
  const row = (attr, id, label, cur, onKey, extra = "") => {
    const on = cur === key;
    const where = on ? th(onKey, { addr: `<bdi dir="ltr">${esc(ipOf(key))}</bdi>` }) : th("ra.now_from", { addr: `<bdi dir="ltr">${esc(ipOf(cur))}</bdi>` });
    return `<label class="check addr-row"><input type="checkbox" ${attr}="${esc(id)}" ${on ? "checked" : ""} ${isMain && on ? "disabled" : ""}>
      <span>${label}<span class="small muted addr-now">${where}${extra}</span></span></label>`;
  };
  const direct = P.direct.map((p) => row("data-place", p.key, esc(tm(p.label)), p.addr, "ra.from")).join("");
  const exits = P.exits.map((u) => row("data-exit", u.id, `<bdi>${esc(u.name)}</bdi>`, u.addr, "ra.exit_from",
    u.refs.length ? ` · ${esc(tm(u.refs))}` : "")).join("");
  const down = x.state === "failed";
  const body = `<div class="addr-head"><b dir="ltr" class="mono">${esc(x.ip || "—")}</b>
      <div class="small ${down ? "bad-text" : x.state === "ok" ? "ok-text" : "muted"}"><span class="dot ${down ? "bad" : x.state === "ok" ? "ok" : ""}"></span>${down ? esc(t("ra.down"))
        : x.state === "ok" ? th("ra.works", { sees: seesHtml(x.seen, x.cc, true) }) : esc(t("addr.checking"))}</div></div>
    <p class="small muted">${th("ra.out_text", { main: `<bdi dir="ltr">${esc(ipOf(P.main || "system"))}</bdi>` })}</p>
    <div class="addr-grp small muted">${esc(t("ra.g_direct"))}</div>
    <div id="ra-direct">${direct || `<p class="muted small">${esc(t("ra.none_direct"))}</p>`}</div>
    <div class="addr-grp small muted">${esc(t("ra.g_exits"))}</div>
    <p class="small muted">${esc(t("ra.exits_text"))}</p>
    <div id="ra-exits">${exits || `<p class="muted small">${esc(t("ra.none_exits"))}</p>`}</div>`;
  openModal(t("ra.out_title"), body, `<button class="btn ghost" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="ra-ok">${esc(t("btn.save"))}</button>`);
  $("#ra-ok").onclick = async () => {
    const pick = (sel, attr) => $$(sel).filter((i) => i.checked).map((i) => i.getAttribute(attr));
    $("#ra-ok").disabled = true;
    try {
      const r = await api("PUT", "addr-out", { addr: key, direct: pick("#ra-direct input[data-place]", "data-place"),
        exits: pick("#ra-exits input[data-exit]", "data-exit") });
      closeModal();
      toast(t("toast.settings_saved"));
      reconnectToast(r);
      refresh();
    } catch (e) { toast(e.message, true); $("#ra-ok").disabled = false; }
  };
}

/* ================================================================ «Система» → «Доступ к панели» */
/** «Адрес панели» и «С какого адреса выходит сам сервер» */
function panelAddrFields() {
  const P = S.panel || {}, T = P.tls || {}, A = S.addrs || {};
  const host = (P.access !== "ssh" && T.host) || P.ip || "";
  const fell = A.own_src && A.own_now && A.own_now !== A.own_src;
  return `<label class="field"><span>${esc(t("sy.panel_host"))}</span><input type="text" id="sy-host" data-field="tls_domain" dir="ltr" autocomplete="off" spellcheck="false" value="${esc(host)}" data-orig="${esc(host)}" placeholder="203.0.113.10">
      <span class="hint">${esc(t("sy.panel_host_hint"))}</span></label>
    <label class="field"><span>${esc(t("sy.own_src"))}</span><select id="sy-own" data-field="own_src">${ownSrcOptions()}</select>
      ${fell ? `<span class="hint warn-text">${th("sy.own_fell", { addr: `<bdi dir="ltr">${esc(A.own_now)}</bdi>` })}</span>` : ""}
      <span class="hint">${esc(t("sy.own_src_hint"))}</span></label>
    <div class="actions" id="sy-addr-bar" hidden><button class="btn sm primary" id="sy-addr-save">${esc(t("btn.save"))}</button></div>`;
}
function bindPanelAddr() {
  const host = $("#sy-host"), own = $("#sy-own");
  if (!host || !own) return;
  const own0 = (S.addrs || {}).own_src || "";
  const dirty = () => { $("#sy-addr-bar").hidden = host.value.trim() === host.dataset.orig && own.value === own0; };
  host.oninput = dirty; own.onchange = dirty;
  const save = async (force = false) => {
    const P = S.panel || {}, T = P.tls || {}, btn = $("#sy-addr-save");
    btn.disabled = true;
    try {
      if (own.value !== own0) await api("PUT", "settings", { own_src: own.value });
      const h = host.value.trim();
      if (h !== host.dataset.orig) {
        const pub = P.access !== "ssh" && (T.mode === "letsencrypt" || T.mode === "selfsigned");
        if (!pub) await api("PUT", "server", { public_host: h });
        else {
          // тот же запрос, что и «Домен и сертификат»: способ и файлы сертификата прежние, меняется только адрес
          const r = await api("PUT", "tls", { domain: h, source: T.source || "letsencrypt", cert: T.cert || "", key: T.key || "",
            challenge: T.challenge || "http", cf_token: "", force });
          if (r.confirm) {
            btn.disabled = false;
            if (confirm(tm(r.confirm) + "\n\n" + t("tls.dns_force"))) return save(true);
            return;
          }
          if (r.warn) toast(tm(r.warn), true);
          else if (r.url && r.url !== P.url) toast(t("tls.moved", { url: r.url }));
          if (r.web && r.web.kind !== "none") webModal(r.web);
        }
      }
      toast(t("toast.settings_saved"));
      refresh();
    } catch (e) { toast(e.message, true); markField(e, $("#main")); btn.disabled = false; }
  };
  $("#sy-addr-save").onclick = () => save(false);
}
function ownSrcOptions() {
  const A = S.addrs || {}, cur = A.own_src || "", sys = (A.system || {}).ip || "";
  const opts = [["", t("sy.own_system", { addr: sys || "—" })]];
  for (const x of A.out || []) if (x.state === "ok" || x.ip === cur) opts.push([x.ip, x.ip + (x.state === "ok" ? "" : " — " + t("out.addr_down"))]);
  return opts.map(([v, l]) => `<option value="${esc(v)}" ${v === cur ? "selected" : ""}>${esc(l)}</option>`).join("");
}
