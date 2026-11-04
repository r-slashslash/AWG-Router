"use strict";
/* Интерфейс панели. Тексты — в i18n.js (t, th), сообщения сервера — через tm(). */

/* ================================================================ утилиты */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const BYTE_UNITS = {
  ru: ["Б", "КБ", "МБ", "ГБ", "ТБ"], en: ["B", "KB", "MB", "GB", "TB"],
  zh: ["B", "KB", "MB", "GB", "TB"], fa: ["بایت", "کیلوبایت", "مگابایت", "گیگابایت", "ترابایت"],
};
function fmtBytes(b) {
  const u = BYTE_UNITS[LANG] || BYTE_UNITS.en;
  if (!b) return `${fmtNum(0)} ${u[0]}`;
  const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1);
  return (b / 1024 ** i).toLocaleString(LANG, { maximumFractionDigits: i ? 1 : 0 }) + " " + u[i];
}
function fmtAge(sec) {
  if (sec == null) return t("never");
  sec = Math.max(0, Math.round(sec));
  const rtf = new Intl.RelativeTimeFormat(LANG, { numeric: "always", style: "short" });
  if (sec < 60) return rtf.format(-sec, "second");
  if (sec < 3600) return rtf.format(-Math.floor(sec / 60), "minute");
  if (sec < 86400) return rtf.format(-Math.floor(sec / 3600), "hour");
  return rtf.format(-Math.floor(sec / 86400), "day");
}
/** когда начнётся следующий месяц учёта (1-е число, 00:00 UTC) по часам браузера — для подсказок */
function monthResetLocal() {
  const n = new Date(), d = new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth() + 1, 1));
  return d.toLocaleDateString(LANG, { day: "numeric", month: "short" }) + ", "
    + d.toLocaleTimeString(LANG, { hour: "2-digit", minute: "2-digit" });
}
function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000), now = new Date();
  const time = d.toLocaleTimeString(LANG, { hour: "2-digit", minute: "2-digit" });
  return d.toDateString() === now.toDateString() ? time
    : d.toLocaleDateString(LANG, { day: "numeric", month: "short" }) + ", " + time;
}
function fmtCompact(n) { return Number(n).toLocaleString(LANG, { notation: "compact", maximumSignificantDigits: 3 }); }
let _regions = null;
function countryName(cc) {
  try {
    if (!_regions || _regions.lang !== LANG) _regions = { lang: LANG, dn: new Intl.DisplayNames([LANG], { type: "region" }) };
    return _regions.dn.of(cc.toUpperCase()) || cc.toUpperCase();
  } catch { return cc.toUpperCase(); }
}
/** Сообщение сервера {$t, p} → текст на текущем языке */
function tm(x) {
  if (x == null) return "";
  if (typeof x === "string" || typeof x === "number") return String(x);
  if (Array.isArray(x)) return x.map(tm).join(sep("refs"));
  if (x.$t) {
    const p = {};
    for (const [k, v] of Object.entries(x.p || {})) p[k] = k === "list" ? listName(v) : tm(v);
    return t(x.$t, p);
  }
  return String(x);
}

function toast(msg, bad = false) {
  const el = document.createElement("div");
  el.className = "toast" + (bad ? " bad" : "");
  el.textContent = msg;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), bad ? 6000 : 3000);
}

class AuthError extends Error {}
async function api(method, path, body) {
  const opt = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const r = await fetch("api/" + path, opt);
  if (r.status === 401 && path !== "login") { showLogin(); throw new AuthError(t("auth.required")); }
  let data = null;
  try { data = await r.json(); } catch { /* пусто */ }
  if (!r.ok) throw new Error(data && data.detail ? tm(data.detail) : `HTTP ${r.status}`);
  return data;
}

/* ================================================================ состояние */
let S = null;
let tab = (location.hash || "#overview").slice(1);
let scrollToLists = tab === "lists";             // закладка на старую вкладку «Списки» (до 1.12.1)
if (tab === "lists") { tab = "routing"; history.replaceState(null, "", "#routing"); }
let routingDraft = null;
const probes = {};
let pollTimer = null;

const LINE_COLORS = 8;
function upstreamById(id) { return S.upstreams.find((u) => u.id === id); }
function upstreamByNum(n) { return S.upstreams.find((u) => u.num === n); }
function lineVar(u) { return `var(--l${((u.num - 1) % LINE_COLORS) + 1})`; }
function listObj(id) { return S && S.lists.find((x) => x.id === id); }
function listName(id) {
  const l = listObj(id);
  if (!l) return id;
  if (l.name) return l.name;
  return l.kind === "country" ? countryName(l.source) : (l.source || l.id);
}
function exitName(v) {
  if (v === "direct") return t("out.direct");
  if (v === "block") return t("out.block");
  const u = typeof v === "string" && v.startsWith("up:") ? upstreamById(v.slice(3)) : null;
  return u ? u.name : t("out.deleted");
}

/** чип выхода по значению из настроек: direct | block | up:<id> */
function outChip(v, extra = "") {
  if (v === "direct") return `<span class="line direct">${esc(t("out.direct"))}${extra}</span>`;
  if (v === "block") return `<span class="line block">${esc(t("out.block"))}${extra}</span>`;
  if (typeof v === "string" && v.startsWith("up:")) {
    const u = upstreamById(v.slice(3));
    if (!u) return `<span class="line block">${esc(t("out.deleted"))}</span>`;
    return `<span class="line" style="--c:${lineVar(u)}"><bdi>${esc(u.name)}</bdi>${extra}</span>`;
  }
  return `<span class="line">${esc(v)}</span>`;
}
/** чип фактического выхода (после резерва): direct | block | номер туннеля */
function effChip(eff, wanted) {
  const val = eff === "direct" || eff === "block" ? eff : "up:" + (upstreamByNum(eff) || {}).id;
  if (wanted && wanted !== val) {
    const w = wanted.startsWith("up:") ? (upstreamById(wanted.slice(3)) || {}).name : null;
    const html = outChip(val, w ? ` <span class="sub">${th("out.instead", { name: `<bdi>${esc(w)}</bdi>` })}</span>` : "");
    return html.replace('class="line', 'class="line fallback');
  }
  return outChip(val);
}
function outOptions(selected, { inherit = null, exclude = null, socksOnly = false } = {}) {
  const opts = [];
  if (inherit !== null) opts.push(["inherit", inherit]);
  if (!socksOnly) opts.push(["direct", t("out.direct")]);
  for (const u of S.upstreams) if ("up:" + u.id !== exclude && (!socksOnly || u.kind === "socks5")) opts.push(["up:" + u.id, t("out.via", { name: u.name })]);
  if (!socksOnly) opts.push(["block", t("out.block")]);
  if (socksOnly && !opts.some(([v]) => v === selected)) opts.unshift([selected, t("re.need_socks")]);
  return opts.map(([v, l]) => `<option value="${esc(v)}" ${v === selected ? "selected" : ""}>${esc(l)}</option>`).join("");
}
function rulesSummary(rules) {
  const rs = rules.filter((r) => r.enabled);
  if (!rs.length) return `<p class="muted small" style="margin:0">${esc(t("ov.no_rules"))}</p>`;
  return `<ol class="summary">${rs.map((r) => `<li>${r.lists.map((l) => `<bdi>${esc(listName(l))}</bdi>`).join(esc(sep("list")))} — ${outChip(r.outbound)}</li>`).join("")}</ol>`;
}

/* ================================================================ язык */
function langSelect(id) {
  return `<select id="${id}" class="lang-select" aria-label="${esc(t("lang"))}">${Object.entries(LANGS)
    .map(([k, v]) => `<option value="${k}" ${k === LANG ? "selected" : ""}>${v.name}</option>`).join("")}</select>`;
}
function bindLang(id) {
  const el = $("#" + id);
  if (el) el.onchange = () => { setLang(el.value, true); applyStaticTexts(); if (S) { renderStatus(); render(); } };
}
function applyStaticTexts() {
  $$("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $("#lang-login").outerHTML = langSelect("lang-login");
  $("#lang-top").outerHTML = langSelect("lang-top");
  bindLang("lang-login");
  bindLang("lang-top");
}

/* ================================================================ вход */
function showLogin() {
  clearInterval(pollTimer);
  closeModal();
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#login-code-wrap").hidden = true;
  $("#login-code").value = "";
  $("#login-pass").focus();
}
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-err").hidden = true;
  const codeWrap = $("#login-code-wrap");
  const body = { password: $("#login-pass").value };
  if (!codeWrap.hidden) body.code = $("#login-code").value.replace(/\D/g, "");
  try {
    const r = await api("POST", "login", body);
    if (r && r.need_code) {
      // пароль верный, включён вход по коду — спрашиваем код
      codeWrap.hidden = false;
      $("#login-code").focus();
      return;
    }
    $("#login-pass").value = "";
    $("#login-code").value = "";
    codeWrap.hidden = true;
    boot();
  } catch (err) {
    $("#login-err").textContent = err.message;
    $("#login-err").hidden = false;
    if (!codeWrap.hidden) { $("#login-code").value = ""; $("#login-code").focus(); }
  }
});

/* ================================================================ каркас */
let lastTyping = 0;
document.addEventListener("input", () => { lastTyping = Date.now(); }, true);
document.addEventListener("focusin", (e) => { if (["INPUT", "SELECT", "TEXTAREA"].includes(e.target.tagName)) lastTyping = Date.now(); }, true);
async function refresh(auto = false) {
  try {
    S = await api("GET", "state");
  } catch (e) {
    if (e instanceof AuthError) return;
    if (updatingTo) { setUpdLine(t("sy.updating_restart")); return; }   // панель перезапускается
    toast(t("panel.offline", { e: e.message }), true);
    return;
  }
  if (followUpdate()) return;
  renderStatus();
  // при фоновом опросе не трогаем вкладки с формами и результатами проверок
  if (auto && !["overview", "clients", "exits"].includes(tab)) return;
  if (auto && $("#modal").open) return;
  // не перерисовываем, пока человек печатает в поиске или выбирает сортировку
  const a = document.activeElement;
  if (auto && a && $("#main").contains(a) && ["INPUT", "SELECT", "TEXTAREA"].includes(a.tagName)
      && Date.now() - lastTyping < 15000) return;
  render();
}

async function boot() {
  $("#login").hidden = true;
  await refresh();
  if (!S) return;
  try {
    const done = sessionStorage.getItem("awgr.updated");
    if (done) { sessionStorage.removeItem("awgr.updated"); toast(t("sy.update_done", { version: done })); }
  } catch { /* нет хранилища */ }
  $("#app").hidden = false;
  clearInterval(pollTimer);
  pollTimer = setInterval(() => { if (!document.hidden) refresh(true); }, 5000);
}

$("#tabs").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-tab]");
  if (!b) return;
  if (tab === "routing" && routingDirty() && !confirm(t("rt.leave"))) return;
  if (tab === "routing") routingDraft = null;
  tab = b.dataset.tab;
  if (tab === "server") { SRV = null; srvDraft = null; }
  history.replaceState(null, "", "#" + tab);
  render();
  window.scrollTo(0, 0);
});

// итог всего сервера за всё время — рядом с названием; разбивка по направлениям во всплывающей подсказке
function renderBrandTraffic() {
  const el = $("#brand-traffic"), x = S.server_traffic;
  el.hidden = !x;
  if (!x) return;
  const sum = (x.total_rx || 0) + (x.total_tx || 0);
  el.title = t("status.traffic_hint") + ": " + arrowsText(x, "total");
  el.innerHTML = `${esc(t("status.traffic"))}: <b>${esc(fmtBytes(sum))}</b>`;
}

function renderStatus() {
  const tg = S.target;
  const online = S.clients.filter((c) => c.live && c.live.handshake && S.now - c.live.handshake < 180).length;
  renderBrandTraffic();
  $("#status").innerHTML = tg
    ? `<span class="state"><span class="dot ${tg.exists === false ? "warn" : "ok"}"></span><b>${esc(tg.kind === "host" ? t("srv.kind_host") : tg.container)}</b> · ${esc(tg.iface)}</span>
       <span>${esc(t("n.clients", { n: S.clients.length }) + sep("phrase") + t("status.online", { n: online }))}</span>`
    : `<span class="state"><span class="dot bad"></span>${esc(t("status.no_target"))}</span>`;
  // новая версия: метка в строке состояния (видна и на телефоне) и точка на вкладке «Система»
  const v = S.version || {};
  const chip = updatingTo ? t("status.updating") : v.available ? t("status.update", { version: v.latest }) : "";
  if (chip) $("#status").insertAdjacentHTML("beforeend", `<button type="button" class="upd-chip" id="upd-chip">${esc(chip)}</button>`);
  const uc = $("#upd-chip");
  if (uc) uc.onclick = () => goTab("system");
  $("#tabs [data-tab=system]").classList.toggle("has-news", !!v.available && !updatingTo);
  $$("#tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === tab));
}

function render(force = false) {
  const views = { overview: viewOverview, clients: viewClients, exits: viewExits, routing: viewRouting, server: viewServer, system: viewSystem };
  if (!force && tab === "routing" && routingDraft && $("#g-rules")) {
    // правку правил не трогаем, а раздел списков обновляем (счётчики, ошибки, новые списки)
    $("#lists-sec").innerHTML = listsSection();
    bindLists();
    return;
  }
  const keepSearch = $("#client-search") ? $("#client-search").value : null;
  $("#main").innerHTML = banners() + (views[tab] || viewOverview)();
  bind[tab] && bind[tab]();
  $$(".banner [data-goto]").forEach((b) => b.onclick = () => goTab(b.dataset.goto));
  if (keepSearch !== null && $("#client-search")) { $("#client-search").value = keepSearch; filterClients(); }
  $$("#tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === tab));
}

function banners() {
  let h = "";
  const code = (s) => `<span class="mono">${esc(s)}</span>`;
  if (updatingTo) h += `<div class="banner info"><b>${esc(t("sy.updating", { version: updatingTo }))}</b> <span id="upd-line" class="small">${esc(updLine || t("sy.updating_wait"))}</span></div>`;
  if (S.demo) h += `<div class="banner info"><b>${esc(t("banner.demo_title"))}</b> ${th("banner.demo", { flag: code("DRY_RUN=1") })}</div>`;
  if (!S.target) h += `<div class="banner bad"><b>${esc(t("banner.no_target_title"))}</b> ${esc(tm(S.target_error))}<br><span class="small">${th("banner.no_target_hint", { a: code("pid: host"), b: code("privileged: true") })}</span></div>`;
  else if (serverMissing() && tab !== "server") h += `<div class="banner info"><b>${esc(t("srv.missing"))}</b> <button class="btn sm" data-goto="server">${esc(t("srv.create_title"))}</button></div>`;
  if (S.engine.last_error) h += `<div class="banner bad"><b>${esc(t("banner.apply_error"))}</b> ${esc(tm(S.engine.last_error))}</div>`;
  return h;
}
const bind = {};

function stateBadge(u) {
  const h = u.health || {};
  if (!u.enabled) return `<span class="state"><span class="dot"></span>${esc(t("st.disabled"))}</span>`;
  if (quotaSwitched(u)) return `<span class="state"><span class="dot warn"></span>${esc(t("st.quota"))}</span>`;
  if (h.healthy) return `<span class="state"><span class="dot ok"></span>${esc(t("st.working"))}</span>`;
  if (h.state === "error") return `<span class="state"><span class="dot bad"></span>${esc(t("st.error"))}</span>`;
  if (h.state === "connecting") return `<span class="state"><span class="dot warn"></span>${esc(t("st.connecting"))}</span>`;
  return `<span class="state"><span class="dot bad"></span>${esc(t("st.no_link"))}</span>`;
}
function probeHtml(k) {
  const p = probes[k];
  if (!p) return "";
  if (p === "…") return `<span class="muted">${esc(t("probe.checking"))}</span>`;
  if (!p.ok) return `<span class="err">${esc(tm(p.error))}</span>`;
  const parts = [p.ip ? `<bdi>${esc(p.ip)}</bdi>` : esc(tm(p.warn) || "?")];
  if (p.cc) parts.push(esc(countryName(p.cc)));
  if (p.latency_ms != null) parts.push(esc(t("probe.ms", { n: p.latency_ms })));
  return parts.join(" · ");
}
async function runProbe(k, after) {
  probes[k] = "…"; after();
  try { probes[k] = await api("POST", "probe", { outbound: k }); }
  catch (e) { probes[k] = { ok: false, error: e.message }; }
  after();
}

/* ================================================================ обзор */
function viewOverview() {
  const counts = {}, assigned = {};
  for (const c of S.clients) {
    counts[c.effective] = (counts[c.effective] || 0) + 1;
    assigned[c.default] = (assigned[c.default] || 0) + 1;
  }
  const track = (cls, color, title, meta, side) => `
    <div class="track ${cls}" style="--c:${color}">
      <div class="track-body"><div class="track-title">${title}</div><div class="track-meta">${meta}</div></div>
      <div class="track-side">${side}</div>
    </div>`;
  const countHtml = (k) => {
    const n = counts[k] || 0;
    return `<div class="track-count">${esc(fmtNum(n))}<small>${esc(t("ov.by_default", { n }))}</small></div>`;
  };
  const probeSide = (k) => {
    const p = probes[k];
    const label = !p ? "btn.check" : p === "…" ? null : p.ok ? "btn.refresh" : "btn.again";
    return `<span class="probe-res">${probeHtml(k)}</span>` +
      (label ? ` <button class="btn sm ${p ? "ghost" : ""}" data-probe="${esc(k)}">${esc(t(label))}</button>` : "");
  };

  let lines = "";
  for (const u of S.upstreams) {
    const h = u.health || {};
    const dead = !u.enabled || !h.healthy || quotaSwitched(u);
    const na = assigned["up:" + u.id] || 0;
    const meta = [
      `<span><bdi>${esc(u.endpoint || "")}</bdi></span>`,
      h.healthy ? `<span>${esc(u.kind === "socks5" ? t("ov.socks_ms", { ms: h.latency_ms ?? "?" }) : t("ov.handshake", { ago: fmtAge(h.handshake_age) }))}</span>` : "",
      acctOn() ? `<span>${esc(t("ex.month"))} ${arrows(u.traffic)}</span>`
        : h.rx != null && u.enabled ? `<span>↓ ${esc(fmtBytes(h.rx))} ↑ ${esc(fmtBytes(h.tx))}</span>` : "",
      dead ? `<span>${esc(na ? t("ov.assigned_now", { n: na }) : t("ov.traffic_goes"))} ${effChip(u.effective)}</span>` : "",
    ].join("");
    lines += track(dead ? "dead" : "", lineVar(u), `<h3><bdi>${esc(u.name)}</bdi></h3>${stateBadge(u)}`, meta,
      countHtml(u.num) + (u.enabled ? probeSide("up:" + u.id) : ""));
  }
  lines += track("direct", "var(--direct)", `<h3>${esc(t("out.direct"))}</h3><span class="muted small">${esc(t("ov.direct_sub"))}</span>`,
    acctOn() ? `<span>${esc(t("ex.month"))} ${arrows(S.direct_traffic)}</span>` : "", countHtml("direct") + probeSide("direct"));
  if (counts.block) lines += track("dead", "var(--block)", `<h3>${esc(t("ov.blocked"))}</h3>`, "", countHtml("block"));

  const evs = [];
  for (const e of S.events) {
    const msg = tm(e.msg);
    const last = evs[evs.length - 1];
    if (last && last.msg === msg) last.n++; else evs.push({ ...e, msg, n: 1 });
  }
  const ev = evs.length
    ? `<ul class="events">${evs.slice(0, 12).map((e) => `<li><time>${esc(fmtTime(e.t))}</time><span class="${e.level}">${esc(e.msg)}${e.n > 1 ? ` <span class="muted">×${esc(fmtNum(e.n))}</span>` : ""}</span></li>`).join("")}</ul>`
    : `<p class="muted small">${esc(t("ov.log_empty"))}</p>`;

  return `
  <div class="ov-grid">
    <div class="section-head ov-head ov-h1"><div><h2>${esc(t("ov.title"))}</h2><p class="muted small">${esc(t("ov.subtitle"))}</p></div>
      <button class="btn" data-goto="exits">${esc(t("ov.add_exit"))}</button></div>
    <div class="section-head ov-head ov-h2"><div><h2>${esc(t("ov.policy"))}</h2><p class="muted small">${esc(t("ov.policy_sub"))}</p></div>
      <button class="btn" data-goto="routing">${esc(t("btn.edit"))}</button></div>
    <div class="map-lines ov-c1">${lines}</div>
    <div class="ov-c2">
      <div class="panel panel-pad">
        ${rulesSummary(S.routing.rules)}
        <div style="margin-top:10px">${th("ov.everything_else", { exit: effChip(S.global_effective, S.routing.default) })}</div>
      </div>
      <div class="section-head" style="margin-top:20px"><h2>${esc(t("ov.log"))}</h2></div>
      <div class="panel panel-pad ov-log">${ev}</div>
    </div>
  </div>`;
}
bind.overview = () => {
  $$("[data-goto]").forEach((b) => b.onclick = () => { tab = b.dataset.goto; history.replaceState(null, "", "#" + tab); render(); });
  $$("[data-probe]").forEach((b) => b.onclick = () => runProbe(b.dataset.probe, render));
};

/* ================================================================ клиенты */
function serverMissing() {
  return S.target && S.target.exists === false;
}
function viewClients() {
  const head = `
    <div class="section-head">
      <div><h2>${esc(t("cl.title"))}</h2><p class="muted small">${esc(t("cl.subtitle"))}</p></div>
      <div class="add-row">
        ${S.clients.length ? `<input type="search" id="client-search" placeholder="${esc(t("cl.search"))}" style="max-width:240px">
          <select id="client-sort" aria-label="${esc(t("cl.sort"))}" style="width:auto">${CLIENT_SORTS.map((k) =>
            `<option value="${k}" ${k === clientSort ? "selected" : ""}>${esc(t("cl.sort_" + k))}</option>`).join("")}</select>` : ""}
        <button class="btn primary" id="add-client" ${serverMissing() || !S.target ? "disabled" : ""}>${esc(t("cl.add"))}</button>
      </div>
    </div>`;
  if (serverMissing()) return `<section class="section">${head}<div class="panel empty"><p>${esc(t("srv.missing"))}</p><button class="btn primary" data-goto="server">${esc(t("srv.create_title"))}</button></div></section>`;
  if (!S.clients.length) return `<section class="section">${head}<div class="panel empty"><p>${esc(t("cl.empty"))}</p><p class="small">${esc(t("cl.empty_hint2"))}</p></div></section>`;
  const rows = sortedClients().map((c) => {
    const live = c.live || {};
    const age = live.handshake ? S.now - live.handshake : null;
    const online = c.enabled && age != null && age < 180;
    const p = c.policy;
    const tags = (!c.enabled ? `<span class="tag tag-off">${esc(t("cl.disabled_tag"))}</span>` : "") +
      (p.rules_mode === "custom" ? `<span class="tag">${esc(t("cl.custom_tag"))}</span>` : "") +
      (p.note ? `<span class="tag"><bdi>${esc(p.note)}</bdi></span>` : "") +
      (c.cps ? `<span class="tag" title="${esc(t("cl.cps"))}">${esc(cpsTag(c.cps))}</span>` : "") + limitTags(c);
    const wanted = p.outbound !== "inherit" ? p.outbound : S.routing.default;
    const activity = !c.enabled ? `<span class="muted">—</span>`
      : `<span class="state"><span class="dot ${online ? "ok" : ""}"></span>${esc(online ? t("cl.online") : fmtAge(age))}</span>`;
    return `<tr class="click ${c.enabled ? "" : "row-off"}" ${endingSoon(c) ? 'data-soon="1"' : ""} data-pk="${esc(c.public_key)}" data-q="${esc((c.name + " " + c.ip + " " + p.note).toLowerCase())}">
      <td><span class="client-name"><bdi>${esc(c.name || t("cl.unnamed"))}</bdi></span>${tags}</td>
      <td data-m="sub" class="nowrap"><bdi>${esc(c.ip || "—")}</bdi></td>
      <td data-m="sub">${activity}</td>
      <td data-m="month" class="nowrap muted"><span class="m-label">${esc(t("ex.month"))}: </span>${trafficCell(c)}</td>
      <td data-m="right">${effChip(c.effective, wanted)}${p.outbound === "inherit" ? "" : `<div class="small muted" style="margin-top:3px">${esc(t("cl.manual"))}</div>`}</td>
    </tr>`;
  }).join("");
  const nSoon = S.clients.filter(endingSoon).length;
  if (!nSoon) clientSoon = false;
  const soon = nSoon ? `<div class="soon-bar"><button type="button" class="btn sm" id="client-soon" aria-pressed="${clientSoon}">⏳ ${esc(t("cl.soon", { n: nSoon }))}</button></div>` : "";
  return `
  <section class="section">${head}${soon}
    <div class="panel"><table class="table responsive">
      <thead><tr><th>${esc(t("cl.col_name"))}</th><th>${esc(t("cl.col_ip"))}</th><th>${esc(t("cl.col_activity"))}</th><th>${esc(t("cl.col_month"))}</th><th>${esc(t("cl.col_exit"))}</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </section>`;
}
const CLIENT_SORTS = ["ip", "name", "traffic", "activity"];
let clientSort = (() => { try { return localStorage.getItem("awgr.sort") || "ip"; } catch { return "ip"; } })();
function monthBytes(c) { const x = c.traffic || {}; return (x.month_rx || 0) + (x.month_tx || 0); }
function totalBytes(c) { const x = c.traffic || {}; return (x.total_rx || 0) + (x.total_tx || 0); }
function sortedClients() {
  const list = [...S.clients];
  const hs = (c) => (c.enabled && c.live && c.live.handshake) || 0;
  if (clientSort === "name") list.sort((a, b) => (a.name || "").localeCompare(b.name || "", LANG));
  else if (clientSort === "traffic") list.sort((a, b) => monthBytes(b) - monthBytes(a));
  else if (clientSort === "activity") list.sort((a, b) => hs(b) - hs(a));
  return list;
}
function isoDay(ts) {
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}
function fmtDay(ts) { return new Date(ts * 1000).toLocaleDateString(LANG, { day: "numeric", month: "short", year: "numeric" }); }
function limitTags(c) {
  const L = c.limits || {};
  let h = "";
  if (L.auto_off === "exp") h += `<span class="tag tag-off">${esc(t("cl.tag_expired"))}</span>`;
  else if ((L.auto_off || "").startsWith("quota:")) h += `<span class="tag tag-off">${esc(t("cl.tag_quota"))}</span>`;
  else if (L.expires && L.expires <= S.now) h += `<span class="tag tag-warn">${esc(t("cl.tag_expired"))}</span>`;
  else if (L.expires) h += `<span class="tag ${L.expires - S.now < 3 * 86400 ? "tag-warn" : ""}">${esc(t("cl.tag_until", { date: fmtDay(L.expires) }))}</span>`;
  return h;
}
function trafficCell(c) {
  const L = c.limits || {};
  const used = L.period === "total" ? totalBytes(c) : monthBytes(c);
  if (!L.quota) return esc(fmtBytes(monthBytes(c)));
  const pct = Math.min(100, Math.round(used / L.quota * 100));
  return `${esc(t("share.of", { used: fmtBytes(used), limit: fmtBytes(L.quota) }))}
    <div class="meter ${pct >= 90 ? "hot" : ""}" title="${esc(t(L.period === "total" ? "cl.quota_total" : "cl.quota_month"))}"><span style="width:${pct}%"></span></div>`;
}
/* трафик по выходам: месячные итоги, квоты выходов */
function acctOn() { return !!(S.acct && S.acct.state === "ok"); }
function arrowsText(x, period = "month") {
  x = x || {};
  return `↓ ${fmtBytes(x[period + "_tx"])} ↑ ${fmtBytes(x[period + "_rx"])}`;
}
function arrows(x, period = "month") {
  x = x || {};
  return `↓ ${esc(fmtBytes(x[period + "_tx"]))} ↑ ${esc(fmtBytes(x[period + "_rx"]))}`;
}
function quotaSwitched(u) { return !!(u.enabled && u.over_quota && u.quota_action !== "notify"); }
// варианты «Когда лимит исчерпан»: уведомить, блокировать, напрямую, другие выходы (не сам)
function quotaOptions(u) {
  const sel = u ? u.quota_action : "notify";
  const opts = [["notify", t("ex.qa_notify")], ["block", t("out.block")], ["direct", t("out.direct")]];
  for (const x of S.upstreams) if (!u || x.id !== u.id) opts.push(["up:" + x.id, t("out.via", { name: x.name })]);
  return opts.map(([v, l]) => `<option value="${esc(v)}" ${v === sel ? "selected" : ""}>${esc(l)}</option>`).join("");
}
function exitQuota(u) {
  const x = u.traffic || {}, used = (x.month_rx || 0) + (x.month_tx || 0);
  const pct = Math.min(100, Math.round(used / u.quota * 100));
  return `${esc(t("share.of", { used: fmtBytes(used), limit: fmtBytes(u.quota) }))}
    <div class="meter ${pct >= 90 ? "hot" : ""}"><span style="width:${pct}%"></span></div>`;
}
/** разбивка трафика клиента за месяц по выходам */
function byExitHtml(c) {
  const bo = (c.traffic || {}).by_out || {};
  const keys = ["direct", ...S.upstreams.map((u) => u.id)].filter((k) => bo[k]);
  if (!keys.length) return "";
  const rows = keys.map((k) => {
    const name = k === "direct" ? esc(t("out.direct")) : `<bdi>${esc(upstreamById(k).name)}</bdi>`;
    return `<div><span>${name}</span><b>↓ ${esc(fmtBytes(bo[k][1]))} ↑ ${esc(fmtBytes(bo[k][0]))}</b></div>`;
  }).join("");
  return `<p class="small muted" style="margin:0 0 6px">${esc(t("cl.by_exit"))}</p><div class="kv" style="margin-bottom:16px">${rows}</div>`;
}
function filterClients() {
  const q = ($("#client-search").value || "").toLowerCase().trim();
  $$("tr[data-q]").forEach((tr) => tr.hidden = !!(q && !tr.dataset.q.includes(q)) || (clientSoon && !tr.dataset.soon));
}
/** срок кончается через 3 дня или меньше, или израсходовано 90 % лимита (как предупреждения в Telegram) */
let clientSoon = false;
function endingSoon(c) {
  const L = c.limits || {};
  if (!c.enabled) return false;
  if (L.expires && L.expires > S.now && L.expires - S.now <= 3 * 86400) return true;
  if (!L.quota) return false;
  const used = L.period === "total" ? totalBytes(c) : monthBytes(c);
  return used >= L.quota * 0.9 && used < L.quota;
}
bind.clients = () => {
  const s = $("#client-search");
  if (s) s.oninput = filterClients;
  const soon = $("#client-soon");
  if (soon) soon.onclick = () => { clientSoon = !clientSoon; soon.setAttribute("aria-pressed", clientSoon); filterClients(); };
  if (clientSoon && s) filterClients();
  const so = $("#client-sort");
  if (so) so.onchange = () => {
    clientSort = so.value;
    try { localStorage.setItem("awgr.sort", clientSort); } catch { /* нет хранилища */ }
    render();
  };
  const add = $("#add-client");
  if (add) add.onclick = addClient;
  $$("[data-goto]").forEach((b) => b.onclick = () => goTab(b.dataset.goto));
  $$("tr[data-pk]").forEach((tr) => tr.onclick = () => editClient(tr.dataset.pk));
};

function goTab(name) {
  tab = name; history.replaceState(null, "", "#" + tab); render(); window.scrollTo(0, 0);
}

function addClient() {
  openModal(t("cl.add_title"), `
    <label class="field"><span>${esc(t("cl.name"))}</span>
      <input type="text" id="n-name" maxlength="60" placeholder="${esc(t("cl.name_ph"))}" autofocus>
      <span class="hint">${esc(t("cl.add_hint"))}</span>
    </label>`,
  `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="n-save">${esc(t("cl.create"))}</button>`);
  const go = async () => {
    const name = $("#n-name").value.trim();
    if (!name) { $("#n-name").focus(); return; }
    $("#n-save").disabled = true;
    try {
      const r = await api("POST", "users", { name });
      await refresh();
      toast(t("toast.client_added", { name }));
      editClient(r.public_key, "connect");
    } catch (e) { toast(e.message, true); $("#n-save").disabled = false; }
  };
  $("#n-save").onclick = go;
  $("#n-name").onkeydown = (e) => { if (e.key === "Enter") go(); };
}

/** Растровая картинка, где каждый модуль — целое число физических пикселей (не меньше 3):
 *  SVG с дробным или даже целым размером сканер AmneziaWG на Android читает плохо или не читает.
 *  Размер подбирается после вёрстки по ширине .connect: сначала сам код (до QR_TARGET_CSS_PX),
 *  потом белое поле из оставшегося места — поле никогда не уменьшает код.
 *  На тёмном фоне камера пересвечивает тонкое белое поле, и сканер теряет «тихую зону», поэтому
 *  в тёмной теме тихая зона внутри картинки шире (QR_QUIET_MODULES_DARK, растёт вместе с кодом),
 *  а рамка .qr-box добирает до QR_DARK_PAD_CSS_PX, если хватает места. */
const QR_TARGET_CSS_PX = 300, QR_MIN_MODULE_PX = 3, QR_QUIET_MODULES = 4, QR_QUIET_MODULES_DARK = 6,
  QR_DARK_PAD_CSS_PX = 64;
const qrCodes = new WeakMap();
const qrDark = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
let qrSeq = 0, qrLayoutWidth = 0;
function qrImage(text) {
  qrcode.stringToBytes = qrcode.stringToBytesFuncs["UTF-8"];
  let qr = null;
  for (const lvl of ["M", "L"]) {
    try { qr = qrcode(0, lvl); qr.addData(text, "Byte"); qr.make(); break; } catch { qr = null; }
  }
  if (!qr) return `<p class="muted small">${esc(t("cl.qr_too_big"))}</p>`;
  const id = `qr-${++qrSeq}`;
  requestAnimationFrame(() => {
    const img = document.getElementById(id);
    if (img) { qrCodes.set(img, qr); drawQr(img); }
  });
  return `<img class="qr" id="${id}" alt="QR">`;
}
function drawQr(img) {
  const qr = qrCodes.get(img), box = img.parentElement;
  const dark = !!(qrDark && qrDark.matches);
  const n = qr.getModuleCount(), m = dark ? QR_QUIET_MODULES_DARK : QR_QUIET_MODULES, size = n + 2 * m;
  const dpr = window.devicePixelRatio || 1;
  box.style.padding = "";
  const style = getComputedStyle(box);
  const pad = parseFloat(style.paddingLeft), border = 2 * parseFloat(style.borderLeftWidth);
  const room = box.parentElement.clientWidth - border;
  const fitPx = Math.floor(Math.min(QR_TARGET_CSS_PX, room - 2 * pad) * dpr / size);
  const modulePx = Math.max(QR_MIN_MODULE_PX, fitPx);
  const cssPx = size * modulePx / dpr;
  if (dark) box.style.padding = `${Math.max(pad, Math.min(QR_DARK_PAD_CSS_PX, Math.floor((room - cssPx) / 2)))}px`;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = size * modulePx;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#000";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) ctx.fillRect((c + m) * modulePx, (r + m) * modulePx, modulePx, modulePx);
  img.src = canvas.toDataURL("image/png");
  img.style.width = `${cssPx}px`;
}
function redrawQrs() {
  document.querySelectorAll("img.qr").forEach((img) => { if (qrCodes.has(img)) drawQr(img); });
}
window.addEventListener("resize", () => {
  const w = document.documentElement.clientWidth;
  if (w === qrLayoutWidth) return;
  qrLayoutWidth = w;
  redrawQrs();
});
if (qrDark && qrDark.addEventListener) qrDark.addEventListener("change", redrawQrs);

// application/octet-stream: с text/plain Chrome на Android дописывает к имени «.txt»,
// и приложение AmneziaVPN не принимает файл «client.conf.txt»
function download(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/octet-stream" }));
  a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); }
  catch {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.append(ta); ta.select();
    document.execCommand("copy"); ta.remove();
  }
  toast(t("toast.copied"));
}

function editClient(pk, section = null) {
  const c = S.clients.find((x) => x.public_key === pk);
  if (!c) return;
  const draft = { outbound: c.policy.outbound, rules_mode: c.policy.rules_mode, note: c.policy.note,
    rules: structuredClone(c.policy.rules_mode === "custom" ? c.policy.rules : S.routing.rules) };
  let view = section || (c.has_config ? "connect" : "route");
  const L = c.limits || {}, tr = c.traffic || {};
  openModal(c.name || c.ip, `
    <p class="muted small" style="margin-top:0"><bdi>${esc(c.ip || "")}</bdi> · ${esc(t("cl.key"))} <span class="mono">${esc(pk.slice(0, 10))}…</span>${c.enabled ? "" : ` · <span class="err">${esc(t("cl.disabled_tag"))}</span>`}</p>
    <div class="seg seg-wide" id="c-view">
      <button type="button" data-v="connect">${esc(t("cl.v_connect"))}</button>
      <button type="button" data-v="route">${esc(t("cl.v_route"))}</button>
      <button type="button" data-v="manage">${esc(t("cl.v_manage"))}</button>
    </div>
    <div id="c-pane-connect" class="c-pane"><div id="c-cps-box"></div><div id="c-conn"></div></div>
    <div id="c-pane-route" class="c-pane">
      <label class="field"><span>${esc(t("cl.default_exit"))}</span>
        <select id="c-out">${outOptions(draft.outbound, { inherit: t("out.inherit_now", { exit: exitName(S.routing.default) }) })}</select>
        <span class="hint">${esc(t("cl.default_exit_hint"))}</span>
      </label>
      <div class="field"><span>${esc(t("cl.rules"))}</span>
        <div class="seg" id="c-mode"><button type="button" data-v="inherit">${esc(t("cl.rules_global"))}</button><button type="button" data-v="custom">${esc(t("cl.rules_own"))}</button></div>
      </div>
      <div id="c-rules"></div>
      <label class="field" style="margin-top:14px"><span>${esc(t("cl.note"))}</span><input type="text" id="c-note" maxlength="120" value="${esc(draft.note)}" placeholder="${esc(t("cl.note_ph"))}"></label>
    </div>
    <div id="c-pane-manage" class="c-pane">
      <label class="field"><span>${esc(t("cl.name"))}</span><input type="text" id="c-name" maxlength="60" value="${esc(c.name)}"></label>
      <div class="kv" style="margin-bottom:16px">
        <div><span>${esc(t("cl.this_month"))}</span><b>↓ ${esc(fmtBytes(tr.month_tx))} ↑ ${esc(fmtBytes(tr.month_rx))}</b></div>
        <div><span>${esc(t("cl.all_time"))}</span><b>↓ ${esc(fmtBytes(tr.total_tx))} ↑ ${esc(fmtBytes(tr.total_rx))}</b></div>
      </div>
      ${byExitHtml(c)}
      <div class="row2">
        <label class="field"><span>${esc(t("cl.expires"))}</span>
          <input type="date" id="c-exp" value="${esc(L.expires ? isoDay(L.expires) : "")}">
          <span class="hint">${esc(t("cl.expires_hint"))}</span></label>
        <div class="field"><span>${esc(t("cl.quota"))}</span>
          <div class="input-btn"><input type="number" id="c-quota" min="0" step="any" inputmode="decimal" placeholder="${esc(t("cl.no_limit"))}" value="${L.quota ? +(L.quota / 1024 ** 3).toFixed(3) : ""}">
            <select id="c-period" style="width:auto"><option value="month" ${L.period !== "total" ? "selected" : ""}>${esc(t("cl.per_month"))}</option><option value="total" ${L.period === "total" ? "selected" : ""}>${esc(t("cl.in_total"))}</option></select></div>
          <span class="hint">${esc(t("cl.quota_hint", { time: monthResetLocal() }))}</span></div>
      </div>
      <div class="manage-row">
        <div style="min-width:0"><b>${esc(t("cl.share"))}</b><div class="small muted">${esc(t(S.panel && S.panel.access === "ssh" ? "cl.share_ssh" : "cl.share_hint"))}</div>
          ${c.share_url ? `<div class="mono small share-url" dir="ltr">${esc(c.share_url)}</div>` : ""}</div>
        <div class="actions" style="flex:none">${c.share_url
          ? `<button class="btn sm" id="c-share-copy">${esc(t("btn.copy"))}</button><button class="btn sm danger" id="c-share-del">${esc(t("cl.share_revoke"))}</button>`
          : `<button class="btn sm" id="c-share-new" ${S.panel && S.panel.access === "ssh" ? "disabled" : ""}>${esc(t("cl.share_create"))}</button>`}</div>
      </div>
      <div class="manage-row">
        <div><b>${esc(t(c.enabled ? "cl.disable" : "cl.enable"))}</b><div class="small muted">${esc(t(c.enabled ? "cl.disable_hint" : "cl.enable_hint"))}</div></div>
        <button class="btn sm" id="c-toggle">${esc(t(c.enabled ? "cl.disable_btn" : "cl.enable_btn"))}</button>
      </div>
      <div class="manage-row">
        <div><b>${esc(t("cl.delete"))}</b><div class="small muted">${esc(t("cl.delete_hint"))}</div></div>
        <button class="btn sm danger" id="c-delete">${esc(t("btn.delete"))}</button>
      </div>
    </div>
  `, `<button class="btn" data-close>${esc(t("btn.close"))}</button><button class="btn primary" id="c-save">${esc(t("btn.save"))}</button>`);

  const loadCps = async () => {
    const box = $("#c-cps-box");
    let info;
    try { info = await api("GET", "cps"); } catch { return; }
    const cur = c.cps ? c.cps.preset : "server";
    const srvName = cpsName(info.server_match);
    box.innerHTML = `
      <label class="field"><span>${esc(t("cl.cps"))}</span>
        <select id="c-cps"><option value="server" ${cur === "server" ? "selected" : ""}>${esc(t("cl.cps_server", { name: srvName }))}</option>
          ${info.presets.map((p) => `<option value="${p.id}" ${cur === p.id ? "selected" : ""}>${esc(cpsName(p.id))}</option>`).join("")}
          <option value="custom" ${cur === "custom" ? "selected" : ""}>${esc(t("cps.custom"))}</option></select>
        <span class="hint">${esc(t("cl.cps_hint"))}</span></label>
      <div id="c-cps-custom" hidden></div>`;
    const sel = $("#c-cps"), custom = $("#c-cps-custom");
    const save = async (body) => {
      sel.disabled = true;
      try {
        const r = await api("PUT", "cps/" + encodeURIComponent(pk), body);
        c.cps = r.cps; toast(t("cl.cps_saved")); loadConnect(); refresh();
      } catch (e) { if (!(e instanceof AuthError)) toast(e.message, true); }
      sel.disabled = false;
    };
    const showCustom = () => {
      const start = c.cps && c.cps.preset === "custom" ? c.cps.values
        : c.cps ? (info.presets.find((p) => p.id === c.cps.preset) || {}).values || {} : info.server;
      custom.hidden = false;
      custom.innerHTML = cpsFields("cc", start) + `<div class="actions" style="margin:-4px 0 14px"><button class="btn sm primary" id="c-cps-apply">${esc(t("cl.cps_apply"))}</button></div>`;
      bindCpsSizes("cc");
      $("#c-cps-apply").onclick = () => {
        const values = {};
        CPS_KEYS.forEach((k) => { values[k] = $("#cc-" + k).value.trim(); });
        save({ preset: "custom", values });
      };
    };
    if (cur === "custom") showCustom();
    sel.onchange = () => {
      if (sel.value === "custom") { showCustom(); return; }
      custom.hidden = true;
      save({ preset: sel.value });
    };
  };
  const loadConnect = async () => {
    const box = $("#c-conn");
    if (!c.has_config) {
      box.innerHTML = `<div class="notice">${esc(t("cl.no_config"))}</div>`;
      return;
    }
    box.innerHTML = `<p class="muted">${esc(t("probe.checking"))}</p>`;
    try {
      const cfg = await api("GET", `users/${encodeURIComponent(pk)}/config`);
      box.innerHTML = `
        ${cfg.warn_host ? `<div class="notice warn">${esc(t("cl.warn_host"))}</div>` : ""}
        <div class="connect">
          <div class="qr-box">${qrImage(cfg.conf)}</div>
          <div class="connect-actions">
            <p class="small muted" style="margin-top:0">${esc(t("cl.qr_hint"))}</p>
            <button class="btn" id="c-dl">${esc(t("cl.download"))}</button>
            <button class="btn" id="c-link">${esc(t("cl.copy_link"))}</button>
            <button class="btn ghost" id="c-copy">${esc(t("cl.copy_conf"))}</button>
            <details class="small"><summary>${esc(t("cl.show_conf"))}</summary><pre class="code" dir="ltr">${esc(cfg.conf)}</pre></details>
          </div>
        </div>`;
      $("#c-dl").onclick = () => download(cfg.filename, cfg.conf);
      $("#c-link").onclick = () => copyText(cfg.link);
      $("#c-copy").onclick = () => copyText(cfg.conf);
    } catch (e) { box.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  };
  const showView = () => {
    $$("#c-view button").forEach((b) => b.setAttribute("aria-pressed", b.dataset.v === view));
    $$(".c-pane").forEach((el) => el.hidden = el.id !== "c-pane-" + view);
    $("#c-save").hidden = view === "connect";
    if (view === "connect" && !$("#c-pane-connect").dataset.loaded) {
      $("#c-pane-connect").dataset.loaded = 1;
      if (c.has_config) loadCps();
      loadConnect();
    }
  };
  $$("#c-view button").forEach((b) => b.onclick = () => { view = b.dataset.v; showView(); });

  const drawMode = () => {
    $$("#c-mode button").forEach((b) => b.setAttribute("aria-pressed", b.dataset.v === draft.rules_mode));
    const box = $("#c-rules");
    if (draft.rules_mode === "inherit") {
      box.innerHTML = S.routing.rules.some((r) => r.enabled) ? rulesSummary(S.routing.rules)
        : `<p class="muted small">${esc(t("cl.no_global"))}</p>`;
    } else {
      rulesEditor(box, draft.rules, () => {});
    }
  };
  $$("#c-mode button").forEach((b) => b.onclick = () => { draft.rules_mode = b.dataset.v; drawMode(); });
  drawMode();
  showView();

  $("#c-save").onclick = async () => {
    try {
      const name = $("#c-name").value.trim();
      if (name && name !== c.name) await api("PUT", "users/" + encodeURIComponent(pk), { name });
      const exp = $("#c-exp").value ? Math.floor(new Date($("#c-exp").value + "T23:59:59").getTime() / 1000) : null;
      const q = $("#c-quota").value.trim();
      const per = $("#c-period").value;
      const oldQ = L.quota ? String(+(L.quota / 1024 ** 3).toFixed(3)) : "";
      if (exp !== (L.expires || null) || q !== oldQ || per !== (L.period || "month")) {
        const r = await api("PUT", "limits/" + encodeURIComponent(pk), { expires: exp, quota_gb: q === "" ? null : +q, period: per });
        if (r.enabled) toast(t("toast.client_enabled"));
      }
      await api("PUT", "clients/" + encodeURIComponent(pk), {
        outbound: $("#c-out").value, rules_mode: draft.rules_mode,
        rules: draft.rules_mode === "custom" ? draft.rules : [], note: $("#c-note").value.trim() });
      closeModal(); toast(t("toast.saved_applying")); refresh();
    } catch (e) { toast(e.message, true); }
  };
  const reopen = async () => { await refresh(); editClient(pk, "manage"); };
  const shareNew = $("#c-share-new");
  if (shareNew) shareNew.onclick = async () => {
    try { const r = await api("POST", "shares/" + encodeURIComponent(pk)); await copyText(r.url); await reopen(); }
    catch (e) { toast(e.message, true); }
  };
  const shareCopy = $("#c-share-copy");
  if (shareCopy) shareCopy.onclick = () => copyText(c.share_url);
  const shareDel = $("#c-share-del");
  if (shareDel) shareDel.onclick = async () => {
    if (!confirm(t("cl.share_revoke_confirm"))) return;
    try { await api("DELETE", "shares/" + encodeURIComponent(pk)); toast(t("cl.share_revoked")); await reopen(); }
    catch (e) { toast(e.message, true); }
  };
  $("#c-toggle").onclick = async () => {
    try {
      await api("PUT", "users/" + encodeURIComponent(pk), { enabled: !c.enabled });
      closeModal(); toast(t(c.enabled ? "toast.client_disabled" : "toast.client_enabled")); refresh();
    } catch (e) { toast(e.message, true); }
  };
  $("#c-delete").onclick = async () => {
    if (!confirm(t("cl.delete_confirm", { name: c.name || c.ip }))) return;
    try {
      await api("DELETE", "users/" + encodeURIComponent(pk));
      closeModal(); toast(t("toast.client_deleted")); refresh();
    } catch (e) { toast(e.message, true); }
  };
}

/* ================================================================ редактор правил */
const LIST_KINDS = ["country", "asn", "url", "manual", "domains"];
/** список в правило; первый список доменов — выход первый SOCKS5, если выбран не он */
function addListTo(r, id) {
  if (r.lists.includes(id)) return;
  r.lists.push(id);
  if (isDomainList(id) && !socksExits().some((u) => "up:" + u.id === r.outbound) && socksExits().length) r.outbound = "up:" + socksExits()[0].id;
}
const isDomainList = (id) => (listObj(id) || {}).kind === "domains";
const socksExits = () => S.upstreams.filter((u) => u.kind === "socks5");
function rulesEditor(box, rules, onChange, { create = null } = {}) {
  const draw = () => {
    const items = rules.map((r, i) => {
      // списки доменов — отдельные правила и только на выход SOCKS5 (имя сайта передаётся прокси)
      const dom = r.lists.some(isDomainList);
      const addable = S.lists.filter((l) => !r.lists.includes(l.id) && (!r.lists.length || (l.kind === "domains") === dom));
      const kinds = LIST_KINDS.filter((k) => !r.lists.length || (k === "domains") === dom);
      return `
      <div class="rule ${r.enabled ? "" : "off"}" data-i="${i}">
        <div class="rule-n">${esc(fmtNum(i + 1))}</div>
        <div>
          <div class="rule-lists">
            ${r.lists.map((l) => `<span class="chip"><bdi>${esc(listName(l))}</bdi><button type="button" data-rm-list="${esc(l)}" aria-label="${esc(t("re.remove_list"))}">×</button></span>`).join("")}
            <select class="add-list" data-add-list aria-label="${esc(t("re.add_list"))}"><option value="">${esc(t("re.add_list"))}</option>${addable.map((l) => `<option value="${esc(l.id)}">${esc(listName(l.id))}</option>`).join("")}${create ? `<optgroup label="${esc(t("re.new_list"))}">${kinds.map((k) => `<option value="new:${k}">＋ ${esc(t("ls.new." + k))}</option>`).join("")}</optgroup>` : ""}</select>
          </div>
          <input type="text" class="rule-comment" data-comment value="${esc(r.comment || "")}" placeholder="${esc(t("re.comment_ph"))}" maxlength="80">
          ${dom ? `<div class="small muted" style="margin-top:4px">${esc(t(socksExits().length ? "re.domain_hint" : "re.domain_no_socks"))}</div>` : ""}
        </div>
        <div class="rule-then"><label>${esc(t(dom ? "re.then_sites" : "re.then"))}</label><select data-out>${outOptions(r.outbound, { socksOnly: dom })}</select></div>
        <div class="rule-ctl">
          <label class="switch" title="${esc(t("re.enabled"))}"><input type="checkbox" data-en ${r.enabled ? "checked" : ""} aria-label="${esc(t("re.enabled"))}"><span></span></label>
          <button class="icon-btn" type="button" data-up ${i === 0 ? "disabled" : ""} aria-label="${esc(t("re.up"))}">↑</button>
          <button class="icon-btn" type="button" data-down ${i === rules.length - 1 ? "disabled" : ""} aria-label="${esc(t("re.down"))}">↓</button>
          <button class="icon-btn" type="button" data-del aria-label="${esc(t("re.delete"))}">✕</button>
        </div>
      </div>`;
    }).join("");
    box.innerHTML = `<div class="rules">${items || `<p class="muted small" style="margin:0 0 4px">${esc(t("re.none"))}</p>`}</div>
      <button class="btn sm" type="button" data-add style="margin-top:8px">${esc(t("re.add"))}</button>`;
    $$(".rule", box).forEach((el) => {
      const i = +el.dataset.i, r = rules[i];
      const ch = () => { onChange(); draw(); };
      $$("[data-rm-list]", el).forEach((b) => b.onclick = () => { r.lists = r.lists.filter((x) => x !== b.dataset.rmList); ch(); });
      $("[data-add-list]", el).onchange = (e) => {
        const v = e.target.value;
        if (!v) return;
        if (v.startsWith("new:")) { e.target.value = ""; create(v.slice(4), (id) => addListTo(r, id)); return; }
        addListTo(r, v);
        ch();
      };
      $("[data-comment]", el).oninput = (e) => { r.comment = e.target.value; onChange(); };
      $("[data-out]", el).onchange = (e) => { r.outbound = e.target.value; onChange(); };
      $("[data-en]", el).onchange = (e) => { r.enabled = e.target.checked; ch(); };
      $("[data-up]", el).onclick = () => { [rules[i - 1], rules[i]] = [rules[i], rules[i - 1]]; ch(); };
      $("[data-down]", el).onclick = () => { [rules[i + 1], rules[i]] = [rules[i], rules[i + 1]]; ch(); };
      $("[data-del]", el).onclick = () => { rules.splice(i, 1); ch(); };
    });
    $("[data-add]", box).onclick = () => {
      rules.push({ lists: [], outbound: "direct", enabled: true, comment: "" });
      onChange(); draw();
    };
  };
  draw();
}

/* ================================================================ правила */
function routingDirty() {
  if (!routingDraft) return false;
  return JSON.stringify(routingDraft) !== JSON.stringify({ default: S.routing.default, rules: S.routing.rules });
}
function viewRouting() {
  return `
  <section class="section">
    <div class="section-head"><div><h2>${esc(t("rt.title"))}</h2><p class="muted small">${esc(t("rt.subtitle"))}</p></div></div>
    <div id="g-rules"></div>
    <div class="default-row" style="margin-top:8px">
      <div class="rule-n" style="padding:0">∗</div>
      <div><b>${esc(t("rt.else"))}</b><div class="small muted">${esc(t("rt.else_sub"))}</div></div>
      <select id="g-default">${outOptions((routingDraft || S.routing).default)}</select>
      <div></div>
    </div>
    <div class="savebar" id="savebar" hidden><span>${esc(t("rt.unsaved"))}</span>
      <span class="actions"><button class="btn sm" id="g-reset">${esc(t("btn.discard"))}</button><button class="btn sm primary" id="g-save">${esc(t("rt.save"))}</button></span></div>
  </section>
  <section class="section" id="lists-sec">${listsSection()}</section>
  <section class="section">
    <div class="section-head"><div><h2>${esc(t("tr.title"))}</h2><p class="muted small">${esc(t("tr.subtitle"))}</p></div></div>
    <div class="panel panel-pad">
      <form class="trace-form" id="trace-form">
        <label class="field"><span>${esc(t("tr.client"))}</span><select id="t-client"><option value="">${esc(t("tr.any"))}</option>${S.clients.map((c) => `<option value="${esc(c.public_key)}">${esc(c.name || c.ip)} — ${esc(c.ip || "")}</option>`).join("")}</select></label>
        <label class="field"><span>${esc(t("tr.address"))}</span><input type="text" id="t-ip" dir="ltr" placeholder="${esc(t("tr.address_ph"))}" required></label>
        <button class="btn primary" type="submit">${esc(t("btn.check"))}</button>
      </form>
      <div id="trace-out" class="trace-out"></div>
    </div>
  </section>`;
}
bind.routing = () => {
  const draft = routingDraft || { default: S.routing.default, rules: structuredClone(S.routing.rules) };
  const upd = () => { routingDraft = draft; $("#savebar").hidden = !routingDirty(); };
  // новый список из правила: после сохранения он сразу в этом правиле (правка не теряется)
  rulesEditor($("#g-rules"), draft.rules, upd, { create: (kind, put) => editList(null, kind, (id) => { put(id); routingDraft = draft; render(true); }) });
  upd();
  bindLists();
  if (scrollToLists) { scrollToLists = false; $("#lists-sec").scrollIntoView(); }
  $("#g-default").onchange = (e) => { draft.default = e.target.value; upd(); };
  $("#g-reset").onclick = () => { routingDraft = null; render(); };
  $("#g-save").onclick = async () => {
    try {
      await api("PUT", "routing", draft);
      routingDraft = null; toast(t("toast.rules_saved")); await refresh();
    } catch (e) { toast(e.message, true); }
  };
  $("#trace-form").onsubmit = async (e) => {
    e.preventDefault();
    const out = $("#trace-out");
    out.innerHTML = `<span class="muted">${esc(t("probe.checking"))}</span>`;
    try {
      const r = await api("POST", "trace", { client: $("#t-client").value, ip: $("#t-ip").value.trim() });
      out.innerHTML = `<div>${th("tr.result", { exit: effChip(r.effective, r.result) })}</div>
        <ol>${r.steps.map((s) => `<li>${esc(tm(s))}</li>`).join("")}</ol>`;
    } catch (err) { out.innerHTML = `<p class="err">${esc(err.message)}</p>`; }
  };
};

/* ================================================================ выходы */
function viewExits() {
  const cards = S.upstreams.map((u) => {
    const h = u.health || {};
    let st = stateBadge(u);
    if (u.enabled && h.healthy && !quotaSwitched(u)) st = `<span class="state"><span class="dot ok"></span>${esc(u.kind === "socks5" ? t("ex.working_socks", { ms: h.latency_ms ?? "?" }) : t("ex.working", { ago: fmtAge(h.handshake_age) }))}</span>`;
    else if (u.enabled && u.kind === "socks5" && h.error && h.state !== "error") st += ` <span class="small warn-text">${esc(tm(h.error))}</span>`;
    else if (u.enabled && h.state === "error") st = `<span class="state"><span class="dot bad"></span>${esc(tm(h.error) || t("st.error"))}</span>`;
    else if (u.enabled && h.handshake_age) st += ` <span class="muted small">${esc(t("ex.last_handshake", { ago: fmtAge(h.handshake_age) }))}</span>`;
    const ver = u.kind === "socks5" ? "SOCKS5" : u.version ? `AWG ${u.version}` : u.config_error ? "" : "WireGuard";
    return `
    <div class="panel exit ${u.enabled ? "" : "disabled-exit"}" style="--c:${lineVar(u)}">
      <div class="exit-bar"></div>
      <div class="exit-main">
        <div class="exit-head">
          <h3><bdi>${esc(u.name)}</bdi> <span class="tag">${esc(u.iface)}</span>${ver ? `<span class="tag">${esc(ver)}</span>` : ""}</h3>
          <label class="switch" title="${esc(t(u.enabled ? "ex.turn_off" : "ex.turn_on"))}"><input type="checkbox" data-toggle="${u.id}" ${u.enabled ? "checked" : ""} aria-label="${esc(t("ex.enabled"))}"><span></span></label>
        </div>
        <div>${st}</div>
        ${u.config_error ? `<p class="err">${esc(tm(u.config_error))}</p>` : ""}
        <div class="kv">
          <div><span>${esc(t("ex.server"))}</span><b><bdi>${esc(u.endpoint || "—")}</bdi></b></div>
          ${u.kind === "socks5" ? `<div><span>${esc(t("ex.socks_user"))}</span><b><bdi>${esc(u.socks_user || t("ex.socks_noauth"))}</bdi></b></div>`
            : `<div><span>${esc(t("ex.address"))}</span><b><bdi>${esc(u.address || "—")}</bdi></b></div>`}
          ${acctOn()
            ? `<div><span>${esc(t("ex.month"))}</span><b>${arrows(u.traffic)}</b></div>
               <div><span>${esc(t("ex.all_time"))}</span><b>${arrows(u.traffic, "total")}</b></div>`
            : `<div><span>${esc(t("ex.traffic"))}</span><b>↓ ${esc(fmtBytes(h.rx))} ↑ ${esc(fmtBytes(h.tx))}</b></div>`}
          ${u.quota ? `<div><span>${esc(t(u.quota_action === "notify" ? "ex.limit_notify" : "ex.limit"))}</span><b>${exitQuota(u)}</b></div>` : ""}
          ${u.quota && u.quota_action !== "notify" ? `<div><span>${esc(t("ex.quota_action"))}</span><b>${outChip(u.quota_action)}</b></div>` : ""}
          <div><span>${esc(t("ex.on_fail"))}</span><b>${outChip(u.fallback)}</b></div>
        </div>
        ${u.refs.length ? `<div class="small muted">${esc(t("ex.used_by", { refs: tm(u.refs) }))}</div>` : ""}
        <div class="actions">
          <button class="btn sm" data-probe="up:${u.id}">${esc(t("btn.check"))}</button>
          <button class="btn sm" data-edit="${u.id}">${esc(t("btn.edit"))}</button>
          <button class="btn sm ghost danger" data-del="${u.id}">${esc(t("btn.delete"))}</button>
          <span class="probe-res" data-probe-res="up:${u.id}">${probeHtml("up:" + u.id)}</span>
        </div>
      </div>
    </div>`;
  }).join("");
  const direct = acctOn() ? `
    <div class="panel exit" style="--c:var(--direct)">
      <div class="exit-bar"></div>
      <div class="exit-main">
        <div class="exit-head"><h3>${esc(t("out.direct"))}</h3></div>
        <div class="small muted">${esc(t("ex.direct_sub"))}</div>
        <div class="kv">
          <div><span>${esc(t("ex.month"))}</span><b>${arrows(S.direct_traffic)}</b></div>
          <div><span>${esc(t("ex.all_time"))}</span><b>${arrows(S.direct_traffic, "total")}</b></div>
        </div>
      </div>
    </div>` : "";
  const off = S.acct && S.acct.state === "off"
    ? `<div class="notice warn">${esc(t("ex.acct_off", { error: S.acct.error || "?" }))}</div>` : "";
  return `
  <section class="section">
    <div class="section-head">
      <div><h2>${esc(t("ex.title"))}</h2><p class="muted small">${esc(t("ex.subtitle"))}</p></div>
      <button class="btn primary" id="add-up">${esc(t("ov.add_exit"))}</button>
    </div>
    ${off}
    ${cards || `<div class="panel empty"><p>${esc(t("ex.empty"))}</p><p class="small">${esc(t("ex.empty_hint"))}</p><button class="btn primary" data-add-empty>${esc(t("ov.add_exit"))}</button></div>`}
    ${direct}
  </section>`;
}
bind.exits = () => {
  const add = () => editUpstream(null);
  $("#add-up").onclick = add;
  const e = $("[data-add-empty]"); if (e) e.onclick = add;
  $$("[data-edit]").forEach((b) => b.onclick = () => editUpstream(b.dataset.edit));
  $$("[data-probe]").forEach((b) => b.onclick = () => {
    const k = b.dataset.probe;
    runProbe(k, () => { const el = $(`[data-probe-res="${k}"]`); if (el) el.innerHTML = probeHtml(k); });
  });
  $$("[data-toggle]").forEach((i) => i.onchange = async () => {
    try { await api("PUT", "upstreams/" + i.dataset.toggle, { enabled: i.checked }); refresh(); }
    catch (err) { toast(err.message, true); i.checked = !i.checked; }
  });
  $$("[data-del]").forEach((b) => b.onclick = () => deleteUpstream(upstreamById(b.dataset.del)));
};

/** удаление выхода: если он где-то используется — выбрать, что встанет на его место */
async function deleteUpstream(u) {
  if (!u.refs.length) {
    if (!confirm(t("ex.delete_confirm", { name: u.name }))) return;
    try { await api("DELETE", "upstreams/" + u.id); toast(t("toast.exit_deleted")); refresh(); }
    catch (err) { if (!(err instanceof AuthError)) toast(err.message, true); }
    return;
  }
  // по умолчанию — его резервный выход: туда трафик и так ушёл бы, если бы выход перестал работать
  const self = "up:" + u.id;
  const fb = u.fallback && u.fallback !== self && (u.fallback === "direct" || u.fallback === "block"
    || upstreamById(u.fallback.slice(3))) ? u.fallback : "direct";
  openModal(t("ex.delete_title", { name: u.name }), `
    <p style="margin-top:0">${esc(t("ex.delete_used"))}</p>
    <ul class="small" style="margin:0 0 12px;padding-inline-start:20px">${u.refs.map((r) => `<li><bdi>${esc(tm(r))}</bdi></li>`).join("")}</ul>
    <label class="field"><span>${esc(t("ex.delete_replace"))}</span>
      <select id="del-repl">${outOptions(fb, { exclude: self })}</select>
      <span class="hint">${esc(t("ex.delete_hint"))}</span></label>`,
  `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn danger" id="del-go">${esc(t("btn.delete"))}</button>`);
  $("#del-go").onclick = async () => {
    $("#del-go").disabled = true;
    try {
      await api("DELETE", "upstreams/" + u.id, { replace: $("#del-repl").value });
      closeModal(); toast(t("toast.exit_deleted")); refresh();
    } catch (err) { if (!(err instanceof AuthError)) toast(err.message, true); $("#del-go").disabled = false; }
  };
}

/* Строка SOCKS5 ⇄ отдельные поля (как awgconf.parse_socks: socks5://логин:пароль@адрес:порт,
   socks5h://, socks://, логин:пароль@адрес:порт, адрес:порт:логин:пароль) */
function socksParse(text) {
  const s = text.trim(); let m;
  const dec = (x) => { try { return decodeURIComponent(x); } catch (e) { return x; } };
  if (!/^socks(5h?)?:\/\//i.test(s) && (m = s.match(/^([^\s:@\/\[\]]+):(\d{1,5}):([^:]*):(.*)$/)))
    return { host: m[1], port: m[2], user: m[3], pass: m[4] };
  let rest = s.replace(/^socks(5h?)?:\/\//i, "").replace(/\/$/, ""), user = "", pass = "";
  const at = rest.lastIndexOf("@");
  if (at >= 0) {
    const up = rest.slice(0, at), i = up.indexOf(":");
    user = dec(i < 0 ? up : up.slice(0, i)); pass = i < 0 ? "" : dec(up.slice(i + 1));
    rest = rest.slice(at + 1);
  }
  m = rest.match(/^\[([0-9a-fA-F:.]+)\](?::(\d*))?$/) || rest.match(/^([^\s:\/\[\]@]*)(?::(\d*))?$/);
  return m ? { host: m[1], port: m[2] || "", user, pass } : null;
}
function socksBuild(f) {
  if (!f.host && !f.port && !f.user && !f.pass) return "";
  const q = encodeURIComponent, h = f.host.includes(":") ? `[${f.host}]` : f.host;
  return "socks5://" + (f.user || f.pass ? q(f.user) + (f.pass ? ":" + q(f.pass) : "") + "@" : "") + h + (f.port ? ":" + f.port : "");
}
const looksSocks = (s) => /^socks(5h?)?:\/\//i.test(s.trim()) || (!!s.trim() && !/[\[\]=\n]/.test(s.trim()) && !/^vpn:\/\//i.test(s.trim()) && !!socksParse(s));

async function editUpstream(id) {
  const u = id ? upstreamById(id) : null;
  const out = u ? "up:" + u.id : null;
  let conf = "", ownText = "";
  if (u) {
    try { conf = (await api("GET", `upstreams/${id}/config`)).config; } catch (e) { toast(e.message, true); return; }
    if (u.own_list && listObj(u.own_list)) { try { ownText = (await api("GET", "lists/" + u.own_list)).source || ""; } catch (e) { /* пусто */ } }
  }
  let kind = u ? (u.kind === "socks5" ? "socks5" : "awg") : "awg";
  const buf = { awg: kind === "awg" ? conf : "", socks5: kind === "socks5" ? conf : "" };
  // что сейчас ведёт на этот выход в общих правилах
  const routed = new Set(out ? S.routing.rules.filter((r) => r.outbound === out && r.enabled !== false).flatMap((r) => r.lists) : []);
  const dlists = S.lists.filter((l) => l.kind === "domains" && l.id !== (u && u.own_list));
  const nlists = S.lists.filter((l) => l.kind !== "domains");
  const box = (l) => `<label class="check"><input type="checkbox" data-rl="${esc(l.id)}" ${routed.has(l.id) ? "checked" : ""}><span><bdi>${esc(listName(l.id))}</bdi></span></label>`;
  const group = (title, ls) => ls.length ? `<div class="field"><span>${esc(title)}</span><div class="check-cols">${ls.map(box).join("")}</div></div>` : "";
  openModal(u ? t("ex.modal_title", { name: u.name }) : t("ex.new"), `
    <div class="field"><span>${esc(t("ex.kind"))}</span>
      <div class="seg" id="u-kind"><button type="button" data-v="awg">AmneziaWG</button><button type="button" data-v="socks5">SOCKS5</button></div>
      ${u ? `<span class="hint">${esc(t("ex.kind_locked"))}</span>` : ""}</div>
    <label class="field"><span>${esc(t("ex.name"))}</span><input type="text" id="u-name" maxlength="40" value="${esc(u ? u.name : "")}" placeholder="${esc(t("ex.name_ph"))}"></label>
    <div id="u-sf">
      <div class="row2 row2-port">
        <label class="field"><span>${esc(t("ex.socks_host"))}</span><input type="text" id="u-sh" dir="ltr" spellcheck="false" autocomplete="off" placeholder="203.0.113.20"></label>
        <label class="field"><span>${esc(t("ex.socks_port"))}</span><input type="text" id="u-sp" dir="ltr" inputmode="numeric" maxlength="5" autocomplete="off" placeholder="1080"></label>
      </div>
      <div class="row2">
        <label class="field"><span>${esc(t("ex.socks_user"))}</span><input type="text" id="u-su" dir="ltr" spellcheck="false" autocomplete="off" placeholder="${esc(t("ex.socks_opt"))}"></label>
        <label class="field"><span>${esc(t("ex.socks_pass"))}</span><input type="password" id="u-sw" dir="ltr" autocomplete="new-password" placeholder="${esc(t("ex.socks_opt"))}"></label>
      </div>
    </div>
    <label class="field"><span id="u-conf-l"></span>
      <textarea id="u-conf" dir="ltr" spellcheck="false"></textarea>
      <span class="hint" id="u-conf-h"></span>
    </label>
    <div class="field" id="u-filef"><input type="file" id="u-file" accept=".conf,.txt,.vpn" aria-label="${esc(t("ex.file"))}"></div>
    <fieldset class="subbox" id="u-route">
      <legend>${esc(t("ex.route_title"))}</legend>
      <p class="small muted" style="margin-top:0">${esc(t("ex.route_hint"))}</p>
      <label class="field"><span>${esc(t("ex.route_sites"))}</span>
        <textarea id="u-doms" class="short" dir="ltr" spellcheck="false" placeholder="${esc(t("ex.route_sites_ph"))}">${esc(ownText)}</textarea>
        <span class="hint">${esc(t("ex.route_sites_hint"))}</span></label>
      ${group(t("ex.route_dlists"), dlists)}
      ${group(t("ex.route_nlists"), nlists)}
      <label class="check"><input type="checkbox" id="u-rdef" ${out && S.routing.default === out ? "checked" : ""}><span>${esc(t("ex.route_default"))}</span></label>
    </fieldset>
    <label class="field"><span>${esc(t("ex.fallback"))}</span>
      <select id="u-fb">${outOptions(u ? u.fallback : "direct", { exclude: out })}</select>
      <span class="hint">${esc(t("ex.fallback_hint"))}</span>
    </label>
    <div class="row2">
      <label class="field"><span>${esc(t("ex.quota"))}</span>
        <input type="number" id="u-quota" min="0" step="any" inputmode="decimal" placeholder="${esc(t("cl.no_limit"))}" value="${u && u.quota ? +(u.quota / 1024 ** 3).toFixed(3) : ""}"></label>
      <label class="field"><span>${esc(t("ex.quota_action"))}</span>
        <select id="u-qa">${quotaOptions(u)}</select></label>
    </div>
    <p class="small muted" style="margin:-6px 0 14px">${esc(t("ex.quota_hint", { time: monthResetLocal() }))}</p>
    ${u ? "" : `<label class="check" id="u-defl"><input type="checkbox" id="u-def" ${S.routing.default === "direct" ? "checked" : ""}><span>${esc(t("ex.make_default"))}</span></label>`}
  `, `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="u-save">${esc(t(u ? "btn.save" : "btn.add"))}</button>`);
  const F = { host: $("#u-sh"), port: $("#u-sp"), user: $("#u-su"), pass: $("#u-sw") };
  const ta = $("#u-conf");
  let routeTouched = false;
  const toFields = () => {
    const f = socksParse(ta.value);
    if (f) for (const k in F) F[k].value = f[k];
  };
  const draw = () => {
    const socks = kind === "socks5";
    $$("#u-kind button").forEach((b) => {
      b.setAttribute("aria-pressed", b.dataset.v === kind);
      b.disabled = !!u && b.dataset.v !== kind;          // тип существующего выхода не меняется
    });
    $("#u-sf").hidden = $("#u-route").hidden = !socks;
    $("#u-filef").hidden = socks;
    if ($("#u-defl")) $("#u-defl").hidden = socks;      // у SOCKS5 — в блоке маршрутизации
    $("#u-conf-l").textContent = t(socks ? "ex.socks_line" : "ex.config");
    $("#u-conf-h").textContent = socks ? t("ex.socks_line_hint") : t("ex.config_hint");
    ta.placeholder = socks ? "socks5://login:password@203.0.113.20:1080" : t("ex.config_ph");
    ta.classList.toggle("short", socks);
    ta.value = buf[kind];
    if (socks) toFields();
  };
  $$("#u-kind button").forEach((b) => b.onclick = () => {
    if (b.disabled || b.dataset.v === kind) return;
    buf[kind] = ta.value; kind = b.dataset.v; draw();
  });
  Object.values(F).forEach((el) => el.oninput = () => {
    if (el === F.port) el.value = el.value.replace(/\D/g, "");
    ta.value = buf.socks5 = socksBuild({ host: F.host.value.trim(), port: F.port.value.trim(), user: F.user.value, pass: F.pass.value });
  });
  ta.oninput = () => {
    if (kind === "socks5") { buf.socks5 = ta.value; toFields(); return; }
    buf.awg = ta.value;
    if (!u && looksSocks(ta.value)) { buf.socks5 = ta.value.trim(); buf.awg = ""; kind = "socks5"; draw(); }   // вставили прокси — сразу SOCKS5
  };
  $$("#u-route input, #u-route textarea").forEach((el) => el.addEventListener("input", () => routeTouched = true));
  $("#u-file").onchange = async (e) => {
    const f = e.target.files[0]; if (!f) return;
    ta.value = buf.awg = (await f.text()).trim();
    if (!$("#u-name").value) $("#u-name").value = f.name.replace(/\.(conf|txt|vpn)$/i, "").slice(0, 40);
  };
  draw();
  $("#u-save").onclick = async () => {
    const body = { name: $("#u-name").value.trim(), fallback: $("#u-fb").value,
      quota_gb: $("#u-quota").value.trim(), quota_action: $("#u-qa").value };
    const c = ta.value.trim();
    if (!u || c !== conf.trim()) body.config = c;
    if (kind === "socks5" && (routeTouched || !u)) {
      const picked = $$("#u-route [data-rl]").filter((x) => x.checked).map((x) => x.dataset.rl);
      body.routing = { domains: $("#u-doms").value.trim(), default: $("#u-rdef").checked,
        domain_lists: picked.filter((x) => dlists.some((l) => l.id === x)),
        net_lists: picked.filter((x) => nlists.some((l) => l.id === x)) };
      if (!u && !body.routing.domains && !picked.length && !body.routing.default) delete body.routing;
    }
    const btn = $("#u-save"); btn.disabled = true;
    try {
      if (u) await api("PUT", "upstreams/" + u.id, body);
      else await api("POST", "upstreams", { ...body, make_default: kind === "awg" && $("#u-def").checked });
      closeModal(); toast(t(u ? "toast.exit_saved" : "toast.exit_added"));
      refresh();
    } catch (e) { toast(e.message, true); }
    btn.disabled = false;
  };
}

/* ================================================================ списки */
/** где используется список: общие правила (с выходом), правила клиентов */
function listUses(l) {
  const out = [];
  S.routing.rules.forEach((r, i) => {
    if (!r.lists.includes(l.id)) return;
    out.push(`<div class="use ${r.enabled === false ? "off" : ""}"><span>${esc(t("ref.rule", { rule: r.comment || "#" + (i + 1) }))}</span> → ${outChip(r.outbound)}</div>`);
  });
  for (const m of l.refs || []) if (m && m.$t === "ref.client_rule") out.push(`<div class="use"><span>${esc(tm(m))}</span></div>`);
  return out.length ? out.join("") : `<span class="muted">${esc(t("ls.unused"))}</span>`;
}
function listsSection() {
  const rows = S.lists.map((l) => {
    const badge = l.kind === "country" ? `<span class="cc">${esc(l.source.toUpperCase())}</span>`
      : l.kind === "asn" ? `<span class="cc">AS</span>` : l.kind === "domains" ? `<span class="cc">SNI</span>` : "";
    const hits = S.sni && S.sni.by_list ? S.sni.by_list[l.id] || 0 : null;
    const size = l.kind === "domains"
      ? (l.count ? `${esc(t("n.domains", { n: l.count }))}${l.refs.length && hits !== null ? `<div class="small muted">${esc(t("ls.domains_hits", { n: hits }))}</div>` : ""}` : `<span class="muted">${esc(t("ls.not_loaded"))}</span>`)
        + (l.refs.length && S.sni && S.sni.state === "error" ? `<div class="small warn-text">${esc(t("ls.sni_error"))}</div>` : "")
      : null;
    const src = l.kind === "url" || (l.kind === "asn" && l.name !== l.source) ? `<bdi>${esc(l.source)}</bdi>` : esc(t("ls.kind." + l.kind));

    return `
    <tr>
      <td>${badge}<b><bdi>${esc(listName(l.id))}</bdi></b><div class="list-row-src">${src}</div></td>
      <td data-m="sub">${size !== null ? size : l.count ? `${esc(t("n.networks", { n: l.count }))}<div class="small muted">${esc(t("n.addresses", { n: l.addresses, nText: fmtCompact(l.addresses) }))}</div>` : `<span class="muted">${esc(t("ls.not_loaded"))}</span>`}${l.skipped_v6 ? `<div class="small warn-text">${esc(t("ls.skipped_v6", { n: l.skipped_v6 }))}</div>` : ""}
        ${l.error ? `<div class="err small">${esc(tm(l.error))}</div>` : ""}${l.updated ? `<div class="small muted">${esc(t("ls.updated", { time: fmtTime(l.updated) }))}</div>` : ""}</td>
      <td data-m="sub" class="uses">${listUses(l)}</td>
      <td data-m="right" class="nowrap acts">
        ${l.kind !== "manual" ? `<button class="icon-btn" data-refresh="${esc(l.id)}" title="${esc(t("ls.refresh"))}" aria-label="${esc(t("ls.refresh"))}">⟳</button>` : ""}
        ${l.kind !== "country" ? `<button class="icon-btn" data-edit-list="${esc(l.id)}" title="${esc(t("btn.edit"))}" aria-label="${esc(t("btn.edit"))}">✎</button>` : ""}
        <button class="icon-btn" data-del-list="${esc(l.id)}" title="${esc(t("btn.delete"))}" aria-label="${esc(t("btn.delete"))}">✕</button>
      </td>
    </tr>`;
  }).join("");
  return `
    <div class="section-head">
      <div><h2>${esc(t("ls.title"))}</h2><p class="muted small">${esc(t("ls.subtitle", { hours: fmtNum(S.settings.list_update_hours) }))}</p></div>
      <div class="add-row">${LIST_KINDS.map((k) => `<button class="btn" data-add-kind="${k}">${esc(t("ls.add_" + k))}</button>`).join("")}</div>
    </div>
    <div class="panel">${S.lists.length ? `<table class="table responsive"><thead><tr><th>${esc(t("ls.col_list"))}</th><th>${esc(t("ls.col_size"))}</th><th>${esc(t("ls.col_used"))}</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="empty"><p>${esc(t("ls.empty"))}</p></div>`}</div>`;
}
function bindLists() {
  $$("[data-add-kind]").forEach((b) => b.onclick = () => editList(null, b.dataset.addKind));
  $$("[data-edit-list]").forEach((b) => b.onclick = () => editList(b.dataset.editList));
  $$("[data-refresh]").forEach((b) => b.onclick = async () => {
    b.disabled = true;
    try {
      const l = await api("POST", `lists/${b.dataset.refresh}/refresh`);
      l.error ? toast(tm(l.error), true) : toast(t("ls.refreshed", { name: listName(l.id) }));
    } catch (e) { toast(e.message, true); }
    refresh();
  });
  $$("[data-del-list]").forEach((b) => b.onclick = async () => {
    if (!confirm(t("ls.delete_confirm", { name: listName(b.dataset.delList) }))) return;
    try { await api("DELETE", "lists/" + b.dataset.delList); refresh(); } catch (e) { toast(e.message, true); }
  });
}
function editList(id, kind, onSaved = null) {
  const l = id ? listObj(id) : null;
  kind = l ? l.kind : kind;
  const nameField = (ph = "") => `<label class="field"><span>${esc(t("ls.name"))}</span><input type="text" id="l-name" maxlength="40" value="${esc(l ? l.name : "")}" placeholder="${esc(ph)}"></label>`;
  let body;
  if (kind === "country") {
    const have = new Set(S.lists.map((x) => x.id));
    const opts = S.country_codes.filter((cc) => !have.has(cc)).map((cc) => [cc, countryName(cc)])
      .sort((a, b) => a[1].localeCompare(b[1], LANG));
    body = `<label class="field"><span>${esc(t("ls.cc"))}</span><input type="text" id="l-src" dir="ltr" list="cc-list" maxlength="2" placeholder="ru" style="text-transform:lowercase">
      <datalist id="cc-list">${opts.map(([cc, n]) => `<option value="${cc}">${esc(n)}</option>`).join("")}</datalist>
      <span class="hint">${esc(t("ls.cc_hint"))}</span></label>`;
  } else if (kind === "asn") {
    body = nameField("Yandex") + `<label class="field"><span>${esc(t("ls.asn"))}</span><textarea id="l-src" dir="ltr" style="min-height:80px" placeholder="AS13238 AS47541">${esc(l ? l.source : "")}</textarea>
      <span class="hint">${esc(t("ls.asn_hint"))}</span></label>`;
  } else if (kind === "url") {
    body = nameField() + `<label class="field"><span>${esc(t("ls.urls"))}</span><textarea id="l-src" dir="ltr" style="min-height:90px" placeholder="https://example.com/list.txt">${esc(l ? l.source : "")}</textarea>
      <span class="hint">${esc(t("ls.urls_hint"))}</span></label>`;
  } else if (kind === "domains") {
    body = nameField("YouTube") + `<label class="field"><span>${esc(t("ls.domains"))}</span><textarea id="l-src" dir="ltr" spellcheck="false" placeholder="youtube.com&#10;googlevideo.com&#10;https://example.com/domains.txt">${esc(l ? l.source || "" : "")}</textarea>
      <span class="hint">${esc(t("ls.domains_hint"))}</span></label>
      <p class="small muted" style="margin:0">${esc(t("ls.domains_how"))}</p>`;
  } else {
    body = nameField(t("ls.manual_ph")) + `<label class="field"><span>${esc(t("ls.cidrs"))}</span><textarea id="l-src" dir="ltr" placeholder="203.0.113.0/24&#10;198.51.100.7">${esc(l ? l.source : "")}</textarea>
      <span class="hint">${esc(t("ls.cidrs_hint"))}</span></label>`;
  }
  const title = l ? t("ls.edit", { name: listName(l.id) }) : t("ls.new." + kind);
  openModal(title, body, `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="l-save">${esc(t(l ? "btn.save" : "btn.add"))}</button>`);
  if (l && (kind === "manual" || kind === "domains")) {
    // текст ручного списка не приходит в /api/state (он бывает в мегабайты) — берём отдельно
    const ta = $("#l-src"), save = $("#l-save");
    ta.disabled = save.disabled = true;
    ta.placeholder = t("ls.loading");
    api("GET", "lists/" + l.id)
      .then((r) => { ta.value = r.source || ""; ta.disabled = save.disabled = false; })
      .catch((err) => toast(err.message, true));
  }
  $("#l-save").onclick = async (e) => {
    const b = { kind, source: $("#l-src").value.trim() };
    if ($("#l-name")) b.name = $("#l-name").value.trim();
    const label = e.target.textContent;
    e.target.disabled = true; e.target.textContent = t("ls.loading");
    try {
      const r = l ? await api("PUT", "lists/" + l.id, b) : await api("POST", "lists", b);
      closeModal();
      await refresh();
      if (onSaved && r && r.id) onSaved(r.id);
      if (r && r.error) toast(t("ls.saved_failed", { e: tm(r.error) }), true);
      else {
        toast(t("ls.saved", { name: listName(r.id), count: t(kind === "domains" ? "n.domains" : "n.networks", { n: r.count || 0 }) }));
        if (r.skipped_v6) toast(t("ls.skipped_v6", { n: r.skipped_v6 }));
      }
    } catch (err) { toast(err.message, true); e.target.disabled = false; e.target.textContent = label; }
  };
}

/* ===================================================== сигнатурные пакеты I1–I5 */
const CPS_KEYS = ["I1", "I2", "I3", "I4", "I5"];
const CPS_SHORT = { amnezia: "DNS icloud", stun: "STUN", quic: "QUIC", dns: "DNS", sip: "SIP" };
/** размер пакета в байтах (как app/cps.py) или null, если теги неверные */
function cpsSize(v) {
  v = (v || "").trim();
  if (!v) return 0;
  let n = 0;
  for (const tok of v.match(/<[^<>]*>|[^<>\s]+|[<>]/g) || []) {
    if (!(tok.startsWith("<") && tok.endsWith(">") && tok.length > 2)) return null;
    const [name, ...rest] = tok.slice(1, -1).trim().split(/\s+/);
    const arg = rest.join(" "), nm = name.toLowerCase();
    if (nm === "b") { const m = /^0x((?:[0-9a-fA-F]{2})+)$/.exec(arg); if (!m) return null; n += m[1].length / 2; }
    else if (nm === "t") { if (arg) return null; n += 4; }
    else if (["r", "rc", "rd"].includes(nm)) { if (!/^\d+$/.test(arg) || +arg < 1 || +arg > 1400) return null; n += +arg; }
    else return null;
  }
  return n;
}
function cpsSizeHtml(v) {
  const n = cpsSize(v);
  if (n === null) return `<span class="err">${esc(t("cps.bad"))}</span>`;
  if (!n) return "";
  return n > 1200 ? `<span class="warn-text">${esc(t("cps.big", { n }))}</span>` : esc(t("cps.bytes", { n }));
}
function cpsNorm(v) { return (v || "").split(/\s+/).filter(Boolean).join(" "); }
/** какой шаблон совпадает со значениями I1–I5 (или null — свои) */
function cpsMatch(presets, values) {
  const p = (presets || []).find((x) => CPS_KEYS.every((k) => cpsNorm(x.values[k]) === cpsNorm(values[k])));
  return p ? p.id : null;
}
function cpsName(id) { return id ? t("cps." + id) : t("cps.custom"); }
function cpsTag(cps) { return cps ? (CPS_SHORT[cps.preset] || t("cps.s_" + cps.preset)) : ""; }
/** поля I1–I5 с размером под каждым (для своих значений клиента) */
function cpsFields(prefix, values) {
  return `<div class="pgrid" style="--cols:1">${CPS_KEYS.map((k) => `
    <label class="field param param-wide"><span><span class="pname">${k}</span></span>
      <textarea id="${prefix}-${k}" data-cps="${k}" dir="ltr" rows="2" spellcheck="false" placeholder="<b 0x…> <r 16>">${esc(values[k] || "")}</textarea>
      <span class="hint" id="${prefix}-${k}-size">${cpsSizeHtml(values[k])}</span></label>`).join("")}</div>`;
}
function bindCpsSizes(prefix) {
  CPS_KEYS.forEach((k) => { const el = $(`#${prefix}-${k}`); if (el) el.addEventListener("input", () => { $(`#${prefix}-${k}-size`).innerHTML = cpsSizeHtml(el.value); }); });
}

/* ================================================================ сервер */
const PARAM_GROUPS = [
  ["srv.g_junk", ["Jc", "Jmin", "Jmax"]],
  ["srv.g_sizes", ["S1", "S2", "S3", "S4"]],
  ["srv.g_headers", ["H1", "H2", "H3", "H4"]],
  ["srv.g_hp", ["HeaderProtectionKey"]],
  ["srv.g_awg3", ["ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
    "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"]],
  ["srv.g_sig", ["I1", "I2", "I3", "I4", "I5"]],
];
let SRV = null;          // /api/server
let srvDraft = null;     // редактируемые параметры

function viewServer() {
  if (!S.target) return `<div class="panel empty"><p>${esc(t("status.no_target"))}</p></div>`;
  if (!SRV) { loadServer(); return `<p class="muted">${esc(t("probe.checking"))}</p>`; }
  if (!SRV.exists) {
    if (!SRV.can_init) return `<div class="panel empty"><p>${esc(t("srv.missing"))}</p></div>`;
    return `
    <section class="section">
      <div class="section-head"><div><h2>${esc(t("srv.create_title"))}</h2><p class="muted small">${esc(t("srv.create_sub"))}</p></div></div>
      <div class="panel panel-pad" style="max-width:560px">
        <label class="field"><span>${esc(t("srv.port"))}</span><input type="number" id="i-port" min="1" max="65535" value="${20000 + Math.floor(Math.random() * 40000)}" style="max-width:160px"><span class="hint">${esc(t("srv.port_hint"))}</span></label>
        <label class="field"><span>${esc(t("srv.subnet"))}</span><input type="text" id="i-subnet" dir="ltr" value="10.8.1.0/24" style="max-width:200px"></label>
        <button class="btn primary" id="i-create">${esc(t("srv.create_btn"))}</button>
      </div>
    </section>`;
  }
  const d = srvDraft || (srvDraft = { ...SRV.params });
  const kindLabel = SRV.kind === "host" ? t("srv.kind_host") : SRV.kind === "demo" ? "demo" : t("srv.kind_container");
  const param = (k) => {
    const meta = SRV.param_meta[k] || {};
    const side = `<span class="side side-${meta.side}" title="${esc(t("srv.side_" + meta.side + "_hint"))}">${esc(t("srv.side_" + meta.side))}</span>`;
    let input;
    if (meta.type === "bool") {
      input = `<select data-p="${k}">${["", "on", "off"].map((v) => `<option value="${v}" ${d[k] === v ? "selected" : ""}>${v ? esc(t("srv.bool_" + v)) : "—"}</option>`).join("")}</select>`;
    } else if (meta.type === "text") {
      input = `<textarea data-p="${k}" dir="ltr" rows="2" spellcheck="false" placeholder="<b 0x…> <r 16>">${esc(d[k] || "")}</textarea>`;
    } else {
      input = `<input type="text" data-p="${k}" dir="ltr" value="${esc(d[k] || "")}" ${meta.type === "key" ? 'class="mono"' : ""}>`;
    }
    const size = meta.type === "text" ? `<span class="hint" id="sz-${k}">${cpsSizeHtml(d[k])}</span>` : "";
    const hint = t("p." + k) ? `<span class="hint">${esc(t("p." + k))}</span>` : "";
    return `<label class="field param ${meta.type === "text" || meta.type === "key" ? "param-wide" : ""}"><span><span class="pname" title="${esc(k)}">${esc(k)}</span>${side}</span>${input}${hint}${size}</label>`;
  };
  return `
  <div class="grid2 pair">
    <section class="section">
      <div class="section-head"><h2>${esc(t("srv.title"))}</h2></div>
      <div class="panel panel-pad">
        <div class="kv" style="margin-bottom:14px">
          <div><span>${esc(t("srv.kind"))}</span><b>${esc(kindLabel)}</b></div>
          <div><span>${esc(t("sy.iface"))}</span><b>${esc(SRV.iface)}</b></div>
          <div><span>${esc(t("srv.version"))}</span><b>${esc(SRV.version ? "AWG " + SRV.version : "WireGuard")}</b></div>
        </div>
        <label class="field"><span>${esc(t("srv.public_host"))}</span><input type="text" id="s-host" dir="ltr" value="${esc(SRV.public_host)}" placeholder="203.0.113.10"><span class="hint">${esc(t("srv.public_host_hint"))}</span></label>
        <div class="row2">
          <label class="field"><span>${esc(t("srv.port"))}</span><input type="number" id="s-port" min="1" max="65535" value="${SRV.port}" ${SRV.port_locked ? "disabled" : ""}><span class="hint">${esc(t(SRV.port_locked ? "srv.port_locked" : "srv.port_hint"))}</span></label>
          <label class="field"><span>${esc(t("srv.subnet"))}</span><input type="text" id="s-addr" dir="ltr" value="${esc(SRV.address)}" ${SRV.subnet_locked ? "disabled" : ""}><span class="hint">${esc(t(SRV.subnet_lock === "container" ? "srv.subnet_container_hint" : SRV.subnet_locked ? "srv.subnet_locked_hint" : "srv.subnet_hint"))}</span></label>
        </div>
      </div>
    </section>
    <section class="section">
      <div class="section-head"><h2>${esc(t("srv.clients_title"))}</h2></div>
      <div class="panel panel-pad">
        <label class="field"><span>${esc(t("srv.client_host"))}</span><select id="s-ch">${clientHostOptions()}</select><span class="hint" id="s-ch-hint">${clientHostHint(SRV.client_host)}</span></label>
        <label class="field"><span>DNS</span><input type="text" id="s-dns" dir="ltr" value="${esc((SRV.client_dns || []).join(", "))}"><span class="hint">${esc(t("srv.dns_hint"))}</span></label>
        <div class="row2">
          <label class="field"><span>MTU</span><input type="number" id="s-mtu" min="1100" max="1500" value="${SRV.client_mtu}"><span class="hint">${esc(t("srv.mtu_hint"))}</span></label>
          <label class="field"><span>PersistentKeepalive</span><input type="text" id="s-ka" dir="ltr" value="${esc(SRV.client_keepalive)}" placeholder="${esc(t("srv.auto", { v: SRV.keepalive_auto }))}"><span class="hint">${esc(t("srv.ka_hint"))}</span></label>
        </div>
      </div>
    </section>
  </div>
  <section class="section">
    <div class="section-head">
      <div><h2>${esc(t("srv.obf_title"))}</h2><p class="muted small">${esc(t("srv.obf_sub"))}</p></div>
      <button class="btn" id="s-gen">${esc(t("srv.generate"))}</button>
    </div>
    <div class="panel panel-pad">
      ${PARAM_GROUPS.map(([g, keys]) => `<fieldset class="pgroup"><legend>${esc(t(g))}</legend>${g === "srv.g_sig" ? sigTemplate(d) : ""}<div class="pgrid" style="--cols:${Math.min(keys.length, 4)}">${keys.map(param).join("")}</div></fieldset>`).join("")}
    </div>
    <div class="savebar" id="s-bar" ${srvDirty() ? "" : "hidden"}><span id="s-bar-text">${esc(t("srv.save_hint"))}</span>
      <span class="actions"><button class="btn sm" id="s-reset">${esc(t("btn.discard"))}</button><button class="btn sm primary" id="s-save">${esc(t("btn.save"))}</button></span></div>
  </section>`;
}
function sigTemplate(d) {
  const presets = SRV.cps_presets || [];
  const cur = cpsMatch(presets, d);
  return `<label class="field" style="max-width:420px"><span>${esc(t("srv.cps_template"))}</span>
    <select id="s-cps">${presets.map((p) => `<option value="${p.id}" ${p.id === cur ? "selected" : ""}>${esc(cpsName(p.id))}</option>`).join("")}
      <option value="" ${cur ? "" : "selected"} disabled>${esc(t("cps.custom"))}</option></select>
    <span class="hint">${esc(t("srv.cps_template_hint"))}</span></label>`;
}
/* Адрес сервера в конфигах клиентов: внешний адрес или найденный IPv4/IPv6 */
function clientHostOptions() {
  const A = SRV.addrs || {}, cur = SRV.client_host || "";
  const opts = [["", t("srv.ch_main", { v: SRV.public_host || "—" })]];
  if (A.v4 && A.v4 !== SRV.public_host) opts.push([A.v4, "IPv4 · " + A.v4]);
  (A.v6 || []).forEach((ip) => { if (ip !== SRV.public_host) opts.push([ip, "IPv6 · " + ip]); });
  if (cur && !opts.some(([v]) => v === cur)) opts.push([cur, (cur.includes(":") ? "IPv6 · " : "IPv4 · ") + cur]);
  return opts.map(([v, label]) => `<option value="${esc(v)}" ${v === cur ? "selected" : ""}>${esc(label)}</option>`).join("");
}
function clientHostHint(val) {
  const A = SRV.addrs || {}, v6 = A.v6 || [];
  const host = val || SRV.public_host || "";
  const out = [esc(t("srv.client_host_hint"))];
  if (val && val.includes(":") && !v6.includes(val)) out.push(`<span class="warn-text">${esc(t("srv.client_host_gone"))}</span>`);
  if (host.includes(":") && !A.v6_listen) out.push(`<span class="warn-text">${esc(t("srv.v6_not_listening", { port: SRV.port }))}</span>`);
  if (!v6.length) out.push(esc(t("srv.no_v6")));
  return out.join(" ");
}
function srvDirty() {
  if (!SRV || !srvDraft) return false;
  return Object.keys(SRV.params).some((k) => (srvDraft[k] || "") !== (SRV.params[k] || "")) ||
    ["#s-host", "#s-ch", "#s-dns", "#s-mtu", "#s-ka", "#s-port", "#s-addr"].some((sel) => {
      const el = $(sel); return el && el.dataset.orig !== undefined && el.value !== el.dataset.orig;
    });
}
async function loadServer() {
  try { SRV = await api("GET", "server"); } catch (e) { SRV = { exists: false, error: e.message }; }
  srvDraft = null;
  if (tab === "server") render();
}
bind.server = () => {
  const create = $("#i-create");
  if (create) {
    create.onclick = async () => {
      create.disabled = true;
      try {
        await api("POST", "server/init", { port: +$("#i-port").value, subnet: $("#i-subnet").value.trim() });
        toast(t("toast.server_created")); SRV = null; await refresh();
      } catch (e) { toast(e.message, true); create.disabled = false; }
    };
    return;
  }
  if (!SRV || !SRV.exists) return;
  const showBar = () => { $("#s-bar").hidden = !srvDirty(); };
  ["#s-host", "#s-ch", "#s-dns", "#s-mtu", "#s-ka", "#s-port", "#s-addr"].forEach((sel) => {
    const el = $(sel); if (!el) return;
    el.dataset.orig = el.value; el.oninput = showBar;
  });

  const syncTpl = () => {
    const sel = $("#s-cps"); if (!sel) return;
    const m = cpsMatch(SRV.cps_presets, srvDraft);
    sel.value = m || "";
    CPS_KEYS.forEach((k) => { const el = $("#sz-" + k); if (el) el.innerHTML = cpsSizeHtml(srvDraft[k]); });
  };
  $$("[data-p]").forEach((el) => el.oninput = el.onchange = () => { srvDraft[el.dataset.p] = el.value.trim(); showBar(); if (/^I[1-5]$/.test(el.dataset.p)) syncTpl(); });
  const tpl = $("#s-cps");
  if (tpl) tpl.onchange = () => {
    const p = (SRV.cps_presets || []).find((x) => x.id === tpl.value);
    if (!p) return;
    CPS_KEYS.forEach((k) => { srvDraft[k] = p.values[k] || ""; const el = $(`[data-p="${k}"]`); if (el) el.value = srvDraft[k]; });
    syncTpl(); showBar();
  };
  const ch = $("#s-ch");
  if (ch) ch.onchange = () => { $("#s-ch-hint").innerHTML = clientHostHint(ch.value); showBar(); };
  showBar();
  $("#s-gen").onclick = async () => {
    if (!confirm(t("srv.generate_confirm"))) return;
    const r = await api("POST", "server/generate", {});
    srvDraft = { ...srvDraft, ...r.params };
    render();
    toast(t("toast.generated"));
  };
  $("#s-reset").onclick = () => { srvDraft = null; render(); };
  $("#s-save").onclick = async () => {
    const changed = {};
    for (const k of Object.keys(SRV.params)) if ((srvDraft[k] || "") !== (SRV.params[k] || "")) changed[k] = srvDraft[k] || "";
    const serverSide = Object.keys(changed).some((k) => SRV.param_meta[k].side === "server");
    const port = +$("#s-port").value, addr = $("#s-addr").value.trim();
    const restart = serverSide || (!SRV.port_locked && port !== SRV.port) || (!SRV.subnet_locked && addr !== SRV.address);
    if (restart && !confirm(t(SRV.kind === "container" && serverSide ? "srv.confirm_restart_amnezia" : "srv.confirm_restart"))) return;
    const body = { public_host: $("#s-host").value.trim(), client_host: $("#s-ch").value, client_dns: $("#s-dns").value,
      client_mtu: +$("#s-mtu").value, client_keepalive: $("#s-ka").value.trim() };
    if (Object.keys(changed).length) body.params = changed;
    if (!SRV.port_locked) body.port = port;
    if (!SRV.subnet_locked) body.address = addr;
    $("#s-save").disabled = true;
    try {
      const r = await api("PUT", "server", body);
      toast(t(r.restarted ? "toast.server_restarted" : "toast.settings_saved"));
      if (r.server_side_changed || r.host_changed) toast(t("toast.reimport"));
      SRV = null; srvDraft = null; await refresh(); loadServer();
    } catch (e) { toast(e.message, true); $("#s-save").disabled = false; }
  };
};

/* ================================================================ система */
function viewSystem() {
  const tg = S.target;
  const P = S.panel || {}, T = P.tls || {};
  const tlsLine = P.access === "ssh" ? t("sy.tls_ssh")
    : T.active === "letsencrypt" ? t("sy.tls_le", { date: fmtTime(T.expires) })
    : T.active === "selfsigned" ? t("sy.tls_self") : t("sy.tls_off");
  return `
  <section class="section">
    <div class="section-head"><h2>${esc(t("sy.access"))}</h2></div>
    <div class="panel panel-pad">
      <div class="kv">
        <div><span>${esc(t("sy.url"))}</span><b><bdi>${esc(P.url || "—")}</bdi></b></div>
        <div><span>${esc(t("sy.access_mode"))}</span><b>${esc(t(P.access === "ssh" ? "sy.access_ssh" : "sy.access_public"))}</b></div>
        <div><span>${esc(t("sy.cert"))}</span><b>${esc(tlsLine)}</b></div>
        <div><span>${esc(t("sy.version"))}</span><b>${esc((S.version || {}).current || "—")}</b></div>
      </div>
      ${updateNotice()}
      ${T.error && T.active !== "letsencrypt" && P.access !== "ssh" ? `<p class="err small" style="margin-bottom:0">${esc(t("sy.tls_error"))}: ${esc(T.error)}</p>` : ""}
      <div class="actions" style="margin-top:12px">
        ${T.mode === "letsencrypt" ? `<button class="btn sm" id="tls-renew">${esc(t("sy.tls_renew"))}</button>` : ""}
        <button class="btn sm" id="upd-check">${esc(t("sy.check_updates"))}</button>
        ${standalone() ? "" : `<button type="button" class="btn sm" id="app-phone">${esc(t("app.btn"))}</button>`}
      </div>
    </div>
  </section>
  <div class="grid2 pair even">
    ${viewSecurity()}
    <section class="section">
      <div class="section-head"><h2>${esc(t("sy.settings"))}</h2></div>
      <div class="panel panel-pad">
        <label class="field"><span>${esc(t("lang"))}</span>${langSelect("lang-sys")}</label>
        <label class="field"><span>${esc(t("sy.hours"))}</span><input type="number" id="s-hours" min="1" max="720" value="${S.settings.list_update_hours}" style="max-width:120px"></label>
        <div class="field"><span>${esc(t("sy.on_stop"))}</span>
          <div class="seg" id="s-stop"><button type="button" data-v="keep">${esc(t("sy.keep"))}</button><button type="button" data-v="restore">${esc(t("sy.restore"))}</button></div>
          <span class="hint">${esc(t("sy.on_stop_hint"))}</span></div>
        <div class="actions"><button class="btn sm primary" id="s-save">${esc(t("btn.save"))}</button><button class="btn sm ghost" id="logout">${esc(t("sy.logout"))}</button></div>
      </div>
    </section>
  </div>
  ${viewTelegram()}
  <div class="grid2 pair even">
    <section class="section">
      <div class="section-head"><h2>${esc(t("sy.conn"))}</h2></div>
      <div class="panel panel-pad">
        <div class="kv">
          <div><span>${esc(t("sy.container"))}</span><b><bdi>${esc(tg ? (tg.kind === "host" ? t("srv.kind_host") : tg.container) : t("sy.not_found"))}</bdi></b></div>
          <div><span>${esc(t("sy.iface"))}</span><b>${esc(tg ? tg.iface : "—")}</b></div>
          <div><span>${esc(t("sy.conf"))}</span><b><bdi>${esc(tg ? tg.conf : "—")}</bdi></b></div>
          <div><span>${esc(t("sy.tunnels"))}</span><b>${esc(S.backend === "kernel" ? t("sy.kernel") : "amneziawg-go")}</b></div>
          <div><span>${esc(t("sy.last_check"))}</span><b>${esc(fmtTime(S.engine.last_reconcile))}</b></div>
          <div><span>${esc(t("sy.applied"))}</span><b>${esc(fmtTime(S.engine.last_apply))}</b></div>
        </div>
        <div class="actions" style="margin-top:14px"><button class="btn sm" id="reapply">${esc(t("sy.reapply"))}</button></div>
      </div>
    </section>
    ${viewBackup()}
  </div>
  <section class="section">
    <div class="section-head"><div><h2>${esc(t("sy.now"))}</h2><p class="muted small">${esc(t("sy.now_sub"))}</p></div><button class="btn sm" id="load-debug">${esc(t("sy.show"))}</button></div>
    <div id="debug"></div>
  </section>`;
}
bind.system = () => {
  bindLang("lang-sys");
  bindUpdate();
  let onStop = S.settings.on_stop || "keep";
  const seg = () => $$("#s-stop button").forEach((b) => b.setAttribute("aria-pressed", b.dataset.v === onStop));
  $$("#s-stop button").forEach((b) => b.onclick = () => { onStop = b.dataset.v; seg(); });
  seg();
  $("#s-save").onclick = async () => {
    try { await api("PUT", "settings", { list_update_hours: +$("#s-hours").value, on_stop: onStop }); toast(t("toast.settings_saved")); refresh(); }
    catch (e) { toast(e.message, true); }
  };
  const rn = $("#tls-renew");
  if (rn) rn.onclick = async () => {
    rn.disabled = true; toast(t("toast.applying"));
    try { const r = await api("POST", "tls/renew", {}); toast(t(r.ok ? "toast.tls_ok" : "toast.tls_fail"), !r.ok); }
    catch (e) { toast(e.message, true); }
    refresh();
  };
  bindTelegram();
  bindSecurity();
  bindBackup();
  $("#reapply").onclick = async () => { await api("POST", "reapply", {}); toast(t("toast.applying")); setTimeout(refresh, 1500); };
  $("#logout").onclick = async () => { await api("POST", "logout", {}); showLogin(); };
  $("#load-debug").onclick = async () => {
    try {
      const d = await api("GET", "debug");
      $("#debug").innerHTML = `
        ${d.ip_rules ? `<h3 style="margin:0 0 8px">ip rule</h3><pre class="code" dir="ltr">${esc(d.ip_rules)}</pre>` : ""}
        ${d.routes ? `<h3 style="margin:16px 0 8px">${esc(t("sy.exit_tables"))}</h3><pre class="code" dir="ltr">${esc(d.routes)}</pre>` : ""}
        ${d.commands && d.commands.length ? `<h3 style="margin:0 0 8px">${esc(t("sy.commands"))}</h3><pre class="code" dir="ltr">${esc(d.commands.join("\n"))}</pre>` : ""}
        <h3 style="margin:16px 0 8px">nftables</h3><pre class="code" dir="ltr">${esc(d.ruleset || t("sy.not_applied"))}</pre>`;
    } catch (e) { toast(e.message, true); }
  };
};

/* ============================================ иконка на главный экран телефона */
let installPrompt = null;   // Chrome/Edge: событие, которое показывает системное окно установки
window.addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); installPrompt = e; if (S && tab === "system") render(); });
window.addEventListener("appinstalled", () => { installPrompt = null; if (S && tab === "system") render(); });
function standalone() { return matchMedia("(display-mode: standalone)").matches || navigator.standalone === true; }
/** «Установить на телефон»: на телефоне — системное окно установки (Chrome) или как добавить вручную;
 *  на компьютере — QR-код адреса панели, чтобы открыть её на телефоне. */
function installApp() {
  const P = S.panel || {};
  const phone = matchMedia("(pointer: coarse)").matches;
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  const steps = `<ul class="small" style="margin:0 0 10px;padding-inline-start:20px">
      ${!phone || !ios ? `<li>${esc(t("app.android"))}</li>` : ""}
      ${!phone || ios ? `<li>${esc(t("app.ios"))}</li>` : ""}</ul>`;
  let body;
  if (P.access === "ssh") {
    body = `<p style="margin-top:0">${esc(t("app.ssh"))}</p>`;
  } else if (phone) {
    body = `<p style="margin-top:0">${esc(t("app.what"))}</p>
      ${installPrompt ? "" : `<p class="small" style="margin:0 0 6px">${esc(t("app.how"))}</p>${steps}`}`;
  } else {
    body = `<p style="margin-top:0">${esc(t("app.what"))}</p>
      <div class="connect">
        <div class="qr-box">${qrImage(P.url || location.href)}</div>
        <div><p class="small" style="margin:0 0 6px">${esc(t("app.scan"))}</p>${steps}</div>
      </div>`;
  }
  if (P.access !== "ssh" && (P.tls || {}).active === "selfsigned") body += `<p class="muted small" style="margin:10px 0 0">${esc(t("app.selfsigned"))}</p>`;
  const go = phone && installPrompt && P.access !== "ssh";
  openModal(t("app.title"), body,
    go ? `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="app-install">${esc(t("app.install"))}</button>`
       : `<button class="btn primary" data-close>${esc(t("btn.close"))}</button>`);
  if (go) $("#app-install").onclick = async () => {
    closeModal();
    installPrompt.prompt();
    try { await installPrompt.userChoice; } catch { /* окно закрыли */ }
    installPrompt = null; render();
  };
}

/* ===================================================== обновление панели */
// версия, до которой идёт обновление (переживает перезагрузку страницы и перезапуск панели)
let updatingTo = (() => { try { return sessionStorage.getItem("awgr.updating") || ""; } catch { return ""; } })();
let updLine = "", updLog = [];
function setUpdating(v) {
  updatingTo = v || ""; updLine = "";
  try { if (v) sessionStorage.setItem("awgr.updating", v); else sessionStorage.removeItem("awgr.updating"); } catch { /* нет хранилища */ }
}
function setUpdLine(text) { updLine = text; const el = $("#upd-line"); if (el) el.textContent = text; }
function updState() { return (S && S.version && S.version.update) || { state: "idle" }; }
/** после ответа /api/state: обновление закончилось — перезагрузить страницу (новые скрипты) */
function followUpdate() {
  const u = updState(), v = S.version || {};
  if (!updatingTo && u.state === "running") setUpdating(u.to || v.latest || "…");   // начато в другом окне
  if (!updatingTo) return false;
  if (u.state === "done" || (v.current && v.current === updatingTo)) {
    try { sessionStorage.setItem("awgr.updated", v.current || updatingTo); } catch { /* нет хранилища */ }
    setUpdating("");
    location.reload();
    return true;
  }
  if (u.state === "failed") { setUpdating(""); loadUpdateLog(); return false; }
  api("GET", "update/status").then((r) => {
    const last = (r.log || []).filter((l) => !/^(exit=|Update from the panel)/.test(l)).slice(-1)[0];
    if (last) setUpdLine(last.trim());
  }).catch(() => {});
  return false;
}
async function loadUpdateLog() {
  try { updLog = (await api("GET", "update/status")).log || []; if (tab === "system") render(); } catch { /* панель недоступна */ }
}
function updateNotice() {
  const v = S.version || {}, u = updState();
  if (updatingTo) return "";
  const news = v.latest ? `<a href="https://github.com/r-slashslash/AWG-Router/releases/tag/v${esc(v.latest)}" target="_blank" rel="noopener noreferrer">${esc(t("sy.whats_new"))}</a>` : "";
  if (u.state === "failed" && v.available) {
    const log = updLog.length ? updLog : [];
    return `<div class="notice warn" style="margin:14px 0 0">
      <p style="margin:0 0 8px">${esc(t("sy.update_failed", { version: u.to || v.latest }))}</p>
      ${log.length ? `<details><summary>${esc(t("sy.update_log"))}</summary><pre class="code" dir="ltr">${esc(log.join("\n"))}</pre></details>` : ""}
      <div class="actions" style="margin-top:10px"><button class="btn sm primary" data-update>${esc(t("sy.update_retry"))}</button>
        <span class="small muted">${th("sy.update_cli", { cmd: `<bdi class="mono">awg-router update</bdi>` })}</span></div></div>`;
  }
  if (!v.available) return "";
  return `<div class="notice" style="margin:14px 0 0">
    <p style="margin:0 0 10px">${th("sy.update_available", { version: `<b>${esc(v.latest)}</b>` })} ${news}</p>
    <div class="actions"><button class="btn sm primary" data-update>${esc(t("sy.update_btn"))}</button>
      <span class="small muted">${th("sy.update_cli", { cmd: `<bdi class="mono">awg-router update</bdi>` })}</span></div></div>`;
}
function bindUpdate() {
  const ph = $("#app-phone");
  if (ph) ph.onclick = installApp;
  if (updState().state === "failed" && !updLog.length && (S.version || {}).available) loadUpdateLog();
  $("#upd-check").onclick = async () => {
    const b = $("#upd-check"); b.disabled = true;
    try {
      const r = await api("POST", "update/check", {});
      S.version = { ...S.version, ...r };
      if (r.error) toast(t("sy.check_failed", { error: r.error }), true);
      else if (!r.available) toast(t("sy.up_to_date"));
      render();
    } catch (e) { if (!(e instanceof AuthError)) toast(e.message, true); b.disabled = false; }
  };
  $$("[data-update]").forEach((b) => b.onclick = async () => {
    const v = S.version || {};
    const stop = (S.settings.on_stop || "keep") === "restore" ? "sy.update_confirm_restore" : "sy.update_confirm_keep";
    if (!confirm(t(stop, { version: v.latest || "?", setting: t("sy.on_stop") }))) return;
    b.disabled = true;
    try {
      const r = await api("POST", "update/run", {});
      updLog = [];
      setUpdating(r.to || v.latest || "…");
      render();
    } catch (e) { if (!(e instanceof AuthError)) toast(e.message, true); b.disabled = false; }
  });
}

/* ===================================================== уведомления в Telegram */
const TG_KINDS = ["exit", "server", "clients", "login", "tls", "update"];
function viewTelegram() {
  const c = S.settings.telegram || {};
  const ev = c.events || {};
  return `
  <section class="section">
    <div class="section-head"><div><h2>${esc(t("tg.title"))}</h2><p class="muted small">${esc(t("tg.sub"))}</p></div></div>
    <div class="panel panel-pad">
      <label class="check"><input type="checkbox" id="tg-on" ${c.enabled ? "checked" : ""}><span><b>${esc(t("tg.enable"))}</b></span></label>
      <div class="tg-cols"><div>
      <label class="field"><span>${esc(t("tg.token"))}</span>
        <input type="text" id="tg-token" autocomplete="off" spellcheck="false" dir="ltr"
          placeholder="${esc(c.token_set ? t("tg.token_saved", { hint: c.token_hint }) : "123456789:AA…")}">
        <span class="hint">${th("tg.token_hint", { bot: "<bdi><b>@BotFather</b></bdi>" })}</span></label>
      <div class="field"><span>${esc(t("tg.chat"))}</span>
        <div class="input-btn"><input type="text" id="tg-chat" autocomplete="off" spellcheck="false" dir="ltr" value="${esc(c.chat_id || "")}">
          <button type="button" class="btn sm" id="tg-detect">${esc(t("tg.find"))}</button></div>
        <span class="hint">${esc(t("tg.chat_hint"))}</span></div>
      <label class="field"><span>${esc(t("tg.lang"))}</span>
        <select id="tg-lang" style="max-width:220px">${Object.entries(LANGS).map(([k, v]) =>
          `<option value="${k}" ${k === (c.enabled || c.token_set ? c.lang : LANG) ? "selected" : ""}>${v.name}</option>`).join("")}</select></label>
      <label class="field"><span>${esc(t("tg.via"))}</span>
        <select id="tg-via" style="max-width:320px">${[["direct", t("out.direct")],
          ...S.upstreams.map((u) => ["up:" + u.id, t("out.via", { name: u.name })])].map(([v, l]) =>
          `<option value="${esc(v)}" ${v === (c.via || "direct") ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>
        <span class="hint">${esc(t("tg.via_hint"))}</span></label>
      </div><div class="field"><span>${esc(t("tg.events"))}</span>
        ${TG_KINDS.map((k) => `<label class="check"><input type="checkbox" id="tg-ev-${k}" ${ev[k] !== false ? "checked" : ""}><span>${esc(t("tg.ev_" + k))}</span></label>`).join("")}</div></div>
      <fieldset class="pgroup" style="margin:4px 0 12px"><legend>${esc(t("tg.control_title"))}</legend>
        <label class="check"><input type="checkbox" id="tg-control" ${c.control ? "checked" : ""}><span><b>${esc(t("tg.control"))}</b></span></label>
        <p class="small muted" style="margin:6px 0 0">${esc(t("tg.control_hint"))}</p>
        ${c.control && S.tg_bot ? viewBotState(S.tg_bot) : ""}
      </fieldset>
      <fieldset class="pgroup" style="margin-top:4px"><legend>${esc(t("tg.backup"))}</legend>
        <div class="tg-cols"><div>
          <label class="field"><span>${esc(t("tg.backup_when"))}</span>
            <select id="tg-bk" style="max-width:220px">${["off", "daily", "weekly"].map((k) =>
              `<option value="${k}" ${(c.backup || "off") === k ? "selected" : ""}>${esc(t("tg.backup_" + k))}</option>`).join("")}</select></label>
          <label class="field"><span>${esc(t("tg.backup_pw"))}</span>
            <input type="password" id="tg-bk-pw" autocomplete="new-password" maxlength="128" dir="ltr"
              placeholder="${esc(t(c.backup_pw_set ? "tg.backup_pw_set" : "tg.backup_pw_none"))}"></label>
          ${c.backup_pw_set ? `<label class="check"><input type="checkbox" id="tg-bk-clear"><span>${esc(t("tg.backup_pw_clear"))}</span></label>` : ""}
        </div><div>
          <p class="small muted" style="margin-top:0">${esc(t("tg.backup_hint"))}</p>
          ${c.backup_error ? `<p class="err small">${esc(t("tg.backup_failed", { error: tm(c.backup_error) }))}</p>`
            : c.backup_last ? `<p class="small">${esc(t("tg.backup_last", { time: fmtDay(c.backup_last) + ", " + fmtTime(c.backup_last) }))}</p>` : ""}
          <button type="button" class="btn sm" id="tg-bk-send">${esc(t("tg.backup_send"))}</button>
        </div></div>
      </fieldset>
      ${c.enabled && S.notify_error ? `<p class="err small">${esc(t("tg.last_error"))}: <bdi>${esc(tm(S.notify_error))}</bdi></p>` : ""}
      <div class="actions"><button class="btn sm primary" id="tg-save">${esc(t("btn.save"))}</button><button class="btn sm" id="tg-test">${esc(t("tg.test"))}</button></div>
    </div>
  </section>`;
}
/* Состояние бота-пульта: слушает ли и когда была последняя команда */
function viewBotState(b) {
  const out = [];
  if (b.state === "error") out.push(`<p class="err small">${esc(t("tg.bot_error"))}: <bdi>${esc(tm(b.error))}</bdi></p>`);
  else if (b.state === "ok") out.push(`<p class="small"><span class="dot ok"></span> ${esc(t("tg.bot_ok"))}</p>`);
  if (b.last) out.push(`<p class="small muted">${esc(t("tg.bot_last", { time: fmtDay(b.last) + ", " + fmtTime(b.last) }))}</p>`);
  if (b.skew) out.push(`<p class="small muted">${esc(t("tg.bot_skew", { n: Math.round(Math.abs(b.skew) / 60) || 1 }))}</p>`);
  return out.join("");
}
function bindTelegram() {
  const body = () => {
    const events = {};
    TG_KINDS.forEach((k) => { events[k] = $("#tg-ev-" + k).checked; });
    return { enabled: $("#tg-on").checked, token: $("#tg-token").value.trim(),
      chat_id: $("#tg-chat").value.trim(), lang: $("#tg-lang").value, via: $("#tg-via").value, events,
      control: $("#tg-control").checked,
      backup: $("#tg-bk").value, backup_pw: $("#tg-bk-pw").value,
      backup_pw_clear: !!($("#tg-bk-clear") && $("#tg-bk-clear").checked) };
  };
  const busy = (id, fn) => async () => {
    const b = $(id); b.disabled = true;
    try { await fn(); } catch (e) { if (!(e instanceof AuthError)) toast(e.message, true); }
    b.disabled = false;
  };
  $("#tg-save").onclick = busy("#tg-save", async () => {
    await api("PUT", "telegram", body());
    toast(t("tg.saved"));
    refresh();
  });
  $("#tg-test").onclick = busy("#tg-test", async () => {
    await api("POST", "telegram/test", body());
    toast(t("tg.test_ok"));
  });
  $("#tg-bk-send").onclick = busy("#tg-bk-send", async () => {
    await api("POST", "telegram/backup", body());
    toast(t("tg.backup_sent"));
    refresh();
  });
  $("#tg-detect").onclick = busy("#tg-detect", async () => {
    const r = await api("POST", "telegram/detect", { token: $("#tg-token").value.trim(), via: $("#tg-via").value });
    $("#tg-chat").value = r.id;
    toast(t("tg.found", { name: r.title || r.id }));
  });
}

/* ======================================================= вход по коду (2FA) */
function viewSecurity() {
  const on = !!(S.security && S.security.totp);
  const hours = (S.security && S.security.session_hours) || 4;
  return `
  <section class="section">
    <div class="section-head"><h2>${esc(t("sec.title"))}</h2></div>
    <div class="panel panel-pad">
      <div class="kv" style="margin-bottom:14px">
        <div><span>${esc(t("sec.session"))}</span><b>${esc(t("sec.session_val", { n: hours }))}</b></div>
        <div><span>${esc(t("sec.totp"))}</span><b><span class="state"><span class="dot ${on ? "ok" : ""}"></span>${esc(t(on ? "sec.on" : "sec.off"))}</span></b></div>
      </div>
      <p class="muted small" style="margin-top:0">${esc(t(on ? "sec.on_hint" : "sec.off_hint"))}</p>
      <div class="actions"><button class="btn sm ${on ? "" : "primary"}" id="totp-btn">${esc(t(on ? "sec.disable" : "sec.enable"))}</button></div>
      ${on ? `<p class="muted small" style="margin:12px 0 0">${th("sec.lost", { cmd: `<bdi class="mono">awg-router 2fa-off</bdi>` })}</p>` : ""}
      <div class="manage-row" style="margin-top:16px">
        <div><b>${esc(t("pw.title"))}</b><div class="small muted">${th("pw.hint", { cmd: `<bdi class="mono">awg-router password</bdi>` })}</div></div>
        <button class="btn sm" id="pw-btn" style="flex:none">${esc(t("pw.change"))}</button>
      </div>
    </div>
  </section>`;
}
function codeField(id, label) {
  return `<label class="field"><span>${esc(label)}</span>
    <input type="text" id="${id}" class="code-input" inputmode="numeric" autocomplete="one-time-code" maxlength="7" dir="ltr"></label>`;
}
function bindSecurity() {
  const on = !!(S.security && S.security.totp);
  $("#totp-btn").onclick = on ? totpDisable : totpEnable;
  $("#pw-btn").onclick = changePassword;
}
function changePassword() {
  const f = (id, key, ac) => `<label class="field"><span>${esc(t(key))}</span><input type="password" id="${id}" autocomplete="${ac}" maxlength="128"></label>`;
  openModal(t("pw.title"), `
    ${f("pw-cur", "pw.current", "current-password")}
    ${f("pw-new", "pw.new", "new-password")}
    ${f("pw-new2", "pw.repeat", "new-password")}
    <p class="muted small" style="margin:0">${esc(t("pw.rules"))}</p>`,
  `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="pw-ok">${esc(t("pw.change"))}</button>`);
  $("#pw-cur").focus();
  $("#pw-ok").onclick = async () => {
    const cur = $("#pw-cur").value, nw = $("#pw-new").value;
    if (nw.length < 10) { toast(t("err.pw_length"), true); $("#pw-new").focus(); return; }
    if (nw !== $("#pw-new2").value) { toast(t("pw.mismatch"), true); $("#pw-new2").focus(); return; }
    $("#pw-ok").disabled = true;
    try { await api("POST", "password", { current: cur, new: nw }); closeModal(); toast(t("pw.done")); refresh(); }
    catch (e) { if (!(e instanceof AuthError)) toast(e.message, true); $("#pw-ok").disabled = false; }
  };
}

/* ====================================================== резервная копия */
function viewBackup() {
  return `
  <section class="section">
    <div class="section-head"><h2>${esc(t("bk.title"))}</h2></div>
    <div class="panel panel-pad">
      <p class="small" style="margin:0 0 14px">${esc(t("bk.sub"))}</p>
      <div class="actions">
        <button class="btn sm primary" id="bk-save">${esc(t("bk.download"))}</button>
        <label class="btn sm" for="bk-file">${esc(t("bk.restore"))}</label>
        <input type="file" id="bk-file" accept=".json,.enc,application/json" hidden>
      </div>
      <p class="muted small" style="margin:12px 0 0">${esc(t("bk.secret"))}</p>
    </div>
  </section>`;
}
function bindBackup() {
  $("#bk-save").onclick = saveBackup;
  $("#bk-file").onchange = async (ev) => {
    const file = ev.target.files[0];
    ev.target.value = "";
    if (!file) return;
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (String.fromCharCode(...bytes.slice(0, 8)) === "Salted__") { decryptBackup(bytes); return; }
    let b;
    try { b = JSON.parse(new TextDecoder().decode(bytes)); } catch { toast(t("err.backup_format"), true); return; }
    showRestore(b);
  };
}
/** «Скачать копию»: пароль необязателен; с ним файл шифруется на сервере (как копии в Telegram) */
function saveBackup() {
  const f = (id, key) => `<label class="field"><span>${esc(t(key))}</span><input type="password" id="${id}" autocomplete="new-password" maxlength="128" dir="ltr"></label>`;
  openModal(t("bk.download"), `
    <p style="margin-top:0">${esc(t("bk.pw_hint"))}</p>
    ${f("bk-pw1", "bk.pw")}
    ${f("bk-pw2", "bk.pw_repeat")}
    <p class="muted small" style="margin:0">${esc(t("bk.pw_rules"))}</p>`,
  `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="bk-go">${esc(t("bk.download"))}</button>`);
  $("#bk-pw1").focus();
  const go = async () => {
    const pw = $("#bk-pw1").value;
    if (pw && pw.length < 8) { toast(t("bk.pw_short"), true); $("#bk-pw1").focus(); return; }
    if (pw !== $("#bk-pw2").value) { toast(t("bk.pw_mismatch"), true); $("#bk-pw2").select(); return; }
    $("#bk-go").disabled = true;
    try {
      const host = (S.panel && S.panel.host) || "";
      const d = new Date();
      const day = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      const name = (h) => `awg-router-backup-${(h || "server").replace(/[^\w.-]+/g, "_")}-${day}.json`;
      if (pw) {
        const r = await api("POST", "backup/encrypted", { password: pw });
        const bin = atob(r.data), bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        download(name(r.host || host) + ".enc", bytes);
        toast(t("bk.saved_enc"));
      } else {
        const b = await api("GET", "backup");
        download(name(b.host), JSON.stringify(b, null, 1));
        toast(t("bk.saved"));
      }
      closeModal();
    } catch (e) { if (!(e instanceof AuthError)) toast(e.message, true); $("#bk-go").disabled = false; }
  };
  $("#bk-go").onclick = go;
  $$("#bk-pw1, #bk-pw2").forEach((el) => el.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); go(); } });
}
/** копия, зашифрованная паролем (из Telegram или скачанная с паролем): пароль → сервер расшифровывает → обычное восстановление */
function decryptBackup(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const data = btoa(bin);
  openModal(t("bk.enc_title"), `
    <p style="margin-top:0">${esc(t("bk.enc_hint"))}</p>
    <label class="field"><span>${esc(t("tg.backup_pw"))}</span><input type="password" id="bk-pw" autocomplete="off" maxlength="128" dir="ltr"></label>`,
  `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="bk-open">${esc(t("bk.open"))}</button>`);
  $("#bk-pw").focus();
  const go = async () => {
    $("#bk-open").disabled = true;
    try {
      const r = await api("POST", "backup/decrypt", { data, password: $("#bk-pw").value });
      closeModal(); showRestore(r.backup);
    } catch (e) { if (!(e instanceof AuthError)) toast(e.message, true); $("#bk-open").disabled = false; $("#bk-pw").select(); }
  };
  $("#bk-open").onclick = go;
  $("#bk-pw").onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); go(); } };
}
function showRestore(b) {
  if (!b || b.format !== "awg-router-backup") { toast(t("err.backup_format"), true); return; }
  const st = b.state || {};
  const srv = b.server && b.server.files ? b.server : null;
  const sameKind = srv && S.target && srv.kind === S.target.kind;
  const nClients = srv ? ((srv.files.clientsTable || "").match(/"clientId"/g) || []).length : 0;
  openModal(t("bk.restore_title"), `
    <div class="kv" style="margin-bottom:14px">
      <div><span>${esc(t("bk.created"))}</span><b>${esc(b.created ? fmtDay(b.created) + ", " + new Date(b.created * 1000).toLocaleTimeString(LANG, { hour: "2-digit", minute: "2-digit" }) : "—")}</b></div>
      <div><span>${esc(t("bk.from"))}</span><b><bdi>${esc(b.host || "—")}</bdi></b></div>
      <div><span>${esc(t("tab.exits"))}</span><b>${esc(fmtNum((st.upstreams || []).length))}</b></div>
      <div><span>${esc(t("tab.lists"))}</span><b>${esc(fmtNum((st.lists || []).length))}</b></div>
    </div>
    <p style="margin-top:0">${esc(t("bk.restore_what"))}</p>
    <label class="check"><input type="checkbox" id="bk-srv" ${sameKind ? "checked" : "disabled"}>
      <span>${esc(t("bk.restore_server", { n: nClients }))}<br><span class="small muted">${esc(t(!srv ? "bk.no_server" : sameKind ? "bk.restore_server_hint" : "bk.kind_differs"))}</span></span></label>
    <div class="notice warn" style="margin:12px 0 0">${esc(t("bk.warn"))}</div>`,
  `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="bk-go">${esc(t("bk.restore_btn"))}</button>`);
  $("#bk-go").onclick = async () => {
    $("#bk-go").disabled = true;
    try {
      const r = await api("POST", "restore", { backup: b, server: $("#bk-srv").checked });
      closeModal(); toast(t(r.restarted ? "bk.done_server" : "bk.done")); setTimeout(refresh, 1500);
    } catch (e) { if (!(e instanceof AuthError)) toast(e.message, true); $("#bk-go").disabled = false; }
  };
}
function modalAction(btnId, inputId, fn) {
  const go = async () => {
    const code = $("#" + inputId).value.replace(/\D/g, "");
    if (code.length !== 6) { $("#" + inputId).focus(); return; }
    $("#" + btnId).disabled = true;
    try { await fn(code); }
    catch (e) {
      if (!(e instanceof AuthError)) toast(e.message, true);
      $("#" + btnId).disabled = false;
      $("#" + inputId).value = ""; $("#" + inputId).focus();
    }
  };
  $("#" + btnId).onclick = go;
  $("#" + inputId).onkeydown = (e) => { if (e.key === "Enter") go(); };
  $("#" + inputId).focus();
}
async function totpEnable() {
  let r;
  try { r = await api("POST", "totp/setup", {}); } catch (e) { if (!(e instanceof AuthError)) toast(e.message, true); return; }
  const key = r.secret.replace(/(.{4})/g, "$1 ").trim();
  openModal(t("sec.enable_title"), `
    <p style="margin-top:0">${esc(t("sec.off_hint"))}</p>
    <div class="connect">
      <div class="qr-box">${qrImage(r.uri)}</div>
      <div>
        <p style="margin-top:0"><b>1.</b> ${esc(t("sec.step1"))}</p>
        <p class="muted small" style="margin-bottom:4px">${esc(t("sec.manual"))}</p>
        <p class="mono" dir="ltr" style="margin:0 0 6px;word-break:break-all">${esc(key)}</p>
        <button type="button" class="btn sm" id="totp-copy">${esc(t("sec.copy_key"))}</button>
        <p style="margin-bottom:6px"><b>2.</b> ${esc(t("sec.step2"))}</p>
        ${codeField("totp-code", t("sec.code"))}
      </div>
    </div>`,
  `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="totp-ok">${esc(t("sec.enable"))}</button>`);
  $("#totp-copy").onclick = () => copyText(r.secret);
  modalAction("totp-ok", "totp-code", async (code) => {
    await api("POST", "totp/enable", { code });
    closeModal();
    toast(t("sec.enabled_toast"));
    refresh();
  });
}
function totpDisable() {
  openModal(t("sec.disable_title"), `
    <p style="margin-top:0">${esc(t("sec.disable_hint"))}</p>
    ${codeField("totp-code", t("sec.code"))}`,
  `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn danger" id="totp-ok">${esc(t("sec.disable"))}</button>`);
  modalAction("totp-ok", "totp-code", async (code) => {
    await api("POST", "totp/disable", { code });
    closeModal();
    toast(t("sec.disabled_toast"));
    refresh();
  });
}

/* ================================================================ модалка */
function openModal(title, body, foot) {
  const m = $("#modal");
  $("#modal-body").innerHTML = `<div class="modal-head"><h2>${esc(title)}</h2><button class="icon-btn" data-close aria-label="${esc(t("btn.close"))}">✕</button></div>
    <div class="modal-body">${body}</div><div class="modal-foot">${foot}</div>`;
  $$("[data-close]", m).forEach((b) => b.onclick = closeModal);
  m.showModal();
}
function closeModal() { $("#modal").close(); }
$("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });
$("#modal").addEventListener("close", () => { if (tab !== "routing") render(); });

window.addEventListener("beforeunload", (e) => { if (routingDirty()) { e.preventDefault(); e.returnValue = ""; } });
applyStaticTexts();
boot();
