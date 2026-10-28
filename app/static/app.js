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
  return l.kind === "country" ? countryName(l.source) : l.source;
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
function outOptions(selected, { inherit = null, exclude = null } = {}) {
  const opts = [];
  if (inherit !== null) opts.push(["inherit", inherit]);
  opts.push(["direct", t("out.direct")]);
  for (const u of S.upstreams) if ("up:" + u.id !== exclude) opts.push(["up:" + u.id, t("out.via", { name: u.name })]);
  opts.push(["block", t("out.block")]);
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
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#login-pass").focus();
}
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-err").hidden = true;
  try {
    await api("POST", "login", { password: $("#login-pass").value });
    $("#login-pass").value = "";
    boot();
  } catch (err) {
    $("#login-err").textContent = err.message;
    $("#login-err").hidden = false;
  }
});

/* ================================================================ каркас */
async function refresh(auto = false) {
  try {
    S = await api("GET", "state");
  } catch (e) {
    if (!(e instanceof AuthError)) toast(t("panel.offline", { e: e.message }), true);
    return;
  }
  renderStatus();
  // при фоновом опросе не трогаем вкладки с формами и результатами проверок
  if (auto && !["overview", "clients", "exits"].includes(tab)) return;
  if (auto && $("#modal").open) return;
  render();
}

async function boot() {
  $("#login").hidden = true;
  await refresh();
  if (!S) return;
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

function renderStatus() {
  const tg = S.target;
  const online = S.clients.filter((c) => c.live && c.live.handshake && S.now - c.live.handshake < 180).length;
  $("#status").innerHTML = tg
    ? `<span class="state"><span class="dot ${tg.exists === false ? "warn" : "ok"}"></span><b>${esc(tg.kind === "host" ? t("srv.kind_host") : tg.container)}</b> · ${esc(tg.iface)}</span>
       <span>${esc(t("n.clients", { n: S.clients.length }) + sep("phrase") + t("status.online", { n: online }))}</span>
       <span>${esc(t("status.applied", { time: fmtTime(S.engine.last_apply) }))}</span>`
    : `<span class="state"><span class="dot bad"></span>${esc(t("status.no_target"))}</span>`;
  $$("#tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === tab));
}

function render() {
  const views = { overview: viewOverview, clients: viewClients, exits: viewExits, routing: viewRouting, lists: viewLists, server: viewServer, system: viewSystem };
  if (tab === "routing" && routingDraft && $("#g-rules")) return; // не мешаем правке
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
      <div class="track-rail"></div>
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
    const dead = !u.enabled || !h.healthy;
    const na = assigned["up:" + u.id] || 0;
    const meta = [
      `<span><bdi>${esc(u.endpoint || "")}</bdi></span>`,
      h.healthy ? `<span>${esc(t("ov.handshake", { ago: fmtAge(h.handshake_age) }))}</span>` : "",
      h.rx != null && u.enabled ? `<span>↓ ${esc(fmtBytes(h.rx))} ↑ ${esc(fmtBytes(h.tx))}</span>` : "",
      dead ? `<span>${esc(na ? t("ov.assigned_now", { n: na }) : t("ov.traffic_goes"))} ${effChip(u.effective)}</span>` : "",
    ].join("");
    lines += track(dead ? "dead" : "", lineVar(u), `<h3><bdi>${esc(u.name)}</bdi></h3>${stateBadge(u)}`, meta,
      countHtml(u.num) + (u.enabled ? probeSide("up:" + u.id) : ""));
  }
  lines += track("direct", "var(--direct)", `<h3>${esc(t("out.direct"))}</h3><span class="muted small">${esc(t("ov.direct_sub"))}</span>`,
    "", countHtml("direct") + probeSide("direct"));
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
  <div class="grid2">
    <section class="section">
      <div class="section-head"><div><h2>${esc(t("ov.title"))}</h2><p class="muted small">${esc(t("ov.subtitle"))}</p></div>
        <button class="btn" data-goto="exits">${esc(t("ov.add_exit"))}</button></div>
      <div class="map"><div class="map-hub"><bdi>${esc(S.target ? S.target.container : "—")}</bdi></div><div class="map-lines">${lines}</div></div>
    </section>
    <section class="section">
      <div class="panel panel-pad" style="margin-bottom:20px">
        <div class="section-head" style="margin-bottom:8px"><h3>${esc(t("ov.policy"))}</h3><button class="btn sm" data-goto="routing">${esc(t("btn.edit"))}</button></div>
        ${rulesSummary(S.routing.rules)}
        <div style="margin-top:10px">${th("ov.everything_else", { exit: effChip(S.global_effective, S.routing.default) })}</div>
      </div>
      <div class="panel panel-pad"><h3 style="margin-bottom:6px">${esc(t("ov.log"))}</h3>${ev}</div>
    </section>
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
        ${S.clients.length ? `<input type="search" id="client-search" placeholder="${esc(t("cl.search"))}" style="max-width:240px">` : ""}
        <button class="btn primary" id="add-client" ${serverMissing() || !S.target ? "disabled" : ""}>${esc(t("cl.add"))}</button>
      </div>
    </div>`;
  if (serverMissing()) return `<section class="section">${head}<div class="panel empty"><p>${esc(t("srv.missing"))}</p><button class="btn primary" data-goto="server">${esc(t("srv.create_title"))}</button></div></section>`;
  if (!S.clients.length) return `<section class="section">${head}<div class="panel empty"><p>${esc(t("cl.empty"))}</p><p class="small">${esc(t("cl.empty_hint2"))}</p></div></section>`;
  const rows = S.clients.map((c) => {
    const live = c.live || {};
    const age = live.handshake ? S.now - live.handshake : null;
    const online = c.enabled && age != null && age < 180;
    const p = c.policy;
    const tags = (!c.enabled ? `<span class="tag tag-off">${esc(t("cl.disabled_tag"))}</span>` : "") +
      (p.rules_mode === "custom" ? `<span class="tag">${esc(t("cl.custom_tag"))}</span>` : "") +
      (p.note ? `<span class="tag"><bdi>${esc(p.note)}</bdi></span>` : "");
    const wanted = p.outbound !== "inherit" ? p.outbound : S.routing.default;
    const activity = !c.enabled ? `<span class="muted">—</span>`
      : `<span class="state"><span class="dot ${online ? "ok" : ""}"></span>${esc(online ? t("cl.online") : fmtAge(age))}</span>`;
    return `<tr class="click ${c.enabled ? "" : "row-off"}" data-pk="${esc(c.public_key)}" data-q="${esc((c.name + " " + c.ip + " " + p.note).toLowerCase())}">
      <td><span class="client-name"><bdi>${esc(c.name || t("cl.unnamed"))}</bdi></span>${tags}</td>
      <td data-m="sub" class="nowrap"><bdi>${esc(c.ip || "—")}</bdi></td>
      <td data-m="sub">${activity}</td>
      <td data-m="hide" class="nowrap muted">↓ ${esc(fmtBytes(live.tx))} ↑ ${esc(fmtBytes(live.rx))}</td>
      <td data-m="right">${effChip(c.effective, wanted)}${p.outbound === "inherit" ? "" : `<div class="small muted" style="margin-top:3px">${esc(t("cl.manual"))}</div>`}</td>
    </tr>`;
  }).join("");
  return `
  <section class="section">${head}
    <div class="panel"><table class="table responsive">
      <thead><tr><th>${esc(t("cl.col_name"))}</th><th>${esc(t("cl.col_ip"))}</th><th>${esc(t("cl.col_activity"))}</th><th>${esc(t("cl.col_traffic"))}</th><th>${esc(t("cl.col_exit"))}</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </section>`;
}
function filterClients() {
  const q = ($("#client-search").value || "").toLowerCase().trim();
  $$("tr[data-q]").forEach((tr) => tr.hidden = q && !tr.dataset.q.includes(q));
}
bind.clients = () => {
  const s = $("#client-search");
  if (s) s.oninput = filterClients;
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

function qrSvg(text) {
  qrcode.stringToBytes = qrcode.stringToBytesFuncs["UTF-8"];
  let qr = null;
  for (const lvl of ["M", "L"]) {
    try { qr = qrcode(0, lvl); qr.addData(text, "Byte"); qr.make(); break; } catch { qr = null; }
  }
  if (!qr) return `<p class="muted small">${esc(t("cl.qr_too_big"))}</p>`;
  const n = qr.getModuleCount(), m = 4;
  let d = "";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) d += `M${c + m},${r + m}h1v1h-1z`;
  return `<svg class="qr" viewBox="0 0 ${n + 2 * m} ${n + 2 * m}" role="img" aria-label="QR" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}

function download(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
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
  openModal(c.name || c.ip, `
    <p class="muted small" style="margin-top:0"><bdi>${esc(c.ip || "")}</bdi> · ${esc(t("cl.key"))} <span class="mono">${esc(pk.slice(0, 10))}…</span>${c.enabled ? "" : ` · <span class="err">${esc(t("cl.disabled_tag"))}</span>`}</p>
    <div class="seg seg-wide" id="c-view">
      <button type="button" data-v="connect">${esc(t("cl.v_connect"))}</button>
      <button type="button" data-v="route">${esc(t("cl.v_route"))}</button>
      <button type="button" data-v="manage">${esc(t("cl.v_manage"))}</button>
    </div>
    <div id="c-pane-connect" class="c-pane"></div>
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

  const loadConnect = async () => {
    const box = $("#c-pane-connect");
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
          <div class="qr-box">${qrSvg(cfg.conf)}</div>
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
    if (view === "connect" && !$("#c-pane-connect").dataset.loaded) { $("#c-pane-connect").dataset.loaded = 1; loadConnect(); }
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
      await api("PUT", "clients/" + encodeURIComponent(pk), {
        outbound: $("#c-out").value, rules_mode: draft.rules_mode,
        rules: draft.rules_mode === "custom" ? draft.rules : [], note: $("#c-note").value.trim() });
      closeModal(); toast(t("toast.saved_applying")); refresh();
    } catch (e) { toast(e.message, true); }
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
function rulesEditor(box, rules, onChange) {
  const draw = () => {
    const items = rules.map((r, i) => `
      <div class="rule ${r.enabled ? "" : "off"}" data-i="${i}">
        <div class="rule-n">${esc(fmtNum(i + 1))}</div>
        <div>
          <div class="rule-lists">
            ${r.lists.map((l) => `<span class="chip"><bdi>${esc(listName(l))}</bdi><button type="button" data-rm-list="${esc(l)}" aria-label="${esc(t("re.remove_list"))}">×</button></span>`).join("")}
            <select class="add-list" data-add-list aria-label="${esc(t("re.add_list"))}"><option value="">${esc(t("re.add_list"))}</option>${S.lists.filter((l) => !r.lists.includes(l.id)).map((l) => `<option value="${esc(l.id)}">${esc(listName(l.id))}</option>`).join("")}</select>
          </div>
          <input type="text" class="rule-comment" data-comment value="${esc(r.comment || "")}" placeholder="${esc(t("re.comment_ph"))}" maxlength="80">
        </div>
        <div class="rule-then"><label>${esc(t("re.then"))}</label><select data-out>${outOptions(r.outbound)}</select></div>
        <div class="rule-ctl">
          <label class="switch" title="${esc(t("re.enabled"))}"><input type="checkbox" data-en ${r.enabled ? "checked" : ""} aria-label="${esc(t("re.enabled"))}"><span></span></label>
          <button class="icon-btn" type="button" data-up ${i === 0 ? "disabled" : ""} aria-label="${esc(t("re.up"))}">↑</button>
          <button class="icon-btn" type="button" data-down ${i === rules.length - 1 ? "disabled" : ""} aria-label="${esc(t("re.down"))}">↓</button>
          <button class="icon-btn" type="button" data-del aria-label="${esc(t("re.delete"))}">✕</button>
        </div>
      </div>`).join("");
    box.innerHTML = `<div class="rules">${items || `<p class="muted small" style="margin:0 0 4px">${esc(t("re.none"))}</p>`}</div>
      <button class="btn sm" type="button" data-add style="margin-top:8px">${esc(t("re.add"))}</button>`;
    $$(".rule", box).forEach((el) => {
      const i = +el.dataset.i, r = rules[i];
      const ch = () => { onChange(); draw(); };
      $$("[data-rm-list]", el).forEach((b) => b.onclick = () => { r.lists = r.lists.filter((x) => x !== b.dataset.rmList); ch(); });
      $("[data-add-list]", el).onchange = (e) => { if (e.target.value) { r.lists.push(e.target.value); ch(); } };
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
  rulesEditor($("#g-rules"), draft.rules, upd);
  upd();
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
    if (u.enabled && h.healthy) st = `<span class="state"><span class="dot ok"></span>${esc(t("ex.working", { ago: fmtAge(h.handshake_age) }))}</span>`;
    else if (u.enabled && h.state === "error") st = `<span class="state"><span class="dot bad"></span>${esc(tm(h.error) || t("st.error"))}</span>`;
    else if (u.enabled && h.handshake_age) st += ` <span class="muted small">${esc(t("ex.last_handshake", { ago: fmtAge(h.handshake_age) }))}</span>`;
    const ver = u.version ? `AWG ${u.version}` : u.config_error ? "" : "WireGuard";
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
          <div><span>${esc(t("ex.address"))}</span><b><bdi>${esc(u.address || "—")}</bdi></b></div>
          <div><span>${esc(t("ex.traffic"))}</span><b>↓ ${esc(fmtBytes(h.rx))} ↑ ${esc(fmtBytes(h.tx))}</b></div>
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
  return `
  <section class="section">
    <div class="section-head">
      <div><h2>${esc(t("ex.title"))}</h2><p class="muted small">${esc(t("ex.subtitle"))}</p></div>
      <button class="btn primary" id="add-up">${esc(t("ov.add_exit"))}</button>
    </div>
    ${cards || `<div class="panel empty"><p>${esc(t("ex.empty"))}</p><p class="small">${esc(t("ex.empty_hint"))}</p><button class="btn primary" data-add-empty>${esc(t("ov.add_exit"))}</button></div>`}
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
  $$("[data-del]").forEach((b) => b.onclick = async () => {
    const u = upstreamById(b.dataset.del);
    if (!confirm(t("ex.delete_confirm", { name: u.name }))) return;
    try { await api("DELETE", "upstreams/" + u.id); toast(t("toast.exit_deleted")); refresh(); }
    catch (err) { toast(err.message, true); }
  });
};

async function editUpstream(id) {
  const u = id ? upstreamById(id) : null;
  let conf = "";
  if (u) { try { conf = (await api("GET", `upstreams/${id}/config`)).config; } catch (e) { toast(e.message, true); return; } }
  openModal(u ? t("ex.modal_title", { name: u.name }) : t("ex.new"), `
    <label class="field"><span>${esc(t("ex.name"))}</span><input type="text" id="u-name" maxlength="40" value="${esc(u ? u.name : "")}" placeholder="${esc(t("ex.name_ph"))}"></label>
    <label class="field"><span>${esc(t("ex.config"))}</span>
      <textarea id="u-conf" dir="ltr" spellcheck="false" placeholder="${esc(t("ex.config_ph"))}">${esc(conf)}</textarea>
      <span class="hint">${esc(t("ex.config_hint"))}</span>
    </label>
    <div class="field"><input type="file" id="u-file" accept=".conf,.txt,.vpn" aria-label="${esc(t("ex.file"))}"></div>
    <label class="field"><span>${esc(t("ex.fallback"))}</span>
      <select id="u-fb">${outOptions(u ? u.fallback : "direct", { exclude: u ? "up:" + u.id : null })}</select>
      <span class="hint">${esc(t("ex.fallback_hint"))}</span>
    </label>
    ${u ? "" : `<label class="check"><input type="checkbox" id="u-def" ${S.routing.default === "direct" ? "checked" : ""}><span>${esc(t("ex.make_default"))}</span></label>`}
  `, `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="u-save">${esc(t(u ? "btn.save" : "btn.add"))}</button>`);
  $("#u-file").onchange = async (e) => {
    const f = e.target.files[0]; if (!f) return;
    $("#u-conf").value = (await f.text()).trim();
    if (!$("#u-name").value) $("#u-name").value = f.name.replace(/\.(conf|txt|vpn)$/i, "").slice(0, 40);
  };
  $("#u-save").onclick = async () => {
    const body = { name: $("#u-name").value.trim(), fallback: $("#u-fb").value };
    const c = $("#u-conf").value.trim();
    if (!u || c !== conf.trim()) body.config = c;
    try {
      if (u) await api("PUT", "upstreams/" + u.id, body);
      else await api("POST", "upstreams", { ...body, make_default: $("#u-def").checked });
      closeModal(); toast(t(u ? "toast.exit_saved" : "toast.exit_added"));
      refresh();
    } catch (e) { toast(e.message, true); }
  };
}

/* ================================================================ списки */
function viewLists() {
  const rows = S.lists.map((l) => {
    const badge = l.kind === "country" ? `<span class="cc">${esc(l.source.toUpperCase())}</span>`
      : l.kind === "asn" ? `<span class="cc">AS</span>` : "";
    const src = l.kind === "url" || (l.kind === "asn" && l.name !== l.source) ? `<bdi>${esc(l.source)}</bdi>` : esc(t("ls.kind." + l.kind));
    return `
    <tr>
      <td>${badge}<b><bdi>${esc(listName(l.id))}</bdi></b><div class="list-row-src">${src}</div></td>
      <td data-m="sub">${l.count ? `${esc(t("n.networks", { n: l.count }))}<div class="small muted">${esc(t("n.addresses", { n: l.addresses, nText: fmtCompact(l.addresses) }))}</div>` : `<span class="muted">${esc(t("ls.not_loaded"))}</span>`}
        ${l.error ? `<div class="err small">${esc(tm(l.error))}</div>` : ""}</td>
      <td data-m="hide" class="small muted">${l.updated ? esc(t("ls.updated", { time: fmtTime(l.updated) })) : "—"}${l.refs.length ? `<div>${esc(t("n.in_rules", { n: l.refs.length }))}</div>` : ""}</td>
      <td data-m="right" class="nowrap acts">
        ${l.kind !== "manual" ? `<button class="icon-btn" data-refresh="${esc(l.id)}" title="${esc(t("ls.refresh"))}" aria-label="${esc(t("ls.refresh"))}">⟳</button>` : ""}
        ${l.kind !== "country" ? `<button class="icon-btn" data-edit-list="${esc(l.id)}" title="${esc(t("btn.edit"))}" aria-label="${esc(t("btn.edit"))}">✎</button>` : ""}
        <button class="icon-btn" data-del-list="${esc(l.id)}" title="${esc(t("btn.delete"))}" aria-label="${esc(t("btn.delete"))}">✕</button>
      </td>
    </tr>`;
  }).join("");
  return `
  <section class="section">
    <div class="section-head">
      <div><h2>${esc(t("ls.title"))}</h2><p class="muted small">${esc(t("ls.subtitle", { hours: fmtNum(S.settings.list_update_hours) }))}</p></div>
      <div class="add-row">${["country", "asn", "url", "manual"].map((k) => `<button class="btn" data-add-kind="${k}">${esc(t("ls.add_" + k))}</button>`).join("")}</div>
    </div>
    <div class="panel">${S.lists.length ? `<table class="table responsive"><thead><tr><th>${esc(t("ls.col_list"))}</th><th>${esc(t("ls.col_size"))}</th><th>${esc(t("ls.col_updated"))}</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="empty"><p>${esc(t("ls.empty"))}</p></div>`}</div>
  </section>`;
}
bind.lists = () => {
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
};
function editList(id, kind) {
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
  } else {
    body = nameField(t("ls.manual_ph")) + `<label class="field"><span>${esc(t("ls.cidrs"))}</span><textarea id="l-src" dir="ltr" placeholder="203.0.113.0/24&#10;198.51.100.7">${esc(l ? l.source : "")}</textarea>
      <span class="hint">${esc(t("ls.cidrs_hint"))}</span></label>`;
  }
  const title = l ? t("ls.edit", { name: listName(l.id) }) : t("ls.new." + kind);
  openModal(title, body, `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="l-save">${esc(t(l ? "btn.save" : "btn.add"))}</button>`);
  $("#l-save").onclick = async (e) => {
    const b = { kind, source: $("#l-src").value.trim() };
    if ($("#l-name")) b.name = $("#l-name").value.trim();
    const label = e.target.textContent;
    e.target.disabled = true; e.target.textContent = t("ls.loading");
    try {
      const r = l ? await api("PUT", "lists/" + l.id, b) : await api("POST", "lists", b);
      closeModal();
      await refresh();
      if (r && r.error) toast(t("ls.saved_failed", { e: tm(r.error) }), true);
      else toast(t("ls.saved", { name: listName(r.id), count: t("n.networks", { n: r.count || 0 }) }));
    } catch (err) { toast(err.message, true); e.target.disabled = false; e.target.textContent = label; }
  };
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
    return `<label class="field param ${meta.type === "text" || meta.type === "key" ? "param-wide" : ""}"><span>${esc(k)} ${side}</span>${input}<span class="hint">${esc(t("p." + k))}</span></label>`;
  };
  return `
  <div class="grid2">
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
          <label class="field"><span>${esc(t("srv.subnet"))}</span><input type="text" id="s-addr" dir="ltr" value="${esc(SRV.address)}" ${SRV.subnet_locked ? "disabled" : ""}><span class="hint">${esc(t(SRV.subnet_locked ? "srv.subnet_locked_hint" : "srv.subnet_hint"))}</span></label>
        </div>
      </div>
    </section>
    <section class="section">
      <div class="section-head"><h2>${esc(t("srv.clients_title"))}</h2></div>
      <div class="panel panel-pad">
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
      ${PARAM_GROUPS.map(([g, keys]) => `<fieldset class="pgroup"><legend>${esc(t(g))}</legend><div class="pgrid">${keys.map(param).join("")}</div></fieldset>`).join("")}
    </div>
    <div class="savebar" id="s-bar" ${srvDirty() ? "" : "hidden"}><span id="s-bar-text">${esc(t("srv.save_hint"))}</span>
      <span class="actions"><button class="btn sm" id="s-reset">${esc(t("btn.discard"))}</button><button class="btn sm primary" id="s-save">${esc(t("btn.save"))}</button></span></div>
  </section>`;
}
function srvDirty() {
  if (!SRV || !srvDraft) return false;
  return Object.keys(SRV.params).some((k) => (srvDraft[k] || "") !== (SRV.params[k] || "")) ||
    ["#s-host", "#s-dns", "#s-mtu", "#s-ka", "#s-port", "#s-addr"].some((sel) => {
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
  ["#s-host", "#s-dns", "#s-mtu", "#s-ka", "#s-port", "#s-addr"].forEach((sel) => {
    const el = $(sel); if (!el) return;
    el.dataset.orig = el.value; el.oninput = showBar;
  });
  $$("[data-p]").forEach((el) => el.oninput = el.onchange = () => { srvDraft[el.dataset.p] = el.value.trim(); showBar(); });
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
    const body = { public_host: $("#s-host").value.trim(), client_dns: $("#s-dns").value,
      client_mtu: +$("#s-mtu").value, client_keepalive: $("#s-ka").value.trim() };
    if (Object.keys(changed).length) body.params = changed;
    if (!SRV.port_locked) body.port = port;
    if (!SRV.subnet_locked) body.address = addr;
    $("#s-save").disabled = true;
    try {
      const r = await api("PUT", "server", body);
      toast(t(r.restarted ? "toast.server_restarted" : "toast.settings_saved"));
      if (r.server_side_changed) toast(t("toast.reimport"));
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
      </div>
      ${T.error && T.active !== "letsencrypt" && P.access !== "ssh" ? `<p class="err small" style="margin-bottom:0">${esc(t("sy.tls_error"))}: ${esc(T.error)}</p>` : ""}
      ${T.mode === "letsencrypt" ? `<div class="actions" style="margin-top:12px"><button class="btn sm" id="tls-renew">${esc(t("sy.tls_renew"))}</button></div>` : ""}
    </div>
  </section>
  <div class="grid2">
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
  <section class="section">
    <div class="section-head"><div><h2>${esc(t("sy.now"))}</h2><p class="muted small">${esc(t("sy.now_sub"))}</p></div><button class="btn sm" id="load-debug">${esc(t("sy.show"))}</button></div>
    <div id="debug"></div>
  </section>`;
}
bind.system = () => {
  bindLang("lang-sys");
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
