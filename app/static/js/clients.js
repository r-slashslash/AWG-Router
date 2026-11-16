// Вкладка «Клиенты»: таблица, QR-коды, окно клиента.
"use strict";

/* ================================================================ клиенты */
function serverMissing() {
  return S.target && S.target.exists === false;
}
/* Вкладка «Клиенты» при опросе: если вокруг таблицы ничего не изменилось и порядок строк тот же, меняются
   только изменившиеся строки, а не вся таблица (тысяча строк — четверть секунды на компьютере и секунды
   на телефоне). clientParts — что нарисовал viewClients(): обвязка без строк и строки по ключам. */
let clientParts = null, clientsShown = null;
const ROWS_MARK = "\u0000rows\u0000";
function patchClients(html) {
  const now = clientParts, was = clientsShown;
  const body = $("#cl-rows");
  if (!now || !was || !body || now.order !== was.order) return false;
  const banner = html.slice(0, html.length - now.html.length);
  if (banner + now.shell !== was.banner + was.shell) return false;
  const rows = body.querySelectorAll("tr[data-pk]");
  if (rows.length !== now.rows.length) return false;
  const tpl = document.createElement("tbody");
  now.rows.forEach(([pk, h], i) => {
    if (was.rows[i][1] === h) return;
    tpl.innerHTML = h;
    const tr = tpl.firstElementChild;
    tr.onclick = () => editClient(tr.dataset.pk);
    rows[i].replaceWith(tr);
  });
  now.banner = banner;
  clientsShown = now;
  if ($("#client-search")) filterClients();
  return true;
}

function viewClients() {
  clientParts = null;
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
  const rowList = sortedClients().map((c) => {
    const live = c.live || {};
    const age = live.handshake ? S.now - live.handshake : null;
    const online = c.enabled && age != null && age < 180;
    const p = c.policy;
    const tags = (!c.enabled ? `<span class="tag tag-off">${esc(t("cl.disabled_tag"))}</span>` : "") +
      (p.rules_mode === "custom" ? `<span class="tag">${esc(t("cl.custom_tag"))}</span>` : "") +
      (p.note ? `<span class="tag"><bdi>${esc(p.note)}</bdi></span>` : "") +
      (c.cps ? `<span class="tag" title="${esc(t("cl.cps"))}">${esc(cpsTag(c.cps))}</span>` : "") + limitTags(c);
    const wanted = p.outbound !== "inherit" ? p.outbound : c.default;
    const activity = !c.enabled ? `<span class="muted">—</span>`
      : `<span class="state"><span class="dot ${online ? "ok" : ""}"></span>${esc(online ? t("cl.online") : fmtAge(age))}</span>`;
    return [c.public_key, `<tr class="click ${c.enabled ? "" : "row-off"}" ${endingSoon(c) ? 'data-soon="1"' : ""} data-pk="${esc(c.public_key)}" data-q="${esc((c.name + " " + c.ip + " " + p.note).toLowerCase())}">
      <td><span class="client-name"><bdi>${esc(c.name || t("cl.unnamed"))}</bdi></span>${tags}</td>
      <td data-m="sub" class="nowrap"><bdi>${esc(c.ip || "—")}</bdi></td>
      <td data-m="sub">${activity}</td>
      <td data-m="month" class="nowrap muted"><span class="m-label">${esc(t("ex.month"))}: </span>${trafficCell(c)}</td>
      <td data-m="right">${effChip(c.effective, wanted)}${p.outbound !== "inherit" ? `<div class="small muted" style="margin-top:3px">${esc(t("cl.manual"))}</div>`
        : c.balanced ? `<div class="small muted" style="margin-top:3px">⚖️ ${esc(t("cl.balanced"))}</div>` : ""}</td>
    </tr>`];
  });
  const rows = rowList.map((r) => r[1]).join("");
  const nSoon = S.clients.filter(endingSoon).length;
  if (!nSoon) clientSoon = false;
  const soon = nSoon ? `<div class="soon-bar"><button type="button" class="btn sm" id="client-soon" aria-pressed="${clientSoon}">⏳ ${esc(t("cl.soon", { n: nSoon }))}</button></div>` : "";
  const shell = `
  <section class="section">${head}${soon}
    <div class="panel"><table class="table responsive">
      <thead><tr><th>${esc(t("cl.col_name"))}</th><th>${esc(t("cl.col_ip"))}</th><th>${esc(t("cl.col_activity"))}</th><th>${esc(t("cl.col_month"))}</th><th>${esc(t("cl.col_exit"))}</th></tr></thead>
      <tbody id="cl-rows">${ROWS_MARK}</tbody>
    </table></div>
  </section>`;
  const html = shell.replace(ROWS_MARK, () => rows);
  clientParts = { shell, rows: rowList, order: rowList.map((r) => r[0]).join(","), html, banner: "" };
  return html;
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
function fmtDay(ts) { return dateFmt({ day: "numeric", month: "short", year: "numeric" }).format(new Date(ts * 1000)); }
function limitTags(c) {
  const L = c.limits || {};
  let h = "";
  if (L.auto_off === "exp") h += `<span class="tag tag-off">${esc(t("cl.tag_expired"))}</span>`;
  else if ((L.auto_off || "").startsWith("quota:")) h += `<span class="tag tag-off">${esc(t("cl.tag_quota"))}</span>`;
  else if (L.expires && L.expires <= S.now) h += `<span class="tag tag-warn">${esc(t("cl.tag_expired"))}</span>`;
  else if (L.expires) h += `<span class="tag ${L.expires - S.now < 3 * 86400 ? "tag-warn" : ""}">${esc(t("cl.tag_until", { date: fmtDay(L.expires) }))}</span>`;
  if (L.rate_down || L.rate_up) h += `<span class="tag" title="${esc(t("cl.rate"))}">${rateHtml(L.rate_down, L.rate_up)}</span>`;
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
  if (!leaveOk()) return;
  if (tab === "server" && name !== "server") { SRV = null; srvDraft = null; }
  tab = name; history.replaceState(null, "", "#" + tab); render(); window.scrollTo(0, 0);
}
/** Уход с вкладки с несохранёнными правками: правила маршрутизации и настройки сервера — спросить. */
function leaveOk() {
  if (tab === "routing" && routingDirty()) return confirm(t("rt.leave"));
  if (tab === "server" && srvDirty()) return confirm(t("srv.leave"));
  return true;
}

/** Свой адрес сервера в конфиге клиента (#37): «как у всех» и адреса с вкладки «Сервер».
 *  Выбора нет, пока у сервера один адрес. */
function hostSelect(id, cur, hint = "cl.host_hint") {
  const H = S.hosts || {}, choices = (H.choices || []).filter((h) => h !== H.default);
  if (!choices.length && !cur) return "";
  const opts = [["", t("cl.host_default", { v: H.default || "—" })], ...choices.map((h) => [h, h])];
  if (cur && !opts.some(([v]) => v === cur)) opts.push([cur, cur]);
  return `<label class="field"><span>${esc(t("cl.host"))}</span>
    <select id="${id}" dir="auto">${opts.map(([v, l]) => `<option value="${esc(v)}" ${v === cur ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>
    <span class="hint">${esc(t(hint))}</span></label>`;
}

function addClient() {
  openModal(t("cl.add_title"), `
    <label class="field"><span>${esc(t("cl.name"))}</span>
      <input type="text" id="n-name" maxlength="60" placeholder="${esc(t("cl.name_ph"))}" autofocus>
      <span class="hint">${esc(t("cl.add_hint"))}</span>
    </label>${hostSelect("n-host", "", "cl.host_new_hint")}`,
  `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="n-save">${esc(t("cl.create"))}</button>`);
  const go = async () => {
    const name = $("#n-name").value.trim();
    if (!name) { $("#n-name").focus(); return; }
    if ($("#n-save").disabled) return;          // второй Enter, пока первый запрос идёт, — не второй клиент
    $("#n-save").disabled = true;
    try {
      const body = { name };
      if ($("#n-host") && $("#n-host").value) body.host = $("#n-host").value;
      const r = await api("POST", "users", body);
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
    <div id="c-pane-connect" class="c-pane">${hostSelect("c-host", c.host || "")}<div id="c-cps-box"></div><div id="c-conn"></div></div>
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
      <div class="row2">
        <label class="field"><span>${esc(t("cl.rate_down"))}</span>
          <input type="number" id="c-rd" min="0" step="any" inputmode="decimal" placeholder="${esc(t("cl.no_limit"))}" value="${L.rate_down || ""}"></label>
        <label class="field"><span>${esc(t("cl.rate_up"))}</span>
          <input type="number" id="c-ru" min="0" step="any" inputmode="decimal" placeholder="${esc(t("cl.no_limit"))}" value="${L.rate_up || ""}"></label>
      </div>
      <p class="small muted" style="margin:-6px 0 14px">${esc(t("cl.rate_hint"))}</p>
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

  const hostSel = $("#c-host");
  if (hostSel) hostSel.onchange = async () => {
    hostSel.disabled = true;
    try {
      const r = await api("PUT", "hosts/" + encodeURIComponent(pk), { host: hostSel.value });
      c.host = r.host; toast(t("cl.host_saved")); loadConnect(); refresh();
    } catch (e) { if (!(e instanceof AuthError)) toast(e.message, true); hostSel.value = c.host || ""; }
    hostSel.disabled = false;
  };
  const loadCps = async () => {
    const box = $("#c-cps-box");
    let info;
    try { info = await api("GET", "cps"); } catch { return; }
    const cur = c.cps ? c.cps.preset : "server";
    // шаблон сервера — это и есть пункт «по умолчанию»: отдельно его не показываем
    // (кроме клиента, за которым он закреплён раньше, чтобы его выбор было видно)
    const srv = info.server_match;
    const srvLabel = srv ? t("cl.cps_server", { name: cpsName(srv) }) : t("cl.cps_server_custom");
    const presets = info.presets.filter((p) => p.id === cur || p.id !== srv);
    box.innerHTML = `
      <label class="field"><span>${esc(t("cl.cps"))}</span>
        <select id="c-cps"><option value="server" ${cur === "server" ? "selected" : ""}>${esc(srvLabel)}</option>
          ${presets.map((p) => `<option value="${p.id}" ${cur === p.id ? "selected" : ""}>${esc(cpsName(p.id))}</option>`).join("")}
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
      box.innerHTML = S.routing.rules.length ? rulesSummary(S.routing.rules)
        : `<p class="muted small">${esc(t("cl.no_global"))}</p>`;
      watchRules(box);
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
      const rd = $("#c-rd").value.trim(), ru = $("#c-ru").value.trim();
      if (exp !== (L.expires || null) || q !== oldQ || per !== (L.period || "month")
          || rd !== String(L.rate_down || "") || ru !== String(L.rate_up || "")) {
        const r = await api("PUT", "limits/" + encodeURIComponent(pk), { expires: exp, quota_gb: q === "" ? null : +q, period: per,
          rate_down: rd || null, rate_up: ru || null });
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
