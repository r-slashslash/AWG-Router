"use strict";
/* Личная страница клиента (открывается по секретной ссылке, без входа в панель). */

const $ = (s, el = document) => el.querySelector(s);
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
function fmtDate(ts) {
  return new Date(ts * 1000).toLocaleDateString(LANG, { day: "numeric", month: "long", year: "numeric" });
}
function toast(msg, bad = false) {
  const el = document.createElement("div");
  el.className = "toast" + (bad ? " bad" : "");
  el.textContent = msg;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), 3000);
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
// application/octet-stream: с text/plain Chrome на Android дописывает к имени «.txt»,
// и приложение AmneziaVPN не принимает файл «client.conf.txt»
function download(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/octet-stream" }));
  a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
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
  if (typeof qrcode === "undefined") return "";
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

const TOKEN = location.pathname.split("/").filter(Boolean).pop();
let D = null, ERR = null;

function statusHtml() {
  const L = D.limits || {};
  let reason = "";
  if (!D.enabled) reason = L.auto_off === "exp" ? t("share.off_exp")
    : (L.auto_off || "").startsWith("quota:") ? t("share.off_quota") : t("share.off_admin");
  const tr = D.traffic || {};
  const month = (tr.month_rx || 0) + (tr.month_tx || 0), total = (tr.total_rx || 0) + (tr.total_tx || 0);
  const of = (used, period) => L.quota && L.period === period
    ? t("share.of", { used: fmtBytes(used), limit: fmtBytes(L.quota) }) : fmtBytes(used);
  return `
    <p class="share-state"><span class="state"><span class="dot ${D.enabled ? "ok" : "bad"}"></span><b>${esc(t(D.enabled ? "share.active" : "share.off"))}</b></span>
      ${reason ? `<span class="muted"> · ${esc(reason)}</span>` : ""}</p>
    <div class="panel panel-pad"><div class="kv">
      <div><span>${esc(t("share.until"))}</span><b>${esc(L.expires ? fmtDate(L.expires) : t("share.unlimited"))}</b></div>
      <div><span>${esc(t("share.month"))}</span><b>${esc(of(month, "month"))}</b></div>
      <div><span>${esc(t("share.total"))}</span><b>${esc(of(total, "total"))}</b></div>
      <div><span>${esc(t("share.last"))}</span><b>${esc(D.handshake ? fmtAge(D.now - D.handshake) : t("never"))}</b></div>
    </div></div>`;
}

function render() {
  document.title = D && D.name ? `${D.name} · AWG Router` : "AWG Router";
  if (ERR) { $("#main").innerHTML = `<div class="panel empty"><p>${esc(ERR)}</p></div>`; return; }
  if (!D) { $("#main").innerHTML = `<p class="muted">${esc(t("probe.checking"))}</p>`; return; }
  const cfg = D.config;
  $("#main").innerHTML = `
    <section class="section">
      <h1 class="share-title"><bdi>${esc(D.name || "AWG")}</bdi></h1>
      <div id="share-status">${statusHtml()}</div>
    </section>
    <section class="section">
      <div class="section-head"><h2>${esc(t("share.conn"))}</h2></div>
      <div class="panel panel-pad">
        ${cfg ? `
        <ol class="share-steps"><li>${esc(t("share.step1"))}</li><li>${esc(t("share.step2"))}</li></ol>
        <div class="connect">
          <div class="qr-box">${qrImage(cfg.conf)}</div>
          <div class="connect-actions">
            <button class="btn" id="s-dl">${esc(t("cl.download"))}</button>
            <button class="btn" id="s-link">${esc(t("cl.copy_link"))}</button>
            <button class="btn ghost" id="s-copy">${esc(t("cl.copy_conf"))}</button>
            <details class="small"><summary>${esc(t("cl.show_conf"))}</summary><pre class="code" dir="ltr">${esc(cfg.conf)}</pre></details>
          </div>
        </div>` : `<div class="notice">${esc(t("share.no_config"))}</div>`}
      </div>
    </section>`;
  if (cfg) {
    $("#s-dl").onclick = () => download(cfg.filename, cfg.conf);
    $("#s-link").onclick = () => copyText(cfg.link);
    $("#s-copy").onclick = () => copyText(cfg.conf);
  }
}

async function load(first) {
  try {
    const r = await fetch("/s/api/" + encodeURIComponent(TOKEN), { cache: "no-store" });
    if (r.status === 404) { ERR = t("share.gone"); D = null; render(); return; }
    if (!r.ok) throw new Error("HTTP " + r.status);
    D = await r.json(); ERR = null;
    if (first || !$("#share-status")) render(); else $("#share-status").innerHTML = statusHtml();
  } catch (e) {
    if (first) { ERR = t("panel.offline", { e: e.message }); render(); }
  }
}

function langSelect() {
  const el = $("#lang-top");
  el.outerHTML = `<select id="lang-top" class="lang-select" aria-label="${esc(t("lang"))}">${Object.entries(LANGS)
    .map(([k, v]) => `<option value="${k}" ${k === LANG ? "selected" : ""}>${v.name}</option>`).join("")}</select>`;
  $("#lang-top").onchange = (e) => { setLang(e.target.value, true); langSelect(); render(); };
}

langSelect();
render();
window.addEventListener("load", () => load(true));
setInterval(() => { if (!document.hidden) load(false); }, 60000);
