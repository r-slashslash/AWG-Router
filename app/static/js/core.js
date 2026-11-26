// Каркас панели: помощники, запросы к API, состояние и его опрос, общие подписи (выходы, списки, скорость),
// вход, шапка, отрисовка вкладок и окна. Грузится первым: остальные файлы пользуются его именами.
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
/* Форматировщики Intl — один на язык и набор настроек: новый на каждое число и дату стоил вкладке «Клиенты» с
   тысячей строк ~100 мс на слабом телефоне при каждой перерисовке */
const _intl = new Map();
function intlFmt(kind, opts) {
  const k = kind + LANG + JSON.stringify(opts);
  let f = _intl.get(k);
  if (!f) _intl.set(k, f = new Intl[kind](LANG, opts));
  return f;
}
const numFmt = (opts) => intlFmt("NumberFormat", opts);
const dateFmt = (opts) => intlFmt("DateTimeFormat", opts);
function fmtBytes(b) {
  const u = BYTE_UNITS[LANG] || BYTE_UNITS.en;
  if (!b) return `${fmtNum(0)} ${u[0]}`;
  const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1);
  return numFmt({ maximumFractionDigits: i ? 1 : 0 }).format(b / 1024 ** i) + " " + u[i];
}
function fmtAge(sec) {
  if (sec == null) return t("never");
  sec = Math.max(0, Math.round(sec));
  const rtf = intlFmt("RelativeTimeFormat", { numeric: "always", style: "short" });
  if (sec < 60) return rtf.format(-sec, "second");
  if (sec < 3600) return rtf.format(-Math.floor(sec / 60), "minute");
  if (sec < 86400) return rtf.format(-Math.floor(sec / 3600), "hour");
  return rtf.format(-Math.floor(sec / 86400), "day");
}
/** между датой и временем: в персидском — своя запятая, в китайском — пробел */
function dtSep() { return LANG === "fa" ? "، " : LANG === "zh" ? " " : ", "; }
/** когда начнётся следующий месяц учёта (1-е число, 00:00 UTC) по часам браузера — для подсказок */
function monthResetLocal() {
  const n = new Date(), d = new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth() + 1, 1));
  return dateFmt({ day: "numeric", month: "short" }).format(d) + dtSep()
    + dateFmt({ hour: "2-digit", minute: "2-digit" }).format(d);
}
function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000), now = new Date();
  const time = dateFmt({ hour: "2-digit", minute: "2-digit" }).format(d);
  return d.toDateString() === now.toDateString() ? time
    : dateFmt({ day: "numeric", month: "short" }).format(d) + dtSep() + time;
}
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
  // открытое окно (dialog) лежит в верхнем слое поверх всей страницы: сообщения — в нём, иначе их не видно
  // окно над окном (окно правила в окне клиента) — в верхнем
  const box = $("#toasts"), host = [...document.querySelectorAll("dialog[open]")].pop() || document.body;
  if (box.parentNode !== host) host.append(box);
  box.append(el);
  setTimeout(() => el.remove(), bad ? 6000 : 3000);
}

/** Строка «Есть несохранённые изменения» — наверху вкладки, сразу под строкой вкладок (решение владельца
   2026-11-19: внизу неудобно). Она и так на виду, поэтому «сначала сохраните» не прокручивает к ней, а мигает ею. */
function flashBar(el) {
  if (!el) return;
  el.classList.remove("flash");
  void el.offsetWidth;            // заново запустить анимацию
  el.classList.add("flash");
}

/** Вопрос перед действием — в самой панели, не окном браузера (владелец 2026-11-27): кнопка на странице — полоса
   сверху (#askbar, как «Изменения применятся после сохранения»), кнопка в окне — внизу этого окна, на месте его
   кнопок. warn — текст оранжевым (что изменится). → true, если нажата кнопка действия; новый вопрос, уход с вкладки,
   закрытие окна и Esc — false. */
let askDone = null;
function ask(text, { from = null, ok = "", danger = false, warn = false } = {}) {
  if (askDone) askDone(false);
  const dlg = from && from.closest ? from.closest("dialog[open]") : null;
  const foot = dlg ? $(".modal-foot", dlg) : null;
  const label = ok || (from && from.textContent.trim()) || t("btn.continue");
  return new Promise((resolve) => {
    const box = document.createElement("div");
    box.className = foot ? "ask-in" : "ask-box";
    box.innerHTML = `<div class="ask-text${warn ? " ask-warn" : ""}">${String(text).split(/\n{2,}/).map((p) => `<div>${esc(p)}</div>`).join("")}</div>
      <span class="actions"><button type="button" class="btn sm" data-ask="0">${esc(t("btn.cancel"))}</button><button type="button" class="btn sm ${danger ? "danger-solid" : "primary"}" data-ask="1">${esc(label)}</button></span>`;
    const bar = $("#askbar"), hidden = foot ? [...foot.children].filter((x) => !x.hidden) : [];
    const onClose = () => done(false);
    const onKey = (e) => { if (e.key === "Escape") done(false); };
    function done(v) {
      if (askDone !== done) return;
      askDone = null;
      box.remove();
      hidden.forEach((x) => { x.hidden = false; });
      if (foot) dlg.removeEventListener("close", onClose);
      else { bar.hidden = true; document.removeEventListener("keydown", onKey); }
      resolve(v);
    }
    askDone = done;
    if (foot) {
      hidden.forEach((x) => { x.hidden = true; });
      foot.append(box);
      dlg.addEventListener("close", onClose);
    } else {
      bar.replaceChildren(box);
      bar.hidden = false;
      document.addEventListener("keydown", onKey);
      flashBar(bar);
    }
    $$("[data-ask]", box).forEach((b) => b.onclick = () => done(b.dataset.ask === "1"));
    $(`[data-ask="${danger ? 0 : 1}"]`, box).focus({ preventScroll: true });
  });
}
/** Уход с вкладки с несохранённым: вкладка не меняется, полоса «Сохранить» загорается — «Сохраните или отмените». */
function barLeave(bar) {
  const s = $("span", bar);
  if (s) { s.textContent = t("bar.leave"); s.classList.add("ask-warn"); }
  flashBar(bar);
}

class AuthError extends Error {}
async function api(method, path, body, timeoutMs = 0, headers = null) {
  const opt = { method, headers: { ...(headers || {}) }, credentials: "same-origin" };
  // опрос состояния не ждёт вечно: зависшая панель — это «Нет связи», а не застывшая страница
  if (timeoutMs && typeof AbortSignal !== "undefined" && AbortSignal.timeout) opt.signal = AbortSignal.timeout(timeoutMs);
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  let r;
  try { r = await fetch("api/" + path, opt); }
  catch {
    // связь оборвалась или запрос не дождался ответа: вместо «Failed to fetch» / «signal timed out» браузера
    const err = new Error(t("status.offline"));
    err.offline = true;
    throw err;
  }
  if (r.status === 401 && path !== "login") { showLogin(); throw new AuthError(t("auth.required")); }
  let data = null;
  try { data = await r.json(); } catch { /* пусто */ }
  if (!r.ok) {
    const err = new Error(data && data.detail ? tm(data.detail) : `HTTP ${r.status}`);
    err.field = data && typeof data.field === "string" ? data.field : null;
    err.key = data && data.detail && typeof data.detail.$t === "string" ? data.detail.$t : null;   // какая ошибка
    throw err;
  }
  return data;
}

/** Поле формы, о котором ошибка сервера (field в ответе; у полей — data-field): рамка, фокус, прокрутка к
 *  нему. Выделение снимается, как только поле правят. Поле скрыто (другой тип выхода) — только сообщение. */
/** поле-число, в котором набрано не число («1e», «1-»): браузер отдаёт его как пустое, и лимит молча снимался бы.
    Есть такое — подсветить, сказать и не сохранять (глубокая проверка 1.23.0) */
function badNumber(ids) {
  const el = ids.map((id) => $("#" + id)).find((x) => x && x.validity && x.validity.badInput);
  if (!el) return false;
  el.classList.add("invalid");
  el.addEventListener("input", () => el.classList.remove("invalid"), { once: true });
  el.focus();
  toast(t("err.bad_value"), true);
  return true;
}
function markField(err, root = document) {
  if (!err || !err.field || !root) return;
  const els = [...root.querySelectorAll("[data-field]")]
    .filter((el) => el.dataset.field.split(" ").includes(err.field) && el.getClientRects().length);
  if (!els.length) return;
  for (const el of els) {
    el.classList.add("invalid");
    el.setAttribute("aria-invalid", "true");
    const off = () => { el.classList.remove("invalid"); el.removeAttribute("aria-invalid"); };
    el.addEventListener("input", off, { once: true });
    el.addEventListener("change", off, { once: true });
  }
  els[0].focus({ preventScroll: true });
  els[0].scrollIntoView({ block: "center", behavior: "smooth" });
}

/* ================================================================ состояние */
let S = null;
let tab = (location.hash || "#overview").slice(1);
let scrollToLists = tab === "lists";             // закладка на старую вкладку «Списки» (до 1.12.1)
if (tab === "lists") { tab = "routing"; history.replaceState(null, "", "#routing"); }
let routingDraft = null;
const probes = {};
let pollTimer = null;
let pollOn = false;
// Опрос состояния: раз в POLL_MS, но перерисовка занимает не больше 1/POLL_BUSY времени. На тысяче клиентов
// перерисовка вкладки «Клиенты» — четверть секунды на компьютере и секунда-две на телефоне: опрос раз в 5 с
// держал бы телефон занятым. Пауза растёт до POLL_MAX_MS; считается только перерисовка, не ожидание сети.
const POLL_MS = 5000, POLL_MAX_MS = 30000, POLL_BUSY = 20;
let renderCost = 0;
function schedulePoll() {
  clearTimeout(pollTimer);
  if (!pollOn) return;
  pollTimer = setTimeout(async () => {
    if (!document.hidden) await refresh(true);
    schedulePoll();
  }, Math.min(POLL_MAX_MS, Math.max(POLL_MS, renderCost * POLL_BUSY)));
}

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
  if (isDirect(v)) return directName(v);          // «Напрямую» или «Напрямую — адрес» (1.25.0)
  if (v === "block") return t("out.block");
  const u = typeof v === "string" && v.startsWith("up:") ? upstreamById(v.slice(3)) : null;
  return u ? u.name : t("out.deleted");
}

/** Свои правила клиента начинаются с копии общих — без месячного лимита и ограничения скорости (1.24.0): у общего
    правила они на всех его клиентов вместе, а у копии были бы свои, отдельные — клиент выпал бы из общего предела */
function copyRules(rules) {
  return structuredClone(rules).map((r) => {
    for (const k of ["quota", "quota_gb", "quota_action", "quota_hit", "quota_warned", "rate_down", "rate_up"]) delete r[k];
    return r;
  });
}
/** чип выхода по значению из настроек: direct | block | up:<id> */
/** выход правила: с балансировкой (1.24.0) — «⚖ выход · выход», иначе — как outChip */
function ruleOutChip(r) {
  const ids = (r && r.balance) || [];
  if (!ids.length) return outChip(r.outbound);
  const names = ids.map((id) => { const u = upstreamById(id); return u ? `<bdi>${esc(u.name)}</bdi>` : ""; }).filter(Boolean);
  return `<span class="line bal-chip" title="${esc(t("bal.option"))}"><span aria-hidden="true">⚖</span> ${names.join(" · ") || esc(t("out.deleted"))}</span>`;
}
function outChip(v, extra = "") {
  if (isDirect(v)) return `<span class="line direct">${esc(directName(v))}${extra}</span>`;
  if (v === "block") return `<span class="line block">${esc(t("out.block"))}${extra}</span>`;
  if (typeof v === "string" && v.startsWith("up:")) {
    const u = upstreamById(v.slice(3));
    if (!u) return `<span class="line block">${esc(t("out.deleted"))}</span>`;
    return `<span class="line" style="--c:${lineVar(u)}" title="${esc(u.name)}"><bdi>${esc(u.name)}</bdi>${extra}</span>`;
  }
  return `<span class="line">${esc(v)}</span>`;
}
/** чип фактического выхода (после резерва): direct | block | номер туннеля */
function effChip(eff, wanted) {
  // фактический «direct» — с адреса системы; основной исходящий адрес — другой (1.25.0): это «Напрямую — адрес системы»
  if (eff === "direct" && (S.addrs || {}).main) eff = "direct@system";
  const val = isDirect(eff) || eff === "block" ? eff : "up:" + (upstreamByNum(eff) || {}).id;
  if (wanted && !sameOut(wanted, val)) {
    const w = wanted.startsWith("up:") ? (upstreamById(wanted.slice(3)) || {}).name : null;
    const html = outChip(val, w ? ` <span class="sub">${th("out.instead", { name: `<bdi>${esc(w)}</bdi>` })}</span>` : "");
    return html.replace('class="line', 'class="line fallback');
  }
  return outChip(val);
}
function outOptions(selected, { inherit = null, exclude = null, block = true } = {}) {
  const opts = [];
  if (inherit !== null) opts.push(["inherit", inherit]);
  // «Напрямую» — у каждого исходящего адреса своё, основной первым (1.25.0); неработающий — серый
  opts.push(...directOptions(selected));
  for (const u of S.upstreams) if ("up:" + u.id !== exclude) opts.push(["up:" + u.id, u.name]);   // просто имя выхода: «Выход: Германия»
  if (block) opts.push(["block", t("out.block")]);
  const sel = opts.some(([v]) => v === selected) ? selected : isDirect(selected) ? "direct" : selected;
  return opts.map(([v, l, off]) => `<option value="${esc(v)}" ${v === sel ? "selected" : ""} ${off ? "disabled" : ""}>${esc(l)}</option>`).join("");
}
/* балансировка и ограничение скорости */
function balOn() { return !!(S.routing.balance && S.routing.balance.on); }
function balMembers() { return (S.balance && S.balance.members) || []; }
/** байт/с → Мбит/с для показа */
function fmtMbps(bps) {
  const m = (bps || 0) * 8 / 1e6;
  return numFmt({ maximumSignificantDigits: m < 10 ? 2 : 3 }).format(m < 0.01 ? 0 : m);
}
/** части «↓ 12» «↑ 3» — каждая без переноса, числа слева направо (в fa тоже); единица — на языке интерфейса */
const mbpsHtml = (parts) => parts.map((x) => `<bdi dir="ltr" class="nowrap">${esc(x)}</bdi>`).join(" ") +
  ` <span class="nowrap">${esc(t("u.mbps"))}</span>`;
/** ограничение скорости (Мбит/с) «↓ 80 ↑ 20 Мбит/с» (HTML); пусто — ничего не задано */
function rateHtml(down, up) {
  const parts = [];
  if (down) parts.push("↓ " + fmtNum(down));
  if (up) parts.push("↑ " + fmtNum(up));
  return parts.length ? mbpsHtml(parts) : "";
}
/** скорость выхода сейчас (HTML); при ограничении — «12 / 80» */
function speedHtml(u) {
  const sp = u.speed || [0, 0];
  const part = (v, cap) => fmtMbps(v) + (cap ? " / " + fmtNum(cap) : "");
  return mbpsHtml([`↓ ${part(sp[1], u.rate_down)}`, `↑ ${part(sp[0], u.rate_up)}`]);
}
function shapingNotice() {
  const s = S.shaping;
  return s && s.state === "error" ? `<div class="notice warn">${esc(t("sh.error", { error: tm(s.error) || "?" }))}</div>` : "";
}
/** что ловит список — подпись в строке правила (HTML): «Домены work (20)»; свои сайты выхода — их первый
 *  домен и сколько ещё («Домены youtube.com +19»): имя такого списка — имя выхода, а он и так справа;
 *  «work (12 сетей)» у своего списка сетей; страны, ASN и списки по ссылке — просто имя */
function listLabel(id) {
  const l = listObj(id);
  if (!l) return `<bdi>${esc(id)}</bdi>`;
  if (l.kind === "domains") {
    const own = S.upstreams.some((u) => u.own_list === id);
    const name = own && l.first
      ? `<bdi>${esc(l.first)}</bdi>${l.count > 1 ? ` <bdi dir="ltr" class="nowrap">+${esc(fmtNum(l.count - 1))}</bdi>` : ""}`
      : `<bdi>${esc(listName(id))}</bdi>${l.count ? ` (${esc(fmtNum(l.count))})` : ""}`;
    return th("rl.domains", { name });
  }
  if (l.kind === "manual" && l.count) return `<bdi>${esc(listName(id))}</bdi> (${esc(t("n.networks", { n: l.count }))})`;
  return `<bdi>${esc(listName(id))}</bdi>`;
}
/** то же текстом — для подсказки */
const listLabelText = (id) => { const d = document.createElement("div"); d.innerHTML = listLabel(id); return d.textContent; };
/** своё название правила: не пустое и не повторяет то, что строка и так показывает, — имя выхода (так окно
 *  выхода подписывало правила до 1.21.0) или имя его списка */
const ruleOwnName = (r) => (r.comment && r.comment !== exitName(r.outbound)
  && !r.lists.some((l) => listName(l) === r.comment) ? r.comment : "");
const openRules = new Set();     // правила, у которых по нажатию на «+N» показан весь состав
/** что ловит правило (HTML): больше двух списков — первые два и «+N»; нажатие показывает остальные на месте (и в окне
 *  клиента). На телефоне, если выход не влез в строку, — один список и «+N» (fitRules, класс compact): какой «+N»
 *  видно, решает CSS по классам строки */
function ruleWhat(r) {
  const labels = r.lists.map(listLabel), n = labels.length, s = esc(sep("list"));
  if (n < 2) return labels.join("");
  return `<span class="rule-l1">${labels[0]}</span><span class="rule-l2">${s}${labels[1]}</span>`
    + (n > 2 ? `<span class="rule-rest">${s}${labels.slice(2).join(s)}</span>` : "")
    + ` <button type="button" class="more-chip" dir="ltr" data-rule-more="${esc(r.id)}" aria-expanded="${openRules.has(r.id)}" title="${esc(r.lists.map(listLabelText).join(sep("list")))}" aria-label="${esc(t("rl.show_all"))}">`
    + `<span class="mc-more">+${esc(fmtNum(n - 2))}</span><span class="mc-one">+${esc(fmtNum(n - 1))}</span><span class="mc-open">−</span></button>`;
}
/** строки правил политики: слева — что ловит правило (его списки), справа — выход. Выключенное правило —
 *  серое и зачёркнутое, со своим номером */
/** Список правил словами. tr = "c" — с местами для трафика клиента по правилам (окно клиента, 1.24.0) */
function rulesSummary(rules, tr = "") {
  if (!rules.length) return `<p class="muted small" style="margin:0">${esc(t("ov.no_rules"))}</p>`;
  return `<ol class="summary rule-sum">${rules.map((r, i) => {
    const n = r.lists.length;
    const cls = [r.enabled === false ? "off" : "", n > 1 ? "many" : "", n > 2 ? "three" : "", openRules.has(r.id) ? "open" : ""]
      .filter(Boolean).join(" ");
    const name = ruleOwnName(r);
    // список без записей (не скачался, пустой) правило тихо выключает — говорим об этом в самой строке
    const empty = r.enabled === false ? [] : r.lists.map(listObj).filter((l) => l && !l.busy && !l.count);
    const names = (ls) => ls.map((l) => `<bdi>${esc(listName(l.id))}</bdi>`).join(esc(sep("list")));
    const warn = [["rl.lists_failed", empty.filter((l) => l.error)], ["rl.lists_empty", empty.filter((l) => !l.error)]]
      .filter(([, ls]) => ls.length)
      .map(([k, ls]) => `<div class="small warn-text rule-warn">⚠ ${th(k, { lists: names(ls) })}</div>`).join("");
    return `<li class="${cls}"${r.enabled === false ? ` title="${esc(t("rl.off"))}"` : ""}>
      <span class="rule-n">${esc(fmtNum(i + 1))}.</span>${name ? `<div class="rule-name"><bdi>${esc(name)}</bdi></div>` : ""}
      <div class="rule-row"><span class="rule-what">${ruleWhat(r)}</span><span class="rule-dash" aria-hidden="true">—</span>${ruleOutChip(r)}${r.balance && r.balance.length && tr === "c" ? `<span class="small muted nowrap" data-rbal-c="${esc(r.id)}"></span>` : ""}${tr === "c" ? `<span class="small muted rule-tr" data-rtr-c="${esc(r.id)}"></span>` : ""}</div>${warn}</li>`;
  }).join("")}</ol>`;
}
/* Телефон: выход правила не влез в строку рядом со списками — показываем один список и «+N» (не влез и тогда —
   выход под строкой, у правого края). Ширину строк смотрит ResizeObserver: он же видит окно клиента, когда оно
   открылось, и поворот экрана. Менять классы — в следующем кадре: правка наблюдаемого блока прямо в обработчике
   даёт ошибку «ResizeObserver loop» в консоли */
const narrowRules = matchMedia("(max-width: 560px)");
function fitRules(list) {
  for (const li of list.querySelectorAll(":scope > li.many")) {
    li.classList.remove("compact");
    if (!narrowRules.matches || li.classList.contains("open")) continue;
    const w = li.querySelector(".rule-what"), c = li.querySelector(".rule-row > .line");
    if (w && c && c.getBoundingClientRect().top >= w.getBoundingClientRect().bottom - 2) li.classList.add("compact");
  }
}
const ruleWidths = new WeakMap();
const ruleRO = typeof ResizeObserver === "function" ? new ResizeObserver((entries) => requestAnimationFrame(() => {
  for (const e of entries) {
    if (!e.target.isConnected) { ruleRO.unobserve(e.target); continue; }  // перерисовали — старый блок не держим
    const w = Math.round(e.contentRect.width);
    if (ruleWidths.get(e.target) === w) continue;
    ruleWidths.set(e.target, w);
    fitRules(e.target);
  }
})) : null;
function watchRules(root) {
  if (ruleRO) root.querySelectorAll(".rule-sum").forEach((el) => ruleRO.observe(el));
}
document.addEventListener("click", (e) => {
  const b = e.target.closest && e.target.closest("[data-rule-more]");
  if (!b) return;
  const id = b.dataset.ruleMore, open = !openRules.has(id), li = b.closest("li");
  if (open) openRules.add(id); else openRules.delete(id);
  li.classList.toggle("open", open);
  b.setAttribute("aria-expanded", open);
  if (!open) fitRules(li.parentElement);
});

/* ================================================================ язык */
function langSelect(id) {
  return `<select id="${id}" class="lang-select" aria-label="${esc(t("lang"))}">${Object.entries(LANGS)
    .map(([k, v]) => `<option value="${k}" ${k === LANG ? "selected" : ""}>${v.name}</option>`).join("")}</select>`;
}
function bindLang(id) {
  const el = $("#" + id);
  if (el) el.onchange = () => { setLang(el.value, true); applyStaticTexts(); if (S) { renderStatus(); render(); } };
}
/* кнопка «день/ночь» в шапке: солнце — включить светлую тему, луна — тёмную */
/* значки рисуются сами, а не символами шрифта: «☀» и «☾» в шрифтах Android стоят ниже середины строки */
const THEME_SUN = `<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
  <circle cx="12" cy="12" r="4.2" fill="currentColor" stroke="none"/>
  <path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6"/></svg>`;
const THEME_MOON = `<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="currentColor">
  <path d="M20.2 14.6A8.5 8.5 0 0 1 9.4 3.8a8.5 8.5 0 1 0 10.8 10.8z"/></svg>`;
function drawThemeBtn() {
  const b = $("#theme-btn");
  if (!b) return;
  const dark = themeDark();
  b.innerHTML = dark ? THEME_SUN : THEME_MOON;
  b.title = t(dark ? "theme.light" : "theme.dark");
  b.setAttribute("aria-label", b.title);
  b.setAttribute("aria-pressed", String(dark));
  b.onclick = toggleTheme;
}
window.addEventListener("awgr-theme", drawThemeBtn);
function applyStaticTexts() {
  $$("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  drawThemeBtn();
  $("#lang-login").outerHTML = langSelect("lang-login");
  $("#lang-top").outerHTML = langSelect("lang-top");
  bindLang("lang-login");
  bindLang("lang-top");
}

/** код 2FA: цифры любой записи (персидские ۱۲۳, арабские, полноширинные) — в ASCII, остальное прочь. Раньше
    `\D` выбрасывал персидские цифры, и вход с кодом с персидской клавиатуры молча не проходил */
function codeDigits(v) {
  return String(v || "").replace(/[\u0660-\u0669\u06f0-\u06f9\uff10-\uff19]/g, (c) => String(c.charCodeAt(0) & 0xf))
    .replace(/\D/g, "");
}

/* ================================================================ вход */
function showLogin() {
  document.title = "AWG Router";       // адрес и название сервера — только после входа
  pollOn = false;
  clearTimeout(pollTimer);
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
  if (!codeWrap.hidden) body.code = codeDigits($("#login-code").value);
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
// «Нет связи с панелью» — только после OFFLINE_AFTER неудачных опросов подряд: один пропуск на мобильной сети
// не должен красить шапку в красный
const OFFLINE_AFTER = 2, STATE_TIMEOUT_MS = 15000;
let pollFails = 0;
// Опрос, начатый до действия, может прийти позже refresh() после него: старый ответ вернул бы на экран
// уже удалённого клиента. Ответ старше применённого отбрасывается.
let stateSeq = 0, stateShown = 0;
let pendingS = null;                              // состояние из опроса, пока открыто окно (см. refresh)
let listsBusy = false;
/** набранное, но не сохранённое в полях вкладки (значение не то, с каким поле нарисовано), кроме полей блока skip */
function typedFields(skip) {
  return $$("#main input[id], #main select[id], #main textarea[id]").filter((el) => !(skip && skip.contains(el)) && (
    el.type === "checkbox" || el.type === "radio" ? el.checked !== el.defaultChecked
      : el.tagName === "SELECT" ? el.value !== ([...el.options].find((o) => o.defaultSelected) || el.options[0] || {}).value
        : el.type !== "file" && el.value !== el.defaultValue))
    .map((el) => [el.id, el.type === "checkbox" || el.type === "radio" ? el.checked : el.value]);
}
/** сохранили один блок вкладки — перерисовать её, вернув набранное в других блоках: на «Системе» «Сохранить» в
    «Настройках» стирало несохранённое в Telegram и наоборот (глубокая проверка 1.23.0) */
async function refreshKeep(btn) {
  const keep = typedFields(btn && (btn.closest(".panel") || btn.parentElement));
  await refresh();
  for (const [id, v] of keep) {
    const el = $("#" + id);
    if (el) { if (typeof v === "boolean") el.checked = v; else el.value = v; }
  }
}
async function refresh(auto = false) {
  const seq = ++stateSeq;
  let same = false;
  try {
    // фоновый опрос шлёт отпечаток прошлого ответа: ничего не изменилось — сервер отвечает коротко, и
    // вкладка не перерисовывается (обновляются только время, процессор и память в шапке)
    const tagged = auto && S && S.tag;
    const data = await api("GET", "state", undefined, STATE_TIMEOUT_MS, tagged ? { "X-State-Tag": S.tag } : null);
    if (seq < stateShown) return;
    stateShown = seq;
    pollFails = 0;
    if (data.same && S && data.tag === S.tag) {
      same = true;
      S.now = data.now; S.system = data.system; S.speeds = data.speeds; S.engine.last_reconcile = data.last_reconcile;
    } else if (data.same) {
      return;                                   // отпечаток уже не тот (другой ответ успел раньше) — ждём следующий
    } else if (auto && S && anyModal()) {
      // Окно открыто: его списки выбора и обработчики живут на состоянии, с которым оно открылось (иначе
      // список в окне — старый, а обработчик ищет по новому). Новое состояние — после закрытия окна.
      pendingS = data;
    } else {
      S = data;
      pendingS = null;
    }
  } catch (e) {
    if (e instanceof AuthError) return;
    pollFails++;
    if (S) renderStatus();
    if (updatingTo) { setUpdLine(t("sy.updating_restart")); return; }   // панель перезапускается
    if (!auto) toast(e.offline ? e.message : t("panel.offline", { e: e.message }), true);   // при опросе — шапка
    return;
  }
  if (pendingS && anyModal()) {                 // шапка — по новому состоянию, окно — по своему
    const keep = S;
    S = pendingS;
    try { renderStatus(); } finally { S = keep; }
    return;
  }
  if (followUpdate()) return;
  renderStatus();
  if (same) { if (tab === "clients") fillSpeeds(); return; }
  // на вкладке «Маршрутизация» опрос обновляет только строки правил: список скачивается (их предупреждения) или правила
  // поменяли в другой вкладке — иначе нажатие на старой строке сохранило бы прежний набор (проверка 1.23.0). Пока
  // строки сохраняются (inert), не трогаем: ответ опроса мог уйти до сохранения
  const busy = S.lists.some((l) => l.busy);
  const g = tab === "routing" && $("#g-rules");
  if (auto && g && !g.inert && !anyModal() && (busy || listsBusy || JSON.stringify(S.routing.rules) !== rulesDrawn)) drawRoutingRules();
  // «Сервер» опрос тоже не перерисовывает, кроме блока «Движок AmneziaWG» (после смены движка он менялся только с
  // перезагрузкой страницы)
  if (auto && tab === "server" && !anyModal()) { drawEngine(); drawAddrStatus(); }     // и состояния адресов (1.25.0)
  // трафик по правилам (1.24.0) — только цифры в готовых местах строк
  if (auto && tab === "routing" && !anyModal()) { fillRuleTraffic(); drawClientRules(); drawServerAddrs(); }
  listsBusy = busy;
  // при фоновом опросе не трогаем вкладки с формами и результатами проверок
  if (auto && !["overview", "clients", "exits"].includes(tab)) return;
  if (auto && anyModal()) return;
  // не перерисовываем, пока человек печатает в поиске или выбирает сортировку
  const a = document.activeElement;
  if (auto && a && $("#main").contains(a) && ["INPUT", "SELECT", "TEXTAREA"].includes(a.tagName)
      && Date.now() - lastTyping < 15000) return;
  const t0 = performance.now();
  render();
  renderCost = performance.now() - t0;
}

async function boot(retry = false) {
  $("#login").hidden = true;
  await refresh(retry);
  if (!S) {
    // первый запрос не прошёл (панель перезапускалась, оборвалась связь): снова через 3 секунды, а не пустая
    // страница навсегда; просит пароль — showLogin, и тогда ждём входа
    if ($("#login").hidden) setTimeout(() => boot(true), 3000);
    return;
  }
  if (((S.awg_engine || {}).install || {}).state === "running") { engWatching = true; engWatch(); }
  try {
    const done = sessionStorage.getItem("awgr.updated");
    if (done) { sessionStorage.removeItem("awgr.updated"); toast(t("sy.update_done", { version: done })); }
  } catch { /* нет хранилища */ }
  $("#app").hidden = false;
  pollOn = true;
  schedulePoll();
}

// высота строки вкладок (она прилипает к верху и на телефоне бывает выше): под ней прилипает строка сохранения
if (typeof ResizeObserver === "function") {
  new ResizeObserver(() => document.documentElement.style.setProperty("--tabs-h", $("#tabs").offsetHeight + "px"))
    .observe($("#tabs"));
}

$("#tabs").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-tab]");
  if (!b) return;
  if (!leaveOk()) return;
  if (askDone) askDone(false);                  // вопрос в полосе сверху — о кнопке прежней вкладки (А6)
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

// процессор и память сервера — в строке состояния; 90 % и выше выделяются цветом
function sysmonHtml() {
  const m = S.system;
  if (!m || (m.cpu == null && !m.mem)) return "";
  const pct = (v) => `<b class="${v >= 90 ? "hot" : ""}"><bdi>${esc(fmtNum(Math.round(v)))}%</bdi></b>`;
  const out = [];
  if (m.cpu != null) {
    const load = (m.load || []).map((x) => numFmt({ minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(x)).join(" · ");
    out.push(`<span title="${esc(t("status.cpu_hint", { cores: m.cores ? fmtNum(m.cores) : "?", load: load || "—" }))}">${esc(t("status.cpu"))} ${pct(m.cpu)}</span>`);
  }
  if (m.mem && m.mem[1]) {
    out.push(`<span title="${esc(t("status.ram_hint", { used: fmtBytes(m.mem[0]), total: fmtBytes(m.mem[1]) }))}">${esc(t("status.ram"))} ${pct(100 * m.mem[0] / m.mem[1])}</span>`);
  }
  return `<span class="sysmon">${out.join("")}</span>`;
}

/* вкладка браузера: название сервера из настроек, без него — адрес сервера (#38: несколько серверов открыты разом) */
function renderTitle() {
  const name = (S.settings && S.settings.panel_name) || (S.panel && S.panel.ip) || "";
  const title = name ? `${name} · AWG Router` : "AWG Router";
  if (document.title !== title) document.title = title;
}
function renderStatus() {
  renderTitle();
  const tg = S.target;
  const online = S.clients.filter((c) => c.live && c.live.handshake && S.now - c.live.handshake < 180).length;
  renderBrandTraffic();
  // состояние: причина ошибки — во всплывающей подсказке, подробности — в полосах под шапкой (по нажатию)
  const [kind, label, hint] = headerState();
  const problem = kind === "bad";
  $("#status").innerHTML = `<span class="state${problem ? " state-bad" : ""}" id="state" title="${esc(hint || "")}"><span class="dot ${kind === "busy" ? "warn" : kind}"></span><b>${esc(label)}</b></span>`
    + sysmonHtml()   // порядок: статус → ресурсы сервера → клиенты
    + (tg ? `<span>${esc(t("n.clients", { n: S.clients.length }) + sep("phrase") + t("status.online", { n: online }))}</span>` : "");
  if (problem) $("#state").onclick = () => window.scrollTo({ top: 0, behavior: "smooth" });
  // новая версия: метка в строке состояния (видна и на телефоне) и точка на вкладке «Система»
  const v = S.version || {};
  const chip = !updatingTo && v.available ? t("status.update", { version: v.latest }) : "";   // во время обновления говорит сам статус
  if (chip) $("#status").insertAdjacentHTML("beforeend", `<button type="button" class="upd-chip" id="upd-chip">${esc(chip)}</button>`);
  const uc = $("#upd-chip");
  if (uc) uc.onclick = () => goTab("system");
  $("#tabs [data-tab=system]").classList.toggle("has-news", !!v.available && !updatingTo);
  $$("#tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === tab));
}

/** Шапка: [вид, надпись, подсказка]; вид ok — зелёный, busy — жёлтый (переходное), bad — красный.
 *  Переходное состояние важнее ошибки, которую оно и вызывает (сервер перезапускается — интерфейса нет),
 *  ошибка важнее «Запуска…» (первый проход упал — это уже ошибка). */
function headerState() {
  if (pollFails >= OFFLINE_AFTER) {
    return updatingTo ? ["busy", t("status.updating_s")] : ["bad", t("status.offline"), t("status.offline_hint")];
  }
  const u = updState(), ae = S.awg_engine || {};
  if (updatingTo || u.state === "running") return ["busy", t("status.updating_s")];
  if (S.phase === "engine" || (ae.install || {}).state === "running") return ["busy", t("status.engine")];
  if (S.phase === "server_restart") return ["busy", t("status.server_restart")];
  const problem = statusProblem();
  if (problem) return ["bad", t("status.err"), problem];
  if (S.phase === "starting") return ["busy", t("status.starting"), t("status.starting_hint")];
  return ["ok", t("status.ok")];
}

/** Почему в шапке «Ошибка» (null — всё работает): нет сервера, его не создали, не применились правила. */
function statusProblem() {
  if (S.phase === "server_down") return t("status.server_down");
  if (S.phase === "starting" && !S.target_error && !(S.engine && S.engine.last_error)) return null;  // ещё ищет сервер
  const tg = S.target;
  if (!tg) return tm(S.target_error) || t("status.no_target");
  if (tg.exists === false) return t("srv.missing");
  if (S.target_error) return tm(S.target_error);
  if (S.engine && S.engine.last_error) return t("banner.apply_error") + ": " + tm(S.engine.last_error);
  if (S.sni && S.sni.strict) return t("rt.strict_now");
  return null;
}

function render(force = false) {
  // вкладка приходит из адреса (#…): Map вместо объекта, чтобы #toString или #__proto__ не доставали
  // свойства Object.prototype
  const views = new Map([["overview", viewOverview], ["clients", viewClients], ["exits", viewExits],
                         ["routing", viewRouting], ["server", viewServer], ["system", viewSystem]]);
  if (!views.has(tab)) tab = "overview";
  const sEl = $("#client-search");
  const keepSearch = sEl ? sEl.value : null;
  // поиск печатают, пока идёт опрос: перерисовка не должна уводить курсор из поля
  const keepCaret = sEl && document.activeElement === sEl ? [sEl.selectionStart, sEl.selectionEnd] : null;
  const html = banners() + views.get(tab)();
  if (!force && tab === "clients" && patchClients(html)) { fillSpeeds(); return; }
  if (tab === "clients" && clientParts) clientParts.banner = html.slice(0, html.length - clientParts.html.length);
  clientsShown = tab === "clients" ? clientParts : null;
  $("#main").innerHTML = html;
  watchRules($("#main"));
  const bindTab = new Map(Object.entries(bind)).get(tab);
  if (bindTab) bindTab();
  $$(".banner [data-goto]").forEach((b) => b.onclick = () => goTab(b.dataset.goto));
  $$("[data-eng]").forEach((b) => b.onclick = () => engAction(b.dataset.eng, b));
  const s2 = $("#client-search");
  if (keepSearch !== null && s2) {
    s2.value = keepSearch; filterClients();
    if (keepCaret) { s2.focus(); try { s2.setSelectionRange(...keepCaret); } catch { /* поле без выделения */ } }
  }
  $$("#tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === tab));
}

function banners() {
  let h = "";
  const code = (s) => `<span class="mono">${esc(s)}</span>`;
  if (updatingTo) h += `<div class="banner info"><b>${esc(updatingTo === CLI_UPDATE ? t("sy.updating_cli") : t("sy.updating", { version: updatingTo }))}</b> <span id="upd-line" class="small">${esc(updLine || t("sy.updating_wait"))}</span></div>`;
  if (S.demo) h += `<div class="banner info"><b>${esc(t("banner.demo_title"))}</b> ${th("banner.demo", { flag: code("DRY_RUN=1") })}</div>`;
  if (!S.target) h += `<div class="banner bad"><b>${esc(t("banner.no_target_title"))}</b> ${esc(tm(S.target_error))}<br><span class="small">${th("banner.no_target_hint", { a: code("pid: host"), b: code("privileged: true") })}</span></div>`;
  else if (serverMissing() && tab !== "server") h += `<div class="banner info"><b>${esc(t("srv.missing"))}</b> <button class="btn sm" data-goto="server">${esc(t("srv.create_title"))}</button></div>`;
  if (S.engine.last_error) h += `<div class="banner bad"><b>${esc(t("banner.apply_error"))}</b> ${esc(tm(S.engine.last_error))}</div>`;
  h += engineBanner();
  const goSys = `<button class="btn sm" data-goto="system">${esc(t("tab.system"))}</button>`;
  // Сертификат и обновление подробно показаны первыми на вкладке «Система» — там полоса не нужна
  if (tab !== "system") {
    const tls = tlsProblem();
    if (tls) h += `<div class="banner bad"><b>${esc(t(tls.key, tls.p))}</b> <bdi>${esc(tm(tls.error))}</bdi> ${goSys}</div>`;
    const u = updState(), v = S.version || {};
    if (!updatingTo && u.state === "failed" && v.available)
      h += `<div class="banner bad"><b>${esc(t("sy.update_failed", { version: u.to || v.latest }))}</b> ${goSys}</div>`;
  }
  const tg = S.settings.telegram || {};
  if (tg.enabled && S.notify_error) h += `<div class="banner bad"><b>${esc(t("banner.tg_failed"))}</b> <bdi>${esc(tm(S.notify_error))}</bdi>${S.notify_pending ? `<br><span class="small">${esc(t("banner.tg_pending", { n: S.notify_pending }))}</span>` : ""} ${goSys}</div>`;
  return h;
}

// Беда с сертификатом HTTPS, заметная пользователю: Let's Encrypt или свой сертификат не встал и панель
// отдаёт временный (браузер предупреждает), или продлить не удаётся, а до конца срока меньше
// TLS_WARN_BEFORE (столько же ждёт уведомление tls_fail в tlsmgr.py). Ошибка без последствий — когда
// действующий сертификат ещё долго годен, а повтор впереди, — полосы не даёт.
const TLS_WARN_BEFORE = 2 * 86400;
function tlsProblem() {
  const P = S.panel || {}, T = P.tls || {};
  if (P.access === "ssh" || !(T.mode === "letsencrypt" || T.mode === "selfsigned") || !T.error || T.busy) return null;
  if (T.source && T.active !== T.source) return { key: "banner.tls_fallback", p: {}, error: T.error };
  if (T.expires && T.expires - Date.now() / 1000 < TLS_WARN_BEFORE)
    return { key: "banner.tls_expiring", p: { date: fmtTime(T.expires) }, error: T.error };
  return null;
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
  if (p.udp != null) parts.push(esc(t(p.udp ? "probe.udp_ok" : "probe.udp_no")));
  return parts.join(" · ");
}
async function runProbe(k, after) {
  probes[k] = "…"; after();
  try { probes[k] = await api("POST", "probe", { outbound: k }); }
  catch (e) { probes[k] = { ok: false, error: e.message }; }
  after();
}

/* ================================================================ модалка */
function openModal(title, body, foot, tag) {
  const m = $("#modal");
  // tag — короткая метка рядом с заголовком (интерфейс выхода awgrN)
  const tg = tag ? ` <span class="tag mono" dir="ltr">${esc(tag)}</span>` : "";
  $("#modal-body").innerHTML = `<div class="modal-head"><h2><bdi>${esc(title)}</bdi>${tg}</h2><button class="icon-btn" data-close aria-label="${esc(t("btn.close"))}">✕</button></div>
    <div class="modal-body">${body}</div><div class="modal-foot">${foot}</div>`;
  $$("[data-close]", m).forEach((b) => b.onclick = closeModal);
  m.showModal();
}
function closeModal() { $("#modal").close(); }
/* Окно над окном (1.23.0): окно правила — и на «Маршрутизации», и в окне клиента; у него свой dialog */
function openModal2(title, body, foot) {
  const m = $("#modal2");
  $("#modal2-body").innerHTML = `<div class="modal-head"><h2><bdi>${esc(title)}</bdi></h2><button class="icon-btn" data-close aria-label="${esc(t("btn.close"))}">✕</button></div>
    <div class="modal-body">${body}</div><div class="modal-foot">${foot}</div>`;
  $$("[data-close]", m).forEach((b) => b.onclick = closeModal2);
  m.showModal();
}
function closeModal2() { $("#modal2").close(); }
const anyModal = () => $("#modal").open || $("#modal2").open;
// окно закрывает только нажатие на затемнение: выделение текста мышью, отпущенной за краем окна, — тоже «щелчок»
// по нему, и введённое пропадало
let downOnBackdrop = false;
for (const id of ["modal", "modal2"]) {
  $("#" + id).addEventListener("pointerdown", (e) => { downOnBackdrop = e.target.id === id; });
  $("#" + id).addEventListener("click", (e) => { if (e.target.id === id && downOnBackdrop) $("#" + id).close(); });
}
$("#modal2").addEventListener("close", () => {
  document.body.append($("#toasts"));
  if ($("#modal").open) { $("#modal").append($("#toasts")); return; }   // под ним окно клиента — оно на своём состоянии
  if (pendingS) { S = pendingS; pendingS = null; }
  render();
});
$("#modal").addEventListener("close", () => {
  document.body.append($("#toasts"));          // сообщения, начатые в окне, досматриваются после него
  if (pendingS) { S = pendingS; pendingS = null; }
  if (tab !== "routing") render();
});
