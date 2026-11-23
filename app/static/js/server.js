// Вкладка «Сервер»: маскировка I1–I5, параметры AWG, движок (модуль ядра), ограничение скорости, адреса.
"use strict";

/* ===================================================== сигнатурные пакеты I1–I5 */
const CPS_KEYS = ["I1", "I2", "I3", "I4", "I5"];
const CPS_SHORT = { icloud: "DNS icloud", stun: "STUN", quic: "QUIC", dns: "DNS", sip: "SIP" };
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

// поля по смыслу (владелец 2026-11-19): слева «Сервер AmneziaWG» — адреса, порт, подсеть, MTU; справа «DNS»
function viewServer() {
  if (!S.target) return `<div class="panel empty"><p>${esc(t("status.no_target"))}</p></div>`;
  if (!SRV) { loadServer(); return `<p class="muted">${esc(t("probe.checking"))}</p>`; }
  if (!SRV.exists) {
    // панель не ответила — это не «сервера нет»
    if (SRV.error) return `<div class="panel empty"><p>${esc(SRV.error)}</p><button class="btn" id="s-retry">${esc(t("btn.retry"))}</button></div>`;
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
      input = `<select data-p="${k}" data-field="params.${k}">${["", "on", "off"].map((v) => `<option value="${v}" ${d[k] === v ? "selected" : ""}>${v ? esc(t("srv.bool_" + v)) : "—"}</option>`).join("")}</select>`;
    } else if (meta.type === "text") {
      input = `<textarea data-p="${k}" data-field="params.${k}" dir="ltr" rows="2" spellcheck="false" placeholder="<b 0x…> <r 16>">${esc(d[k] || "")}</textarea>`;
    } else {
      input = `<input type="text" data-p="${k}" data-field="params.${k}" dir="ltr" value="${esc(d[k] || "")}" ${meta.type === "key" ? 'class="mono"' : ""}>`;
    }
    const size = meta.type === "text" ? `<span class="hint" id="sz-${k}">${cpsSizeHtml(d[k])}</span>` : "";
    const hint = t("p." + k) ? `<span class="hint">${esc(t("p." + k))}</span>` : "";
    return `<label class="field param ${meta.type === "text" || meta.type === "key" ? "param-wide" : ""}"><span><span class="pname" title="${esc(k)}">${esc(k)}</span>${side}</span>${input}${hint}${size}</label>`;
  };
  return `
  <div class="savebar" id="s-bar" ${srvDirty() ? "" : "hidden"}><span id="s-bar-text">${esc(t("srv.save_hint"))}</span>
    <span class="actions"><button class="btn sm" id="s-reset">${esc(t("btn.discard"))}</button><button class="btn sm primary" id="s-save">${esc(t("btn.save"))}</button></span></div>
  <div class="grid2 pair">
    <section class="section">
      <div class="section-head"><h2>${esc(t("srv.title"))}</h2><button class="btn" id="s-restart">${esc(t("srv.restart"))}</button></div>
      <div class="panel panel-pad">
        <div class="kv" style="margin-bottom:14px">
          <div><span>${esc(t("srv.kind"))}</span><b>${esc(kindLabel)}</b></div>
          <div><span>${esc(t("sy.iface"))}</span><b>${esc(SRV.iface)}</b></div>
          <div><span>${esc(t("srv.version"))}</span><b>${esc(SRV.version ? "AWG " + SRV.version : "WireGuard")}</b></div>
        </div>
        <label class="field"><span>${esc(t("srv.public_host"))}</span><input type="text" data-field="public_host" id="s-host" dir="ltr" value="${esc(SRV.public_host)}" placeholder="203.0.113.10"><span class="hint">${esc(t("srv.public_host_hint"))}</span></label>
        <label class="field"><span>${esc(t("srv.extra_hosts"))}</span><input type="text" data-field="extra_hosts" id="s-extra" dir="ltr" placeholder="203.0.113.20, vpn2.example.com" value="${esc((SRV.extra_hosts || []).join(", "))}"><span class="hint">${esc(t("srv.extra_hosts_hint"))}</span></label>
        <label class="field"><span>${esc(t("srv.client_host"))}</span><select data-field="client_host" id="s-ch">${clientHostOptions()}</select><span class="hint" id="s-ch-hint">${clientHostHint(SRV.client_host)}</span></label>
        <div class="row2">
          <label class="field"><span>${esc(t("srv.port"))}</span><input type="number" data-field="port" id="s-port" min="1" max="65535" value="${SRV.port}"><span class="hint">${esc(t("srv.port_hint"))}</span></label>
          <label class="field"><span>${esc(t("srv.subnet"))}</span><input type="text" data-field="address" id="s-addr" dir="ltr" value="${esc(SRV.address)}" ${SRV.subnet_locked ? "disabled" : ""}><span class="hint">${esc(t(SRV.subnet_lock === "container" ? "srv.subnet_container_hint" : SRV.subnet_locked ? "srv.subnet_locked_hint" : "srv.subnet_hint"))}</span></label>
        </div>
        <div class="row2">
          <label class="field"><span>MTU</span><input type="number" data-field="client_mtu" id="s-mtu" min="1100" max="1500" value="${SRV.client_mtu}"><span class="hint">${esc(t("srv.mtu_hint"))}</span></label>
          <label class="field"><span>PersistentKeepalive</span><input type="text" data-field="client_keepalive" id="s-ka" dir="ltr" value="${esc(SRV.client_keepalive)}" placeholder="${esc(t("srv.auto", { v: SRV.keepalive_auto }))}"><span class="hint">${esc(t("srv.ka_hint"))}</span></label>
        </div>
      </div>
    </section>
    <section class="section">
      <div class="section-head"><h2>${esc(t("srv.clients_title"))}</h2></div>
      <div class="panel panel-pad">
        <label class="field"><span>${esc(t("srv.dns_servers"))}</span><input type="text" data-field="client_dns" id="s-dns" dir="ltr" value="${esc((SRV.client_dns || []).join(", "))}"><span class="hint">${esc(t("srv.dns_hint"))}</span></label>
        <div class="field">
          <label class="check"><input type="checkbox" id="s-pdns" ${SRV.panel_dns ? "checked" : ""}><span>${esc(t("srv.panel_dns"))}</span></label>
          <span class="hint">${esc(t("srv.panel_dns_hint", { addr: SRV.panel_dns_addr || "—" }))}</span>
          ${panelDnsStatus()}
        </div>
        <div class="field">
          <label class="check"><input type="checkbox" id="s-domf" ${SRV.dom_filter ? "checked" : ""}><span>${esc(t("srv.dom_filter"))}</span></label>
          <span class="hint">${esc(t("srv.dom_filter_hint"))}</span>
          ${SRV.dom_filter && !SRV.panel_dns ? `<div class="small warn-text">${esc(t("srv.dom_filter_needs_dns"))}</div>` : ""}
        </div>
        <label class="field"><span>${esc(t("srv.pdns_enc"))}</span><select data-field="panel_dns_enc" id="s-pdns-enc">${["doh", "dot", "plain"].map((m) =>
          `<option value="${m}" ${(SRV.panel_dns_enc || "doh") === m ? "selected" : ""}>${esc(t("srv.pdns_enc_" + m))}</option>`).join("")}</select><span class="hint">${esc(t("srv.pdns_enc_hint"))}</span></label>
        <div class="field">
          <details class="small"><summary>${esc(t("srv.panel_dns_more"))}</summary>${["srv.panel_dns_why", "srv.panel_dns_cascade", "srv.panel_dns_best"].map((k) => `<p class="small">${esc(t(k))}</p>`).join("")}</details>
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
  </section>
  ${wgSection()}
  ${shapingSection()}
  ${socksSection()}
  ${engineSection()}`;
}
const KERNEL_CMD = "sudo awg-router install-kernel";
/** движок AmneziaWG: чем работают сервер и туннели к выходам, выбор для выходов, установка модуля ядра */
function engineSection() {
  const E = S.awg_engine;
  if (!E) return "";
  const m = E.module || {};
  // после смены движка или перезапуска сервер ещё поднимается — «запускается», а не «не запущен»
  const srv = E.server === "kernel" ? t("eng.kernel") : E.server === "go" ? "amneziawg-go"
    : t(S.phase === "engine" || S.phase === "server_restart" ? "eng.starting" : "eng.unknown");
  // версия — слева направо и без переноса: в fa «3.1.20260812» иначе рвалась на «.3» и «1.20260812»
  const ver = `<bdi dir="ltr" class="nowrap">${esc(m.version || "?")}</bdi>`;
  const mod = !m.loaded ? esc(t("eng.mod_none")) : m.ok ? th("eng.mod_ok", { version: ver })
    : th("eng.mod_old", { version: ver, min: esc(E.min) });
  return `
  <section class="section" id="engine">
    <div class="section-head"><div><h2>${esc(t("eng.title"))}</h2><p class="muted small">${esc(t("eng.sub"))}</p></div></div>
    <div class="panel panel-pad">
      ${E.old ? `<div class="banner bad">${esc(t("eng.old_warn", { version: E.old, min: E.min }))}</div>` : ""}
      ${E.fallback ? `<div class="banner bad">${esc(E.fallback.conf
        ? t("eng.fallback_conf", { iface: E.fallback.iface || "", error: tm(E.fallback.error) })
        : t("eng.fallback", { error: tm(E.fallback.error) }))}</div>` : ""}
      <div class="kv" style="margin-bottom:14px">
        <div><span>${esc(t("eng.server"))}</span><b><bdi>${esc(srv)}</bdi></b></div>
        <div><span>${esc(t("eng.module"))}</span><b>${mod}</b></div>
        <div><span>${esc(t("eng.exits"))}</span><b><bdi>${esc(E.exits_now === "kernel" ? t("eng.kernel") : "amneziawg-go")}</bdi></b></div>
      </div>
      ${engineChooser(E, m)}
      ${E.forced ? `<p class="small muted">${esc(t("eng.forced", { value: E.forced }))}</p>` : ""}
      <p class="small muted">${esc(t("eng.server_auto"))}</p>
      ${E.disabled ? `<div class="banner bad">${esc(t(E.disabled.error ? "eng.n_disabled_reboot" : "eng.n_disabled"))}</div>` : ""}
      ${engInstallBlock(E, m)}
    </div>
  </section>`;
}

/** «Движок» в «Подключении к Amnezia»: на чём работает сервер (у модуля — с версией). Туннели к выходам идут за
 *  сервером, поэтому отдельной строкой — только если движки разошлись (модуль не запустил туннель, EXIT_ENGINE). */
function engineKv() {
  const E = S.awg_engine;
  if (!E) return "";
  const m = E.module || {};
  const name = (e) => e === "kernel" ? t("sy.kernel") : e === "go" ? "amneziawg-go" : t("eng.unknown");
  const srv = E.server === "kernel" && m.version ? `${esc(t("sy.kernel"))} <bdi dir="ltr" class="nowrap">${esc(m.version)}</bdi>`
    : `<bdi>${esc(name(E.server))}</bdi>`;
  let h = `<div><span>${esc(t("sy.engine"))}</span><b>${srv}</b></div>`;
  if (E.server && E.exits_now !== E.server) h += `<div><span>${esc(t("sy.tunnels"))}</span><b><bdi>${esc(name(E.exits_now))}</bdi></b></div>`;
  return h;
}

/* ---------------------------------------- модуль ядра: оповещение сверху и установка кнопкой */
let engJob = null;          // последний ответ GET engine/install (журнал установки)
let engTimer = null;
let engWatching = false;    // установку запустили или застали в этой вкладке: по окончании — спросить о перезапуске

function engKind() {
  const n = (S.awg_engine || {}).notice;
  return n ? n.split(":")[0] : null;
}

/** Оповещение про модуль ядра (вид — engine_offer в app/api/server.py); «Скрыть» запоминает вид на сервере. */
function engineBanner() {
  const E = S.awg_engine || {}, kind = engKind();
  if (!kind) return "";
  const btn = (act, key, cls = "") => `<button class="btn sm ${cls}" data-eng="${act}">${esc(t(key))}</button>`;
  const text = kind === "disabled" && E.disabled && E.disabled.error ? t("eng.n_disabled_reboot")
    : t("eng.n_" + kind, { version: (E.module || {}).version || "?" });
  let acts = "";
  if (["offer", "old", "lost"].includes(kind)) acts = btn("install", "eng.btn_install");
  else if (kind === "disabled") acts = btn("install", "eng.btn_retry");
  else if (kind === "restart") acts = btn("restart", "srv.restart");
  if (kind === "installing") acts = btn("open", "eng.btn_details");
  else acts += " " + btn("hide", "eng.btn_hide", "ghost");
  return `<div class="banner ${["disabled", "old"].includes(kind) ? "bad" : "info"}"><b>${esc(text)}</b> ${acts}</div>`;
}

/** Ручной выбор движка — один на весь сервер (выходы идут следом). Модуль недоступен (сервер не подходит, модуля
 *  нет) — кнопка модуля неактивна; пока ставится модуль — обе. */
function engineChooser(E, m) {
  const cur = E.server || (E.choice === "go" ? "go" : null);
  const busy = ((engJob || E.install || {}).state) === "running";
  const kernelOk = E.fit || (m.loaded && m.ok);
  const b = (v, key, ok) => `<button type="button" data-eng-choose="${v}" aria-pressed="${cur === v}"${ok && !busy ? "" : " disabled"}>${esc(t(key))}</button>`;
  return `<div class="field" style="margin:4px 0 12px"><span>${esc(t("eng.choose"))}</span>
    <div class="seg">${b("kernel", "eng.opt_kernel", kernelOk)}${b("go", "eng.opt_go", true)}</div></div>`;
}

let engChoosing = false;   // выбор движка отправлен и ещё идёт (сервер перезапускается): drawEngine ждёт

async function engChoose(v) {
  const E = S.awg_engine || {};
  if (v === E.server) return;
  if (srvKeepTyped()) return;
  if (!confirm(t(v === "go" ? "eng.to_go_confirm" : "eng.to_kernel_confirm"))) return;
  $$("[data-eng-choose]").forEach((x) => x.disabled = true);
  engChoosing = true;
  try {
    const r = await api("POST", "engine/choose", { engine: v });
    if (r.action === "install") { engWatching = true; engWatch(); }
    else toast(t(r.reboot ? "eng.go_reboot" : "srv.restarting"));
  } catch (e) { toast(e.message, true); }
  engChoosing = false;
  await refresh();
  if (tab === "server") render();
}

/** Блок «Движок AmneziaWG» заново, если он изменился. Вкладку «Сервер» опрос не перерисовывает (поля формы), а после
 *  смены движка сервер перезапускается и определяется заново: без этого блок до перезагрузки страницы показывал
 *  прежний движок и не подсвечивал выбранный (владелец, 2026-11-20). Пока ставится модуль, блок ведёт engWatch. */
function drawEngine() {
  const el = $("#engine");
  if (!el || engChoosing || ((engJob || (S.awg_engine || {}).install || {}).state) === "running") return;
  const tpl = document.createElement("template");
  tpl.innerHTML = engineSection().trim();
  const fresh = tpl.content.firstElementChild;
  if (!fresh || fresh.outerHTML === el.outerHTML) return;
  el.replaceWith(fresh);
  bindEngine(fresh);
}
function bindEngine(root) {
  $$("[data-eng-choose]", root).forEach((b) => b.onclick = () => engChoose(b.dataset.engChoose));
  $$("[data-eng]", root).forEach((b) => b.onclick = () => engAction(b.dataset.eng, b));
  const ec = $("#eng-copy", root);
  if (ec) ec.onclick = () => copyText(KERNEL_CMD);
}

/** «Установка модуля ядра»: модуль уже работает — блока нет; сервер не подходит — только почему; иначе кнопка,
 *  журнал и та же команда для SSH. Требования не перечисляются: панель проверила сервер сама (kernelmod.fit). */
function engInstallBlock(E, m) {
  const job = engJob || E.install || {};
  if (m.loaded && m.ok && job.state !== "running" && !(engJob && engJob.state === "failed")) return "";
  if (E.choice === "go" && job.state !== "running") return "";     // выбран amneziawg-go: вернуться — переключателем
  if (!E.fit) return `<div class="field" style="margin-top:14px"><span>${esc(t("eng.install"))}</span>
    <p class="small">${esc(t("eng.no_fit"))} <bdi>${esc(tm(E.fit_why))}</bdi></p></div>`;
  return `<div class="field" style="margin-top:14px"><span>${esc(t("eng.install"))}</span>
    ${engInstallHtml(E, m)}
    <span class="hint">${esc(t("eng.or_ssh"))}</span>
    <pre class="code" dir="ltr">${esc(KERNEL_CMD)}</pre>
    <div><button class="btn sm" id="eng-copy">${esc(t("web.copy"))}</button></div></div>`;
}

/** Кнопка установки и журнал в разделе «Движок AmneziaWG». */
function engInstallHtml(E, m) {
  const job = engJob || E.install || {};
  const ready = m.loaded && m.ok;
  let h = "";
  if (job.state === "running") h += `<p class="small"><b>${esc(t("eng.inst_progress"))}</b></p>`;
  else if (job.state === "failed") h += `<p class="small bad">${esc(t("eng.inst_failed"))}</p>`;
  else if (job.state === "done" && ready) h += `<p class="small">${esc(t("eng.inst_done"))}</p>`;
  if (!ready && job.state !== "running")
    h += `<div><button class="btn sm primary" data-eng="install">${esc(t(E.disabled ? "eng.btn_retry" : "eng.btn_install"))}</button></div>`;
  if (engJob && engJob.log && engJob.log.length)
    h += `<pre class="code" dir="ltr" id="eng-log" style="margin-top:8px;max-height:220px">${esc(engJob.log.join("\n"))}</pre>`;
  return h;
}

async function engAction(act, b) {
  if (act === "open") { goTab("server"); setTimeout(() => { const el = $("#engine"); if (el) el.scrollIntoView(); }, 50); return; }
  if ((act === "hide" || act === "restart") && srvKeepTyped()) return;
  if (act === "hide") {
    try { await api("PUT", "engine", { hidden: S.awg_engine.notice }); await refresh(); } catch (e) { toast(e.message, true); }
    return;
  }
  if (act === "restart") {
    if (!confirm(t("srv.restart_confirm"))) return;
    try { await api("POST", "server/restart", {}); toast(t("srv.restarting")); } catch (e) { toast(e.message, true); }
    refresh();
    return;
  }
  if (act === "install") {
    if (!confirm(t("eng.inst_confirm"))) return;
    if (b) b.disabled = true;
    try {
      await api("POST", "engine/install", {});
      engWatching = true;
      engWatch();
      goTab("server");
      setTimeout(() => { const el = $("#engine"); if (el) el.scrollIntoView(); }, 50);
    } catch (e) { toast(e.message, true); if (b) b.disabled = false; }
  }
}

/** Пока модуль ставится — журнал раз в 2 с; по окончании — предложить перезапуск сервера. */
function engWatch() {
  clearTimeout(engTimer);
  const tick = async () => {
    try { engJob = await api("GET", "engine/install"); } catch { engTimer = setTimeout(tick, 4000); return; }
    const log = $("#eng-log");
    if (log) { log.textContent = (engJob.log || []).join("\n"); log.scrollTop = log.scrollHeight; }
    else if (tab === "server") render();
    if (engJob.state === "running") { engTimer = setTimeout(tick, 2000); return; }
    await refresh();
    if (tab === "server") render();
    if (!engWatching) return;
    engWatching = false;
    if (engJob.state === "done") {
      if (confirm(t("eng.inst_restart"))) {
        try { await api("POST", "server/restart", {}); toast(t("srv.restarting")); } catch (e) { toast(e.message, true); }
        refresh();
      }
    } else toast(t("eng.inst_failed"), true);
  };
  tick();
}
/** параллельный классический WireGuard (wg0) */
function wgSection() {
  const w = SRV.wg || { enabled: false, port: 51820, subnet: "10.8.2.0/24", subnet_locked: false };
  return `
  <section class="section">
    <div class="section-head"><div><h2>${esc(t("srv.wg_title"))}</h2><p class="muted small">${esc(t("srv.wg_hint"))}</p></div></div>
    <div class="panel panel-pad">
      <div class="field">
        <label class="check"><input type="checkbox" id="s-wg-on" ${w.enabled ? "checked" : ""}><span>${esc(t("srv.wg_enable"))}</span></label>
      </div>
      <div class="row2">
        <label class="field"><span>${esc(t("srv.wg_port"))}</span><input type="number" data-field="wg.port" id="s-wg-port" min="1" max="65535" value="${w.port || 51820}"></label>
        <label class="field"><span>${esc(t("srv.wg_subnet"))}</span><input type="text" data-field="wg.subnet" id="s-wg-subnet" dir="ltr" value="${esc(w.subnet || "10.8.2.0/24")}" ${w.subnet_locked ? "disabled" : ""}></label>
      </div>
    </div>
  </section>`;
}
/** общее ограничение скорости клиентов (своё сохранение, без перезапуска интерфейса) */
function shapingSection() {
  const sh = S.settings.shaping || {};
  return `
  <section class="section">
    <div class="section-head"><div><h2>${esc(t("sh.title"))}</h2><p class="muted small">${esc(t("sh.sub"))}</p></div></div>
    <div class="panel panel-pad">
      ${shapingNotice()}
      <div class="row2">
        <label class="field"><span>${esc(t("sh.down"))}</span><input type="number" id="sh-down" min="0" step="any" inputmode="decimal" placeholder="${esc(t("cl.no_limit"))}" value="${sh.down || ""}"></label>
        <label class="field"><span>${esc(t("sh.up"))}</span><input type="number" id="sh-up" min="0" step="any" inputmode="decimal" placeholder="${esc(t("cl.no_limit"))}" value="${sh.up || ""}"></label>
      </div>
      <p class="small muted" style="margin-top:-6px">${esc(t("sh.hint"))}</p>
      <button class="btn primary" id="sh-save">${esc(t("btn.save"))}</button>
    </div>
  </section>`;
}
/** публичный входящий SOCKS5-прокси */
function socksSection() {
  const sp = S.socks_proxy || { enabled: false, port: 1080, runtime: {} };
  const rt = sp.runtime || {};
  const badge = sp.enabled
    ? `<span class="state"><span class="dot ${rt.state === "on" ? "ok" : rt.state === "error" ? "bad" : ""}"></span>${esc(t(rt.state === "on" ? "sp.on" : rt.state === "error" ? "sp.err" : "sp.starting"))}</span>`
    : `<span class="state"><span class="dot"></span>${esc(t("st.disabled"))}</span>`;
  const errHtml = rt.state === "error" && rt.error
    ? `<div class="banner bad" style="margin-bottom:12px">${esc(tm(rt.error))}</div>` : "";
  return `
  <section class="section">
    <div class="section-head">
      <div><h2>${esc(t("sp.title"))}</h2><p class="muted small">${esc(t("sp.subtitle"))}</p></div>
      ${badge}
    </div>
    <div class="panel panel-pad">
      ${errHtml}
      <div class="field">
        <label class="check"><input type="checkbox" id="sp-en" ${sp.enabled ? "checked" : ""}><span>${esc(t("sp.enable"))}</span></label>
      </div>
      <div class="row2">
        <label class="field"><span>${esc(t("sp.port"))}</span><input type="number" id="sp-port" min="1" max="65535" dir="ltr" value="${esc(String(sp.port || 1080))}"></label>
      </div>
      <button class="btn primary" id="sp-save">${esc(t("btn.save"))}</button>
    </div>
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
  (SRV.extra_hosts || []).forEach((h) => { if (h !== SRV.public_host && !opts.some(([v]) => v === h)) opts.push([h, t("srv.ch_extra", { v: h })]); });
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
  return Object.keys(SRV.params).some((k) => (srvDraft[k] || "") !== (SRV.params[k] || "")) || srvFieldsDirty();
}
/** набранное в полях адреса, порта, MTU, DNS (не параметры маскировки): перерисовка вкладки его стирает */
function srvFieldsDirty() {
  if (!SRV) return false;
  const pdns = $("#s-pdns");
  const wgon = $("#s-wg-on");
  const w = SRV.wg || {};
  return (pdns && pdns.checked !== !!SRV.panel_dns) ||
    ($("#s-domf") && $("#s-domf").checked !== !!SRV.dom_filter) ||
    (wgon && wgon.checked !== !!w.enabled) ||
    ["#s-host", "#s-ch", "#s-extra", "#s-dns", "#s-pdns-enc", "#s-mtu", "#s-ka", "#s-port", "#s-addr", "#s-wg-port", "#s-wg-subnet"].some((sel) => {
      const el = $(sel); return el && el.dataset.orig !== undefined && el.value !== el.dataset.orig;
    });
}
/** кнопка, после которой вкладка «Сервер» перерисуется: несохранённое в полях — «Сначала сохраните» (глубокая проверка
    1.23.0: «Сгенерировать новые» и выбор движка молча стирали набранный адрес и DNS) */
function srvKeepTyped(all = true) {
  if (tab !== "server" || !(all ? srvDirty() : srvFieldsDirty())) return false;
  toast(t("srv.save_first"), true);
  flashBar($("#s-bar"));
  return true;
}
async function loadServer() {
  try { SRV = await api("GET", "server"); } catch (e) { SRV = { exists: false, error: e.message }; }
  srvDraft = null;
  if (tab === "server") render();
}
bind.server = () => {
  const retry = $("#s-retry");
  if (retry) retry.onclick = () => { SRV = null; render(); };
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
  if ($("#engine")) bindEngine($("#engine"));
  // кнопки ниже перерисовывают вкладку: несохранённые правки выше пропали бы без слова
  const saveFirst = () => {
    if (!srvDirty()) return false;
    toast(t("srv.save_first"), true);
    flashBar($("#s-bar"));
    return true;
  };
  $("#sh-save").onclick = async () => {
    if (saveFirst()) return;
    const b = $("#sh-save"); b.disabled = true;
    try {
      await api("PUT", "settings", { shaping: { down: $("#sh-down").value.trim() || null, up: $("#sh-up").value.trim() || null } });
      toast(t("toast.saved_applying")); await refresh();
    } catch (e) { toast(e.message, true); }
    b.disabled = false;
  };
  if ($("#sp-save")) $("#sp-save").onclick = async () => {
    const b = $("#sp-save"); b.disabled = true;
    try {
      await api("PUT", "socks/settings", {
        enabled: $("#sp-en").checked,
        port: Number($("#sp-port").value.trim()),
      });
      await refresh();
      toast(t("sp.saved"));
      loadServer();
    } catch (e) { if (!(e instanceof AuthError)) toast(e.message, true); }
    finally { b.disabled = false; }
  };
  const showBar = () => { $("#s-bar").hidden = !srvDirty(); };
  ["#s-host", "#s-ch", "#s-extra", "#s-dns", "#s-pdns-enc", "#s-mtu", "#s-ka", "#s-port", "#s-addr", "#s-wg-port", "#s-wg-subnet"].forEach((sel) => {
    const el = $(sel); if (!el) return;
    el.dataset.orig = el.value; el.oninput = showBar; el.onchange = showBar;
  });
  ["#s-pdns", "#s-domf"].forEach((sel) => { if ($(sel)) $(sel).onchange = showBar; });
  if ($("#s-wg-on")) $("#s-wg-on").onchange = showBar;

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
  $("#s-restart").onclick = async () => {
    if (saveFirst() || !confirm(t("srv.restart_confirm"))) return;
    const b = $("#s-restart");
    b.disabled = true;
    try { await api("POST", "server/restart", {}); toast(t("srv.restarting")); }
    catch (e) { toast(e.message, true); }
    finally { b.disabled = false; refresh(); }
  };
  $("#s-gen").onclick = async () => {
    if (srvKeepTyped(false)) return;              // параметры маскировки в черновике сохранятся, поля — нет
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
    // пустое поле или 0 — порт не меняется; неверный порт — ошибка у поля сразу, а не после двух предупреждений
    const portText = $("#s-port").value.trim(), addr = $("#s-addr").value.trim();
    const port = portText === "" || +portText === 0 ? SRV.port : +portText;
    const portErr = !Number.isInteger(port) || port < 1 || port > 65535 ? t("srv.bad_port")
      : port !== SRV.port && port === 53 ? t("srv.port_dns", { port }) : null;      // 53 — DNS на сервере
    if (portErr) { toast(portErr, true); markField({ field: "port" }, $("#main")); return; }
    const restart = serverSide || port !== SRV.port || (!SRV.subnet_locked && addr !== SRV.address);
    if (restart && !confirm(t(SRV.kind === "container" && serverSide ? "srv.confirm_restart_amnezia" : "srv.confirm_restart"))) return;
    // клиенты из приложения AmneziaVPN: их ключ только на устройстве, новый конфиг с новым портом панель не выдаст
    const appMade = port !== SRV.port ? S.clients.filter((c) => !c.has_config).length : 0;
    if (appMade && !confirm(t("srv.confirm_port_app", { n: appMade }))) return;
    const body = { public_host: $("#s-host").value.trim(), client_host: $("#s-ch").value, extra_hosts: $("#s-extra").value, client_dns: $("#s-dns").value,
      panel_dns: $("#s-pdns").checked, dom_filter: $("#s-domf").checked, panel_dns_enc: $("#s-pdns-enc").value, client_mtu: +$("#s-mtu").value, client_keepalive: $("#s-ka").value.trim() };
    if ($("#s-wg-on")) {
      body.wg = {
        enabled: $("#s-wg-on").checked,
        port: +$("#s-wg-port").value,
        subnet: $("#s-wg-subnet").value.trim(),
      };
    }
    if (Object.keys(changed).length) body.params = changed;
    body.port = port;
    if (!SRV.subnet_locked) body.address = addr;
    $("#s-save").disabled = true;
    try {
      const r = await api("PUT", "server", body);
      toast(t(r.restarted ? "toast.server_restarted" : "toast.settings_saved"));
      // новый порт или подсеть — тоже новые конфиги у всех клиентов (Endpoint, Address)
      const moved = port !== SRV.port || (!SRV.subnet_locked && addr !== SRV.address);
      if (r.server_side_changed || r.host_changed || r.dns_changed || moved) toast(t("toast.reimport"));
      SRV = null; srvDraft = null; await refresh(); loadServer();
    } catch (e) { toast(e.message, true); markField(e, $("#main")); $("#s-save").disabled = false; }
  };
};

// состояние DNS панели под переключателем (вкладка «Сервер»)
function panelDnsStatus() {
  const d = SRV.panel_dns_state;
  if (!SRV.panel_dns || !d) return "";
  if (d.state === "error") return `<div class="small warn-text">${esc(tm(d.error))}</div>`;
  const n = d.queries != null ? t("srv.panel_dns_stats", { q: d.queries, c: d.cached || 0 }) : "";
  const mode = t("srv.pdns_mode_" + (d.encrypt || "plain"));
  return `<div class="small muted">${esc(t("srv.panel_dns_on", { addr: d.listen }))} · ${esc(mode)}${n ? " · " + esc(n) : ""}</div>`
    + (d.upstream_error ? `<div class="small warn-text">${esc(t("srv.panel_dns_upfail", { error: d.upstream_error }))}</div>` : "")
    // шифрованный DNS не проходит напрямую из страны сервера (1.22.0): с местным DNS — что спрашивается у него
    + (d.direct_down ? `<div class="small warn-text">${esc(d.direct_down.fallback.length
      ? t("srv.pdns_direct_fb", { dns: d.direct_down.fallback.join(", ") }) : t("srv.pdns_direct_down"))}</div>` : "");
}
