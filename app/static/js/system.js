// Вкладка «Система»: общие настройки, домен и сертификат панели, иконка на телефоне, обновление панели.
"use strict";

/* ================================================================ система */
function viewSystem() {
  const tg = S.target;
  const P = S.panel || {}, T = P.tls || {};
  const pub = P.access !== "ssh" && (T.mode === "letsencrypt" || T.mode === "selfsigned");
  const tlsLine = P.access === "ssh" ? t("sy.tls_ssh")
    : T.busy ? t("sy.tls_busy")
    : T.active === "letsencrypt" ? t("sy.tls_le", { date: fmtTime(T.expires) })
    : T.active === "custom" ? t("sy.tls_custom", { date: fmtTime(T.expires) })
    : T.active === "selfsigned" ? t("sy.tls_self") : t("sy.tls_off");
  const W = T.web;
  const webLine = !W ? "" : W.kind === "manual" ? t("web.manual_set", { server: webLabel(W) })
    : t("sy.tls_web_file", { server: webLabel(W) });
  const fallback = T.error && T.active !== T.source && !T.busy;
  return `
  <section class="section">
    <div class="section-head"><h2>${esc(t("sy.access"))}</h2></div>
    <div class="panel panel-pad">
      <div class="kv">
        <div><span>${esc(t("sy.url"))}</span><b><bdi>${esc(P.url || "—")}</bdi></b></div>
        <div><span>${esc(t("sy.access_mode"))}</span><b>${esc(t(P.access === "ssh" ? "sy.access_ssh" : "sy.access_public"))}</b></div>
        <div><span>${esc(t("sy.cert"))}</span><b>${esc(tlsLine)}</b></div>
        ${pub && W && T.source === "letsencrypt" ? `<div><span>${esc(t("sy.tls_web"))}</span><b style="word-break:normal">${esc(webLine)}</b>${W.file ? `<span class="muted small" dir="ltr" style="display:block;overflow-wrap:anywhere">${esc(W.file)}</span>` : ""}</div>` : ""}
        <div><span>${esc(t("sy.version"))}</span><b>${esc((S.version || {}).current || "—")}</b></div>
      </div>
      ${updateNotice()}
      ${pub && fallback && !T.port80 ? `<p class="err small" style="margin-bottom:0">${esc(t(T.source === "custom" ? "tls.src_custom" : "sy.tls_error"))}: ${esc(tm(T.error))}</p>` : ""}
      ${pub && T.port80 && T.source === "letsencrypt" && !W ? `<p class="warn-text small" style="margin-bottom:0">${esc(t("sy.tls_port80", { server: webLabel(T.port80) }))}</p>` : ""}
      <div class="actions" style="margin-top:12px">
        ${pub ? `<button class="btn sm" id="tls-setup">${esc(t("sy.tls_setup"))}</button>` : ""}
        ${pub && T.port80 && T.source === "letsencrypt" && !W ? `<button class="btn sm primary" id="tls-web">${esc(t("sy.tls_port80_btn"))}</button>` : ""}
        ${pub && T.source === "letsencrypt" && !T.port80 ? `<button class="btn sm" id="tls-renew">${esc(t("sy.tls_renew"))}</button>` : ""}
        ${pub && W ? `<button class="btn sm ghost" id="tls-web-rm">${esc(t("sy.tls_web_remove"))}</button>` : ""}
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
        <label class="field"><span>${esc(t("sy.panel_name"))}</span><input type="text" id="s-name" maxlength="40" data-field="panel_name" value="${esc(S.settings.panel_name || "")}" placeholder="${esc(S.panel.ip || "")}" dir="auto">
          <span class="hint">${esc(t("sy.panel_name_hint"))}</span></label>
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
          ${engineKv()}
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
    try {
      await api("PUT", "settings", { on_stop: onStop, panel_name: $("#s-name").value.trim() });
      toast(t("toast.settings_saved")); refreshKeep($("#s-save"));
    }
    catch (e) { toast(e.message, true); }
  };
  const rn = $("#tls-renew");
  if (rn) rn.onclick = async () => {
    rn.disabled = true; toast(t("toast.applying"));
    try { const r = await api("POST", "tls/renew", {}); toast(t(r.ok ? "toast.tls_ok" : "toast.tls_fail"), !r.ok); }
    catch (e) { toast(e.message, true); }
    refresh();
  };
  const ts = $("#tls-setup");
  if (ts) ts.onclick = tlsModal;
  const tw = $("#tls-web");
  if (tw) tw.onclick = async () => {
    tw.disabled = true;
    try { webModal(await api("GET", "tls/web")); } catch (e) { toast(e.message, true); }
    tw.disabled = false;
  };
  const tr = $("#tls-web-rm");
  if (tr) tr.onclick = async () => {
    const W = S.panel.tls.web;
    if (!confirm(t("web.remove_confirm", { file: W.file || webLabel(W), server: webLabel(W) }))) return;
    try { await api("POST", "tls/web", { action: "remove" }); toast(t("web.removed")); } catch (e) { toast(e.message, true); }
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

/* ================================================ домен и сертификат панели */
/** «nginx на этом сервере» / «nginx в контейнере web» — кто держит порт 80. */
function webLabel(w) {
  const name = w.process || "?";
  return w.where === "docker" ? t("web.in_docker", { name, container: w.container || "?" }) : t("web.on_host", { name });
}
function tlsModal() {
  const T = S.panel.tls || {};
  const ip = S.panel.ip || "";
  let src = T.source === "custom" ? "custom" : "letsencrypt";
  const certPh = "/etc/letsencrypt/live/example.com/fullchain.pem", keyPh = "/etc/letsencrypt/live/example.com/privkey.pem";
  const body = `
    <label class="field"><span>${esc(t("tls.domain"))}</span><input type="text" id="tls-domain" dir="ltr" autocomplete="off" spellcheck="false" value="${esc(T.domain || "")}" placeholder="panel.example.com">
      <span class="hint">${esc(t("tls.domain_hint", { ip: ip || "IP" }))}</span></label>
    <div class="field"><span>${esc(t("tls.source"))}</span>
      <div class="seg" id="tls-src"><button type="button" data-v="letsencrypt">${esc(t("tls.src_le"))}</button><button type="button" data-v="custom">${esc(t("tls.src_custom"))}</button></div>
      <span class="hint" id="tls-src-hint"></span></div>
    <div id="tls-files">
      <label class="field"><span>${esc(t("tls.cert"))}</span><input type="text" id="tls-cert" dir="ltr" autocomplete="off" spellcheck="false" value="${esc(T.cert || "")}" placeholder="${esc(certPh)}"></label>
      <label class="field"><span>${esc(t("tls.key"))}</span><input type="text" id="tls-key" dir="ltr" autocomplete="off" spellcheck="false" value="${esc(T.key || "")}" placeholder="${esc(keyPh)}"></label>
    </div>`;
  openModal(t("tls.title"), body, `<button class="btn ghost" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="tls-apply">${esc(t("tls.apply"))}</button>`);
  const paths = () => {
    const d = $("#tls-domain").value.trim().toLowerCase() || "example.com";
    return { cert: `/etc/letsencrypt/live/${d}/fullchain.pem`, key: `/etc/letsencrypt/live/${d}/privkey.pem` };
  };
  const isIp = (v) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || v.includes(":");
  const seg = () => {
    $$("#tls-src button").forEach((b) => b.setAttribute("aria-pressed", b.dataset.v === src));
    $("#tls-files").hidden = src !== "custom";
    const p = paths();
    const dom = $("#tls-domain").value.trim();
    const leHint = T.dns_configured && dom && !isIp(dom) ? t("tls.le_dns_hint") : t("tls.le_hint");
    $("#tls-src-hint").innerHTML = src === "custom" ? th("tls.custom_hint", { cert: `<bdi dir="ltr">${esc(p.cert)}</bdi>`, key: `<bdi dir="ltr">${esc(p.key)}</bdi>` }) : esc(leHint);
    $("#tls-cert").placeholder = p.cert; $("#tls-key").placeholder = p.key;
  };
  $$("#tls-src button").forEach((b) => b.onclick = () => { src = b.dataset.v; seg(); });
  $("#tls-domain").oninput = seg;
  seg();
  const apply = async (force) => {
    const btn = $("#tls-apply"); btn.disabled = true;
    const before = S.panel.url;
    try {
      const r = await api("PUT", "tls", { domain: $("#tls-domain").value.trim(), source: src,
        cert: $("#tls-cert").value.trim(), key: $("#tls-key").value.trim(), force: !!force });
      if (r.confirm) {
        btn.disabled = false;
        if (confirm(tm(r.confirm) + "\n\n" + t("tls.dns_force"))) return apply(true);
        return;
      }
      if (r.warn) toast(tm(r.warn), true);
      else toast(r.url && r.url !== before ? t("tls.moved", { url: r.url }) : t("tls.applying"));
      if (r.web && r.web.kind !== "none") webModal(r.web);
      else closeModal();
      refresh();
    } catch (e) { toast(e.message, true); btn.disabled = false; }
  };
  $("#tls-apply").onclick = () => apply(false);
}
/** Порт 80 занят веб-сервером: добавить наш файл (auto) или показать текст для вставки вручную. */
function webModal(w) {
  if (!w || w.kind === "none") { toast(t("web.free")); closeModal(); refresh(); return; }
  const server = webLabel(w);
  const text = w.auto ? t("web.auto", { file: w.file || "", host: w.host || "" })
    : `${tm(w.reason)}. ${t("web.manual", { dir: "/var/lib/awg-router/acme" })}`;
  const body = `<p>${esc(t("web.busy", { server }))}</p><p>${esc(text)}</p>
    <pre class="code" dir="ltr" id="web-snippet">${esc(w.snippet || "")}</pre>`;
  const foot = `<button class="btn ghost" data-close>${esc(t("btn.cancel"))}</button>
    <button class="btn" id="web-copy">${esc(t("web.copy"))}</button>
    <button class="btn primary" id="web-go">${esc(w.auto ? t("web.add", { server: w.process || "" }) : t("web.check"))}</button>`;
  openModal(t("web.title"), body, foot);
  $("#web-copy").onclick = () => copyText(w.snippet || "");
  $("#web-go").onclick = async () => {
    const b = $("#web-go"); b.disabled = true; toast(t("toast.applying"));
    try {
      await api("POST", "tls/web", { action: w.auto ? "add" : "manual" });
      closeModal(); toast(t("web.added", { server }));
    } catch (e) { toast(e.message, true); b.disabled = false; }
    refresh();
  };
}

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
// обновление запущено не из панели (`awg-router update` в консоли): версии, до которой идёт, страница не знает
const CLI_UPDATE = "-";
function followUpdate() {
  const u = updState(), v = S.version || {};
  if (!updatingTo && u.state === "running") setUpdating(u.cli ? CLI_UPDATE : (u.to || v.latest || "…"));   // начато в другом окне или в консоли
  if (!updatingTo) return false;
  const cli = updatingTo === CLI_UPDATE;
  if (cli ? u.state !== "running" : (u.state === "done" || (v.current && v.current === updatingTo))) {
    if (cli) { setUpdating(""); location.reload(); return true; }
    try { sessionStorage.setItem("awgr.updated", v.current || updatingTo); } catch { /* нет хранилища */ }
    setUpdating("");
    location.reload();
    return true;
  }
  if (u.state === "failed") { setUpdating(""); loadUpdateLog(); return false; }
  if (cli) return false;
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
