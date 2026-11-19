// Вкладка «Система»: Telegram, пароль и вход по коду (2FA), резервная копия.
"use strict";

/* ===================================================== уведомления в Telegram */
const TG_KINDS = ["exit", "server", "system", "clients", "login", "tls", "update"];
function viewTelegram() {
  const c = S.settings.telegram || {};
  const ev = c.events || {};
  return `
  <section class="section">
    <div class="section-head"><div><h2>${esc(t("tg.title"))}</h2><p class="muted small">${esc(t("tg.sub"))}</p></div></div>
    <div class="panel panel-pad">
      <label class="check"><input type="checkbox" id="tg-on" ${c.enabled ? "checked" : ""}><span><b>${esc(t("tg.enable"))}</b></span></label>
      <label class="check" style="margin-top:6px"><input type="checkbox" id="tg-control" ${c.control ? "checked" : ""}><span><b>${esc(t("tg.control"))}</b></span></label>
      ${c.enabled && (c.control || c.clients !== false) && S.tg_bot ? `<div style="margin:6px 0 12px">${viewBotState(S.tg_bot)}</div>` : ""}
      <div class="tg-cols"><div>
      <label class="field"><span>${esc(t("tg.token"))}</span>
        <input type="text" data-field="token" id="tg-token" autocomplete="off" spellcheck="false" dir="ltr"
          placeholder="${esc(c.token_set ? t("tg.token_saved", { hint: c.token_hint }) : "123456789:AA…")}">
        <span class="hint">${th("tg.token_hint", { bot: "<bdi><b>@BotFather</b></bdi>" })}</span></label>
      <div class="field"><span>${esc(t("tg.chat"))}</span>
        <div class="input-btn"><input type="text" data-field="chat_id" id="tg-chat" autocomplete="off" spellcheck="false" dir="ltr" value="${esc(c.chat_id || "")}">
          <button type="button" class="btn sm" id="tg-detect">${esc(t("tg.find"))}</button></div>
        <span class="hint">${esc(t("tg.chat_hint"))}</span></div>
      <label class="field"><span>${esc(t("tg.lang"))}</span>
        <select id="tg-lang" style="max-width:220px">${Object.entries(LANGS).map(([k, v]) =>
          `<option value="${k}" ${k === (c.enabled || c.token_set ? c.lang : LANG) ? "selected" : ""}>${v.name}</option>`).join("")}</select></label>
      <label class="field"><span>${esc(t("tg.via"))}</span>
        <select data-field="via" id="tg-via" style="max-width:320px">${[["direct", t("out.direct")],
          ...S.upstreams.map((u) => ["up:" + u.id, u.name])].map(([v, l]) =>
          `<option value="${esc(v)}" ${v === (c.via || "direct") ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>
        <span class="hint">${esc(t("tg.via_hint"))}</span></label>
      <label class="check" style="margin:0 0 14px"><input type="checkbox" id="tg-fb" ${c.fallback !== false ? "checked" : ""}><span>${esc(t("tg.fallback"))}</span></label>
      ${c.enabled && S.tg_path ? `<p class="small warn-text" style="margin:-6px 0 12px">${th("tg.path_now", { name: `<bdi>${esc(exitName(S.tg_path.via))}</bdi>` })}</p>` : ""}
      </div><div class="field"><span>${esc(t("tg.events"))}</span>
        ${TG_KINDS.map((k) => `<label class="check"><input type="checkbox" id="tg-ev-${k}" ${ev[k] !== false ? "checked" : ""}><span>${esc(t("tg.ev_" + k))}</span></label>`).join("")}</div></div>
      <fieldset class="pgroup" style="margin:4px 0 12px"><legend>${esc(t("tg.clients_title"))}</legend>
        <label class="check"><input type="checkbox" id="tg-clients" ${c.clients !== false ? "checked" : ""}><span><b>${esc(t("tg.clients"))}</b></span></label>
        <p class="small muted" style="margin:6px 0 0">${esc(t("tg.clients_hint"))}</p>
        ${c.clients !== false && S.tg_bot && S.tg_bot.linked ? `<p class="small muted">${esc(t("tg.clients_linked", { n: S.tg_bot.linked }))}</p>` : ""}
      </fieldset>
      <fieldset class="pgroup" style="margin-top:4px"><legend>${esc(t("tg.backup"))}</legend>
        <div class="tg-cols"><div>
          <label class="field"><span>${esc(t("tg.backup_when"))}</span>
            <select id="tg-bk" style="max-width:220px">${["off", "daily", "weekly"].map((k) =>
              `<option value="${k}" ${(c.backup || "off") === k ? "selected" : ""}>${esc(t("tg.backup_" + k))}</option>`).join("")}</select></label>
          <label class="field"><span>${esc(t("tg.backup_pw"))}</span>
            <input type="password" data-field="backup_pw" id="tg-bk-pw" autocomplete="new-password" maxlength="128" dir="ltr"
              placeholder="${esc(t(c.backup_pw_set ? "tg.backup_pw_set" : "tg.backup_pw_none"))}"></label>
          ${c.backup_pw_set ? `<label class="check"><input type="checkbox" id="tg-bk-clear"><span>${esc(t("tg.backup_pw_clear"))}</span></label>` : ""}
        </div><div>
          <p class="small muted" style="margin-top:0">${esc(t("tg.backup_hint"))}</p>
          ${c.backup_error ? `<p class="err small">${esc(t("tg.backup_failed", { error: tm(c.backup_error) }))}</p>`
            : c.backup_last ? `<p class="small">${esc(t("tg.backup_last", { time: fmtDay(c.backup_last) + dtSep() + fmtTime(c.backup_last) }))}</p>` : ""}
          <button type="button" class="btn sm" id="tg-bk-send">${esc(t("tg.backup_send"))}</button>
        </div></div>
      </fieldset>
      ${c.enabled && S.notify_error ? `<p class="err small">${esc(t("tg.last_error"))}: <bdi>${esc(tm(S.notify_error))}</bdi></p>` : ""}
      <div class="actions"><button class="btn sm primary" id="tg-save">${esc(t("btn.save"))}</button><button class="btn sm" id="tg-test">${esc(t("tg.test"))}</button></div>
    </div>
  </section>`;
}
/* Состояние бота: слушает ли (управление или клиенты) и когда была последняя команда */
function viewBotState(b) {
  const out = [];
  if (b.state === "error") out.push(`<p class="err small">${esc(t("tg.bot_error"))}: <bdi>${esc(tm(b.error))}</bdi></p>`);
  else if (b.state === "ok") out.push(`<p class="small"><span class="dot ok"></span> ${esc(t("tg.bot_ok"))}</p>`);
  if (b.last) out.push(`<p class="small muted">${esc(t("tg.bot_last", { time: fmtDay(b.last) + dtSep() + fmtTime(b.last) }))}</p>`);
  if (b.skew) out.push(`<p class="small muted">${esc(t("tg.bot_skew", { n: Math.round(Math.abs(b.skew) / 60) || 1 }))}</p>`);
  return out.join("");
}
function bindTelegram() {
  const body = () => {
    const events = {};
    TG_KINDS.forEach((k) => { events[k] = $("#tg-ev-" + k).checked; });
    return { enabled: $("#tg-on").checked, token: $("#tg-token").value.trim(),
      chat_id: $("#tg-chat").value.trim(), lang: $("#tg-lang").value, via: $("#tg-via").value, events,
      fallback: $("#tg-fb").checked,
      // напоминания клиентам — та же галочка (1.23.0); поле остаётся для отката на 1.22.0
      control: $("#tg-control").checked, clients: $("#tg-clients").checked, client_notify: $("#tg-clients").checked,
      backup: $("#tg-bk").value, backup_pw: $("#tg-bk-pw").value,
      backup_pw_clear: !!($("#tg-bk-clear") && $("#tg-bk-clear").checked) };
  };
  const busy = (id, fn) => async () => {
    const b = $(id); b.disabled = true;
    try { await fn(); } catch (e) { if (!(e instanceof AuthError)) { toast(e.message, true); markField(e, $("#main")); } }
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
      <div><span>${esc(t("bk.created"))}</span><b>${esc(b.created ? fmtDay(b.created) + dtSep() + dateFmt({ hour: "2-digit", minute: "2-digit" }).format(new Date(b.created * 1000)) : "—")}</b></div>
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
      if (e.keepCode) return;          // ошибка не в коде (пароль): код ещё годен, фокус уже где нужно
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
        <p style="margin-top:0"><b>${esc(fmtNum(1))}.</b> ${esc(t("sec.step1"))}</p>
        <p class="muted small" style="margin-bottom:4px">${esc(t("sec.manual"))}</p>
        <p class="mono" dir="ltr" style="margin:0 0 6px;overflow-wrap:anywhere">${esc(key)}</p>
        <button type="button" class="btn sm" id="totp-copy">${esc(t("sec.copy_key"))}</button>
        <p style="margin-bottom:6px"><b>${esc(fmtNum(2))}.</b> ${esc(t("sec.step2"))}</p>
        ${codeField("totp-code", t("sec.code"))}
        <label class="field"><span>${esc(t("pw.current"))}</span><input type="password" id="totp-pw" autocomplete="current-password" maxlength="128"></label>
      </div>
    </div>`,
  `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="totp-ok">${esc(t("sec.enable"))}</button>`);
  $("#totp-copy").onclick = () => copyText(r.secret);
  $("#totp-pw").onkeydown = (e) => { if (e.key === "Enter") $("#totp-ok").click(); };
  // ошибка пароля: введённый код не стирается (сервер его ещё не принял), курсор — в поле пароля
  const pwError = (e) => { e.keepCode = true; $("#totp-pw").value = ""; setTimeout(() => $("#totp-pw").focus()); return e; };
  modalAction("totp-ok", "totp-code", async (code) => {
    // включение 2FA — с паролем панели: чужая открытая сессия не должна закрыть владельцу вход своим кодом
    const password = $("#totp-pw").value;
    if (!password) throw pwError(new Error(t("sec.need_password")));
    try { await api("POST", "totp/enable", { code, password }); }
    catch (e) { throw e.key === "err.wrong_password" ? pwError(e) : e; }
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
