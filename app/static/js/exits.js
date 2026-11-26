// Вкладка «Выходы»: карточки выходов и окно выхода (AmneziaWG и SOCKS5).
"use strict";

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
          <h3><bdi>${esc(u.name)}</bdi>${ver ? ` <span class="tag">${esc(ver)}</span>` : ""}</h3>
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
          ${acctOn() && u.enabled ? `<div><span>${esc(t("ex.speed"))}</span><b>${speedHtml(u)}</b></div>` : ""}
          ${(u.rate_down || u.rate_up) && !(acctOn() && u.enabled) ? `<div><span>${esc(t("ex.rate"))}</span><b>${rateHtml(u.rate_down, u.rate_up)}</b></div>` : ""}
          ${balOn() && u.balance ? `<div><span>${esc(t("ex.bal"))}</span><b>${esc(t("ex.bal_clients", { n: u.bal_clients }))}</b></div>` : ""}
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
    ${off}${shapingNotice()}
    ${cards || `<div class="panel empty"><p>${esc(t("ex.empty"))}</p><p class="small">${esc(t("ex.empty_hint"))}</p></div>`}
    ${direct}
  </section>`;
}
bind.exits = () => {
  const add = () => editUpstream(null);
  $("#add-up").onclick = add;
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
    <label class="field"><span>${esc(t("ex.name"))}</span><input type="text" data-field="name" id="u-name" maxlength="40" value="${esc(u ? u.name : "")}" placeholder="${esc(t("ex.name_ph"))}"></label>
    <div id="u-sf">
      <div class="row2 row2-port">
        <label class="field"><span>${esc(t("ex.socks_host"))}</span><input type="text" data-field="config" id="u-sh" dir="ltr" spellcheck="false" autocomplete="off" placeholder="203.0.113.20"></label>
        <label class="field"><span>${esc(t("ex.socks_port"))}</span><input type="text" data-field="config" id="u-sp" dir="ltr" inputmode="numeric" maxlength="5" autocomplete="off" placeholder="1080"></label>
      </div>
      <div class="row2">
        <label class="field"><span>${esc(t("ex.socks_user"))}</span><input type="text" data-field="config" id="u-su" dir="ltr" spellcheck="false" autocomplete="off" placeholder="${esc(t("ex.socks_opt"))}"></label>
        <label class="field"><span>${esc(t("ex.socks_pass"))}</span><input type="password" data-field="config" id="u-sw" dir="ltr" autocomplete="new-password" placeholder="${esc(t("ex.socks_opt"))}"></label>
      </div>
      <div class="field"><label class="check"><input type="checkbox" data-field="quic" id="u-quic" ${u && u.quic === true && u.kind === "socks5" ? "checked" : ""}><span>${esc(t("ex.socks_quic"))}</span></label>
        <span class="hint">${esc(t("ex.socks_quic_hint"))}</span></div>
    </div>
    <label class="field"><span id="u-conf-l"></span>
      <textarea data-field="config" id="u-conf" dir="ltr" spellcheck="false"></textarea>
      <span class="hint" id="u-conf-h"></span>
    </label>
    <div class="field" id="u-filef"><input type="file" id="u-file" accept=".conf,.txt,.vpn" aria-label="${esc(t("ex.file"))}"></div>
    <fieldset class="subbox" id="u-route">
      <legend>${esc(t("ex.route_title"))}</legend>
      <p class="small muted" style="margin-top:0">${esc(t("ex.route_hint"))}</p>
      <label class="field"><span>${esc(t("ex.route_sites"))}</span>
        <textarea data-field="routing" id="u-doms" class="short" dir="ltr" spellcheck="false" placeholder="${esc(t("ex.route_sites_ph"))}">${esc(ownText)}</textarea>
        <span class="hint">${esc(t("ex.route_sites_hint"))}</span></label>
      ${group(t("ex.route_dlists"), dlists)}
      ${group(t("ex.route_nlists"), nlists)}
      <label class="check"><input type="checkbox" id="u-rdef" ${out && S.routing.default === out ? "checked" : ""}><span>${esc(t("ex.route_default"))}</span></label>
    </fieldset>
    <label class="field"><span>${esc(t("ex.fallback"))}</span>
      <select data-field="fallback" id="u-fb">${outOptions(u ? u.fallback : "block", { exclude: out })}</select>
      <span class="hint">${esc(t("ex.fallback_hint"))}</span>
    </label>
    ${directAddrs().length ? `<label class="field"><span>${esc(t("ex.bind"))}</span>
      <select data-field="bind" id="u-bind">${bindOptions(u ? u.bind || "" : "")}</select>
      <span class="hint">${esc(t("ex.bind_hint"))}</span></label>` : ""}
    <div class="row2">
      <label class="field"><span>${esc(t("ex.quota"))}</span>
        <input type="number" data-field="quota_gb" id="u-quota" min="0" step="any" inputmode="decimal" placeholder="${esc(t("cl.no_limit"))}" value="${u && u.quota ? +(u.quota / 1024 ** 3).toFixed(3) : ""}"></label>
      <label class="field"><span>${esc(t("ex.quota_action"))}</span>
        <select data-field="quota_action" id="u-qa">${quotaOptions(u)}</select></label>
    </div>
    <p class="small muted" style="margin:-6px 0 14px">${esc(t("ex.quota_hint", { time: monthResetLocal() }))}</p>
    <div class="row2">
      <label class="field"><span>${esc(t("ex.rate_down"))}</span>
        <input type="number" data-field="rate_down" id="u-rd" min="0" step="any" inputmode="decimal" placeholder="${esc(t("cl.no_limit"))}" value="${u && u.rate_down ? u.rate_down : ""}"></label>
      <label class="field"><span>${esc(t("ex.rate_up"))}</span>
        <input type="number" data-field="rate_up" id="u-ru" min="0" step="any" inputmode="decimal" placeholder="${esc(t("cl.no_limit"))}" value="${u && u.rate_up ? u.rate_up : ""}"></label>
    </div>
    <p class="small muted" style="margin:-6px 0 14px">${esc(t("ex.rate_hint"))}</p>
  `, `<button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="u-save">${esc(t(u ? "btn.save" : "btn.add"))}</button>`,
  u && u.iface);
  const F = { host: $("#u-sh"), port: $("#u-sp"), user: $("#u-su"), pass: $("#u-sw") };
  const ta = $("#u-conf");
  let routeTouched = false, rdefTouched = false;
  // новый выход AWG становится основным, если основного ещё нет и в нём не вписаны свои сайты: вписали сайты — выход для
  // них, а не для всего трафика (решение владельца 2026-11-21)
  const rdefAuto = () => kind !== "socks5" && S.routing.default === "direct" && !$("#u-doms").value.trim();
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
    $("#u-sf").hidden = !socks;
    $("#u-filef").hidden = socks;
    // новый выход AWG, пока ничего не выбрано, становится основным, если основного ещё нет (как раньше)
    if (!u && !routeTouched) $("#u-rdef").checked = rdefAuto();
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
  $("#u-rdef").addEventListener("change", () => { rdefTouched = true; });
  $("#u-doms").addEventListener("input", () => { if (!u && !rdefTouched) $("#u-rdef").checked = rdefAuto(); });
  $("#u-file").onchange = async (e) => {
    const f = e.target.files[0]; if (!f) return;
    ta.value = buf.awg = (await f.text()).trim();
    if (!$("#u-name").value) $("#u-name").value = f.name.replace(/\.(conf|txt|vpn)$/i, "").slice(0, 40);
  };
  draw();
  $("#u-save").onclick = async () => {
    if (badNumber(["u-quota", "u-rd", "u-ru"])) return;
    const body = { name: $("#u-name").value.trim(), fallback: $("#u-fb").value,
      quota_gb: $("#u-quota").value.trim(), quota_action: $("#u-qa").value,
      rate_down: $("#u-rd").value.trim() || null, rate_up: $("#u-ru").value.trim() || null };
    const c = ta.value.trim();
    if (!u || c !== conf.trim()) body.config = c;
    if (kind === "socks5") body.quic = $("#u-quic").checked;
    if ($("#u-bind")) body.bind = $("#u-bind").value;          // «Подключаться с адреса» (1.25.0)
    if (routeTouched || !u) {
      const picked = $$("#u-route [data-rl]").filter((x) => x.checked).map((x) => x.dataset.rl);
      body.routing = { domains: $("#u-doms").value.trim(), default: $("#u-rdef").checked,
        domain_lists: picked.filter((x) => dlists.some((l) => l.id === x)),
        net_lists: picked.filter((x) => nlists.some((l) => l.id === x)) };
      if (!u && !body.routing.domains && !picked.length && !body.routing.default) delete body.routing;
    }
    const btn = $("#u-save"); btn.disabled = true;
    try {
      const r = u ? await api("PUT", "upstreams/" + u.id, body) : await api("POST", "upstreams", body);
      closeModal(); toast(t(u ? "toast.exit_saved" : "toast.exit_added"));
      reconnectToast(r);
      refresh();
    } catch (e) { toast(e.message, true); markField(e, $("#modal")); }
    btn.disabled = false;
  };
}
