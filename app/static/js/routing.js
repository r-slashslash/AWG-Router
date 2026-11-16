// Вкладка «Маршрутизация»: редактор правил, общие правила, балансировка и списки сетей и доменов.
"use strict";

/* ================================================================ редактор правил */
const LIST_KINDS = ["country", "asn", "url", "manual", "domains"];
function addListTo(r, id) {
  if (!r.lists.includes(id)) r.lists.push(id);
}
const isDomainList = (id) => (listObj(id) || {}).kind === "domains";
function rulesEditor(box, rules, onChange, { create = null } = {}) {
  const draw = () => {
    const items = rules.map((r, i) => {
      // списки доменов — отдельные правила (по имени сайта, раньше правил по адресам), выход любой
      const dom = r.lists.some(isDomainList);
      const addable = S.lists.filter((l) => !r.lists.includes(l.id) && (!r.lists.length || (l.kind === "domains") === dom));
      const kinds = LIST_KINDS.filter((k) => !r.lists.length || (k === "domains") === dom);
      return `
      <div class="rule ${r.enabled ? "" : "off"}" data-i="${i}">
        <div class="rule-n">${esc(fmtNum(i + 1))}</div>
        <div>
          <div class="rule-lists">
            ${r.lists.map((l) => `<span class="chip"><span>${listLabel(l)}</span><button type="button" data-rm-list="${esc(l)}" aria-label="${esc(t("re.remove_list"))}">×</button></span>`).join("")}
            <select class="add-list" data-add-list aria-label="${esc(t("re.add_list"))}"><option value="">${esc(t("re.add_list"))}</option>${addable.map((l) => `<option value="${esc(l.id)}">${esc(listName(l.id))}</option>`).join("")}${create ? `<optgroup label="${esc(t("re.new_list"))}">${kinds.map((k) => `<option value="new:${k}">＋ ${esc(t("ls.new." + k))}</option>`).join("")}</optgroup>` : ""}</select>
          </div>
          <input type="text" class="rule-comment" data-comment value="${esc(r.comment || "")}" placeholder="${esc(t("re.comment_ph"))}" maxlength="80">
          ${dom ? `<div class="small muted" style="margin-top:4px">${esc(t("re.domain_hint"))}</div>` : ""}
        </div>
        <div class="rule-then"><label>${esc(t(dom ? "re.then_sites" : "re.then"))}</label><select data-out>${outOptions(r.outbound)}</select></div>
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
function routingNow() {
  return { default: S.routing.default, rules: S.routing.rules,
    balance: { on: balOn(), skip: (S.routing.balance && S.routing.balance.skip) || [] }, strict: !!S.routing.strict };
}
function routingDirty() {
  if (!routingDraft) return false;
  return JSON.stringify(routingDraft) !== JSON.stringify(routingNow());
}
/** выходы балансировки: галочки и состояние каждого */
function balBox(d) {
  if (!S.upstreams.length) return `<p class="small muted" style="margin:0">${esc(t("bal.no_exits"))}</p>`;
  const live = new Set(balMembers());
  const row = (u) => {
    const on = !d.balance.skip.includes(u.id);
    const why = !on ? "" : live.has(u.id) ? t("ex.bal_clients", { n: u.bal_clients || 0 })
      : !u.enabled ? t("bal.off") : quotaSwitched(u) ? t("bal.quota") : t("bal.down");
    return `<label class="check"><input type="checkbox" data-bal="${esc(u.id)}" ${on ? "checked" : ""}><span><bdi>${esc(u.name)}</bdi>${why ? ` <span class="muted small">— ${esc(why)}</span>` : ""}</span></label>`;
  };
  return `<div class="field"><span>${esc(t("bal.exits"))}</span><div class="check-cols">${S.upstreams.map(row).join("")}</div></div>`;
}
function viewRouting() {
  const rd = routingDraft || routingNow();
  return `
  <section class="section">
    <div class="section-head"><div><h2>${esc(t("rt.title"))}</h2><p class="muted small">${esc(t("rt.subtitle"))}</p></div></div>
    <div id="g-rules"></div>
    <div class="default-row" style="margin-top:8px">
      <div class="rule-n" style="padding:0">∗</div>
      <div><b>${esc(t("rt.else"))}</b><div class="small muted">${esc(t("rt.else_sub"))}</div></div>
      <select id="g-default"><option value="balance" ${rd.balance.on ? "selected" : ""}>${esc(t("bal.option"))}</option>${outOptions(rd.balance.on ? "" : rd.default)}</select>
      <div></div>
    </div>
    <div class="panel panel-pad bal-box" id="g-bal" ${rd.balance.on ? "" : "hidden"}>
      <p class="small muted" style="margin-top:0">${esc(t("bal.hint"))}</p>
      <div id="g-bal-exits">${balBox(rd)}</div>
      <label class="field" style="margin-bottom:0"><span>${esc(t("bal.fallback"))}</span>
        <select id="g-bal-fb">${outOptions(rd.default)}</select><span class="hint">${esc(t("bal.fallback_hint"))}</span></label>
    </div>
    ${S.lists.some((l) => l.kind === "domains") || rd.strict ? `<div class="field" style="margin-top:14px">
      <label class="check"><input type="checkbox" id="g-strict" ${rd.strict ? "checked" : ""}><span>${esc(t("rt.strict"))}</span></label>
      <span class="hint">${esc(t("rt.strict_hint"))}</span>
      ${S.sni && S.sni.strict ? `<div class="small warn-text">${esc(t("rt.strict_now"))}</div>` : ""}</div>` : ""}
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
  const draft = routingDraft || structuredClone(routingNow());
  const upd = () => { routingDraft = draft; $("#savebar").hidden = !routingDirty(); };
  // новый список из правила: после сохранения он сразу в этом правиле (правка не теряется)
  rulesEditor($("#g-rules"), draft.rules, upd, { create: (kind, put) => editList(null, kind, (id) => { put(id); routingDraft = draft; render(true); }) });
  upd();
  bindLists();
  if (scrollToLists) { scrollToLists = false; $("#lists-sec").scrollIntoView(); }
  $("#g-default").onchange = (e) => {
    const v = e.target.value;
    draft.balance.on = v === "balance";
    if (v !== "balance") draft.default = v;
    $("#g-bal").hidden = !draft.balance.on;
    $("#g-bal-fb").value = draft.default;
    upd();
  };
  $("#g-bal-fb").onchange = (e) => { draft.default = e.target.value; upd(); };
  if ($("#g-strict")) $("#g-strict").onchange = (e) => { draft.strict = e.target.checked; upd(); };
  $$("[data-bal]").forEach((i) => i.onchange = () => {
    const id = i.dataset.bal;
    draft.balance.skip = draft.balance.skip.filter((x) => x !== id);
    if (!i.checked) draft.balance.skip.push(id);
    upd();
  });
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
        ${l.busy ? `<div class="small muted">${esc(t("ls.busy"))}</div>` : `${l.error ? `<div class="err small">${esc(tm(l.error))}</div>` : ""}${l.updated ? `<div class="small muted">${esc(t("ls.updated", { time: fmtTime(l.updated) }))}</div>` : ""}`}</td>
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
      if (l.busy) toast(t("ls.refresh_busy", { name: listName(l.id) }));
      else l.error ? toast(tm(l.error), true) : toast(t("ls.refreshed", { name: listName(l.id) }));
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
      <p class="small muted" style="margin:0">${esc(t("ls.domains_how"))}</p>
      ${S.sni && S.sni.quic && S.sni.quic !== "on" ? `<p class="small warn-text" style="margin:6px 0 0">${esc(t("ls.quic_off"))}</p>` : ""}`;
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
      if (r && r.busy) toast(t("ls.saved_busy", { name: listName(r.id) }));
      else if (r && r.error) toast(t("ls.saved_failed", { e: tm(r.error) }), true);
      else {
        toast(t("ls.saved", { name: listName(r.id), count: t(kind === "domains" ? "n.domains" : "n.networks", { n: r.count || 0 }) }));
        if (r.skipped_v6) toast(t("ls.skipped_v6", { n: r.skipped_v6 }));
      }
    } catch (err) { toast(err.message, true); e.target.disabled = false; e.target.textContent = label; }
  };
}
