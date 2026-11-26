// «Маршрутизация» → «Правила клиентов» (1.24.0, владелец 2026-11-25): клиенты со своими правилами, их правила и выход
// по умолчанию. Всё сохраняется сразу — тем же PUT /api/clients/<ключ>, что и окно клиента.
"use strict";

/** клиенты со своими правилами — по адресу, как в списке клиентов */
function customClients() {
  return S.clients.filter((c) => c.policy && c.policy.rules_mode === "custom");
}
/** то, что видно в разделе: по нему опрос решает, перерисовать ли его (правила поменяли в другой вкладке) */
function clientRulesSig() {
  return JSON.stringify(customClients().map((c) => [c.public_key, c.name, c.policy]));
}
let clientRulesDrawn = "";

function clientRulesHtml() {
  const list = customClients();
  const cards = list.map((c) => {
    const pk = esc(c.public_key), tr = c.traffic || {};
    const inherit = t("out.inherit_now", { exit: exitName(S.routing.default) });
    return `<div class="panel panel-pad cr-card" data-cr="${pk}">
      <div class="cr-head">
        <div class="cr-who"><b><bdi>${esc(c.name || c.ip)}</bdi></b> <span class="muted small" dir="ltr">${esc(c.ip || "")}</span>
          <div class="small muted"><span>${esc(t("rt.month"))}</span> <span class="nowrap">↓ ${esc(fmtBytes(tr.month_tx))} ↑ ${esc(fmtBytes(tr.month_rx))}</span></div></div>
        <div class="cr-acts"><button class="btn sm" type="button" data-cr-add>${esc(t("rw.add"))}</button><button class="btn sm" type="button" data-cr-reset>${esc(t("cr.reset"))}</button></div>
      </div>
      <div class="cr-rules">${ruleRowsHtml(c.policy.rules || [], "c", c.public_key)}</div>
      <div class="default-row" style="margin-top:8px">
        <div class="rule-n" style="padding:0">∗</div>
        <div><b>${esc(t("cr.else"))}</b><div class="small muted rule-tr" data-rtr-c="_d" data-rtr-pk="${pk}"></div></div>
        <select data-cr-out aria-label="${esc(t("cr.else"))}">${outOptions(c.policy.outbound || "inherit", { inherit })}</select>
        <div></div>
      </div>
    </div>`;
  }).join("");
  return `<section class="section" id="cr-sec">
    <div class="section-head"><div><h2>${esc(t("cr.title"))}</h2><p class="muted small">${esc(t("cr.subtitle"))}</p></div></div>
    <div class="add-row rules-add"><button class="btn primary" type="button" id="cr-add">${esc(t("rw.add"))}</button></div>
    ${list.length ? cards : `<p class="muted small" style="margin:0">${esc(t("cr.none"))}</p>`}
  </section>`;
}

/** своя политика клиента с другими правилами или выходом — сразу на сервер (как «Сохранить» окна клиента) */
async function saveClientRules(c, patch) {
  const p = c.policy;
  const r = await api("PUT", "clients/" + encodeURIComponent(c.public_key), {
    outbound: p.outbound || "inherit", rules_mode: p.rules_mode || "inherit", rules: p.rules || [], note: p.note || "", ...patch });
  toast(t("toast.rules_saved"));
  reconnectToast(r);
  await refresh();
  return true;
}
/** новое правило клиента: окно правила с выбором клиента (pk — уже выбран: кнопка в карточке клиента) */
function openClientRule(pk = null) {
  const choices = S.clients.map((c) => [c.public_key, `${c.name || c.ip} — ${c.ip || ""}`]);
  ruleWindow({ lists: [], outbound: "block", enabled: true, comment: "" }, {
    title: t("cr.new"), okLabel: t("btn.save"), at: 0, pk,
    pick: pk ? null : { choices, hint: (x) => {
      const c = S.clients.find((y) => y.public_key === x);
      return c && !(c.policy && c.policy.rules_mode === "custom") ? t("cr.copy_hint") : "";
    } },
    ok: async (nr, made, picked) => {
      const c = S.clients.find((y) => y.public_key === (pk || picked));
      if (!c) { toast(t("cr.need_client"), true); return false; }
      // у клиента с общими правилами свои начинаются с копии общих, как в окне клиента; новое — последним
      const own = c.policy && c.policy.rules_mode === "custom";
      const base = own ? (c.policy.rules || []) : copyRules(S.routing.rules);
      return saveClientRules(c, { rules_mode: "custom", rules: [...base, nr] });
    },
  });
}
function bindClientRules() {
  const sec = $("#cr-sec");
  if (!sec) return;
  clientRulesDrawn = clientRulesSig();
  fillRuleTraffic(sec);
  $("#cr-add", sec).onclick = () => openClientRule(null);
  $$(".cr-card", sec).forEach((card) => {
    const c = S.clients.find((x) => x.public_key === card.dataset.cr);
    if (!c) return;
    const rules = c.policy.rules || [];
    const box = $(".cr-rules", card);
    $("[data-cr-add]", card).onclick = () => openClientRule(c.public_key);
    $("[data-cr-reset]", card).onclick = async (e) => {
      const btn = e.currentTarget;
      if (!await ask(t("cr.reset_confirm", { name: c.name || c.ip }), { from: btn, danger: true })) return;
      btn.disabled = true;
      try { await saveClientRules(c, { rules_mode: "inherit", rules: [] }); } catch (err) { toast(err.message, true); btn.disabled = false; }
    };
    $("[data-cr-out]", card).onchange = async (e) => {
      try { await saveClientRules(c, { outbound: e.target.value }); } catch (err) { toast(err.message, true); }
    };
    bindRuleRows(box, rules, async (next) => {
      // пока это сохраняется, строки не нажимаются (как общие правила: второе нажатие считалось бы от прежних)
      box.inert = true;
      try { await saveClientRules(c, { rules: next }); } catch (err) { toast(err.message, true); markField(err, box); }
      finally { box.inert = false; }
    }, (i) => ruleWindow(rules[i], {
      title: t("rw.title"), okLabel: t("btn.save"), at: i, pk: c.public_key,
      ok: async (nr) => saveClientRules(c, { rules: withRule(rules, i, nr) }),
      del: { i, fn: () => saveClientRules(c, { rules: rules.filter((_, j) => j !== i) }) },
    }));
  });
}
/** опрос: раздел заново, когда правила клиентов поменялись (не под окном и не во время сохранения) */
function drawClientRules() {
  const sec = $("#cr-sec");
  if (!sec || $$("[inert]", sec).length) return;
  if (clientRulesSig() !== clientRulesDrawn) {
    sec.outerHTML = clientRulesHtml();
    bindClientRules();
  } else fillRuleTraffic(sec);
}
