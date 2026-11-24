// Вкладка «Маршрутизация»: общие правила и окно правила (со списками сетей и доменов внутри), балансировка.
"use strict";

/* ================================================================ правила (1.23.0)
   Списки — внутри правил: отдельного раздела «Списки» нет (решение владельца 2026-11-19). Правило правится в своём
   окне (ruleWindow): имя, списки (готовые, страны или новый — прямо в окне), свой DNS у правила по доменам, выход.
   На «Маршрутизации» «Сохранить» в окне, включение, место и удаление правила сохраняются сразу; в окне клиента —
   вместе с окном клиента («Готово»). Список, который после этого не стоит ни в одном правиле, сервер удаляет сам
   (api/routing.drop_unused_lists). */
const LIST_KINDS = ["country", "asn", "url", "manual", "domains"];
function addListTo(r, id) {
  if (!r.lists.includes(id)) r.lists.push(id);
}
const isDomainList = (id) => (listObj(id) || {}).kind === "domains";

/* Трафик по правилам за месяц (1.24.0). Строки правил держат пустые места [data-rtr] (общие правила и «По умолчанию»)
   и [data-rtr-c] (правила одного клиента: окно клиента, раздел «Правила клиентов» — data-rtr-pk), а цифры кладут
   fill*: опрос приносит новые цифры каждые несколько секунд, а строки из-за них не перерисовываются. */
function ruleTrafficHtml(v) {
  if (!S.rule_traffic || S.rule_traffic.state !== "ok") return "";
  const p = v || [0, 0];
  return `<span>${esc(t("rt.month"))}</span> <span class="nowrap">↓ ${esc(fmtBytes(p[1]))} ↑ ${esc(fmtBytes(p[0]))}</span>`;
}
function fillRuleTraffic(root = $("#main")) {
  if (!root) return;
  const g = (S.rule_traffic && S.rule_traffic.rules) || {};
  $$("[data-rtr]", root).forEach((el) => {
    const html = ruleTrafficHtml(g[el.dataset.rtr]);
    if (el.innerHTML !== html) el.innerHTML = html;
  });
  const own = Object.fromEntries(S.clients.map((c) => [c.public_key, c.rule_traffic || {}]));
  $$("[data-rtr-pk]", root).forEach((el) => {
    const html = ruleTrafficHtml((own[el.dataset.rtrPk] || {})[el.dataset.rtrC]);
    if (el.innerHTML !== html) el.innerHTML = html;
  });
}
/** строки правил: номер (выбор места), что ловит правило и выход; нажатие открывает окно правила. tr — места для
    трафика правила: "g" — общие правила, "c" — правила клиента (pk — в разделе «Правила клиентов») */
function ruleRowsHtml(rules, tr = "", pk = "") {
  if (!rules.length) return `<p class="muted small" style="margin:0 0 4px">${esc(t("re.none"))}</p>`;
  const s = esc(sep("list"));
  return `<div class="rules">${rules.map((r, i) => {
    const empty = r.enabled === false ? [] : r.lists.map(listObj).filter((l) => l && !l.busy && !l.count);
    const names = (ls) => ls.map((l) => `<bdi>${esc(listName(l.id))}</bdi>`).join(s);
    const warn = [["rl.lists_failed", empty.filter((l) => l.error)], ["rl.lists_empty", empty.filter((l) => !l.error)]]
      .filter(([, ls]) => ls.length)
      .map(([k, ls]) => `<div class="small warn-text">⚠ ${th(k, { lists: names(ls) })}</div>`).join("")
      // обработчик правил по доменам не запустился — правила по доменам не работают
      + (r.lists.some(isDomainList) && S.sni && S.sni.state === "error" ? `<div class="small warn-text">⚠ ${esc(t("ls.sni_error"))}</div>` : "");
    const what = r.lists.length ? r.lists.map(listLabel).join(s) : `<span class="muted">${esc(t("rw.no_lists"))}</span>`;
    // месячный лимит правила исчерпан (1.24.0): до нового месяца трафик правила идёт по «Когда лимит исчерпан»
    const over = r.quota && r.quota_hit === S.month && r.quota_action && r.quota_action !== "notify"
      ? `<div class="small warn-text">📦 ${th("rq.over", { gb: fmtNum(+(r.quota / 1024 ** 3).toFixed(3)), to: outChip(r.quota_action) })}</div>` : "";
    return `<div class="rule rule-item ${r.enabled === false ? "off" : ""}" data-i="${i}">
      ${rules.length > 1
    // место правила: выбрать номер — правило встаёт туда (на телефоне удобнее, чем жать ↑ ↓ много раз)
    ? `<select class="rule-n rule-pos" data-pos aria-label="${esc(t("re.position"))}" title="${esc(t("re.position"))}">${rules.map((_, j) => `<option value="${j}" ${j === i ? "selected" : ""}>${esc(fmtNum(j + 1))}</option>`).join("")}</select>`
    : `<div class="rule-n">${esc(fmtNum(i + 1))}</div>`}
      <button type="button" class="rule-open" data-open aria-label="${esc(t("rw.edit"))}">
        ${r.comment ? `<span class="rule-title"><bdi>${esc(r.comment)}</bdi></span>` : ""}
        <span class="rule-line"><span class="rule-what">${what}</span> <span aria-hidden="true">—</span> ${ruleOutChip(r)}${r.balance && r.balance.length && tr === "c" ? ` <span class="small muted nowrap" data-rbal-c="${esc(r.id)}"></span>` : ""}</span>
        ${tr === "g" ? `<span class="small muted rule-tr" data-rtr="${esc(r.id)}"></span>` : ""}${tr === "c" ? `<span class="small muted rule-tr" data-rtr-c="${esc(r.id)}"${pk ? ` data-rtr-pk="${esc(pk)}"` : ""}></span>` : ""}
        ${over}${warn}
      </button>
      <div class="rule-ctl">
        <label class="switch" title="${esc(t("re.enabled"))}"><input type="checkbox" data-en ${r.enabled !== false ? "checked" : ""} aria-label="${esc(t("re.enabled"))}"><span></span></label>
        <button class="icon-btn" type="button" data-up ${i === 0 ? "disabled" : ""} aria-label="${esc(t("re.up"))}">↑</button>
        <button class="icon-btn" type="button" data-down ${i === rules.length - 1 ? "disabled" : ""} aria-label="${esc(t("re.down"))}">↓</button>
      </div>
    </div>`;
  }).join("")}</div>`;
}
/** Строки правил с кнопками. change(rules) — порядок или включение поменялись (страница сохраняет сразу, окно
    клиента — в свой черновик); open(i) — открыть окно правила i. */
function bindRuleRows(box, rules, change, open) {
  $$(".rule-item", box).forEach((el) => {
    const i = +el.dataset.i;
    const moved = (to) => { const next = [...rules]; const [r0] = next.splice(i, 1); next.splice(to, 0, r0); change(next); };
    $("[data-open]", el).onclick = () => open(i);
    $("[data-en]", el).onchange = (e) => change(rules.map((r, j) => j === i ? { ...r, enabled: e.target.checked } : r));
    const pos = $("[data-pos]", el);
    if (pos) pos.onchange = () => moved(+pos.value);
    $("[data-up]", el).onclick = () => moved(i - 1);
    $("[data-down]", el).onclick = () => moved(i + 1);
  });
}

/* ------------------------------------------------ окно правила */
/** что о списке видно в окне правила: вид, сколько записей, скачивается, ошибка, когда обновлён */
function listInfoHtml(l) {
  const parts = [esc(t("ls.kind." + l.kind))];
  if (l.busy) parts.push(esc(t("ls.busy")));
  else if (l.count) parts.push(esc(t(l.kind === "domains" ? "n.domains" : "n.networks", { n: l.count })));
  else parts.push(esc(t("ls.not_loaded")));
  if (!l.busy && l.updated && l.kind !== "manual") parts.push(esc(t("ls.updated", { time: fmtTime(l.updated) })));
  const err = !l.busy && l.error ? `<div class="err small">${esc(tm(l.error))}</div>` : "";
  const v6 = l.skipped_v6 ? `<div class="small warn-text">${esc(t("ls.skipped_v6", { n: l.skipped_v6 }))}</div>` : "";
  return `<div class="small muted">${parts.join(" · ")}</div>${err}${v6}`;
}
/** поля нового или существующего списка (в окне правила, без второго окна) */
function listFormHtml(kind, l) {
  const nameField = (ph = "") => `<label class="field"><span>${esc(t("ls.name"))}</span><input type="text" id="l-name" maxlength="40" value="${esc(l ? l.name : "")}" placeholder="${esc(ph)}"></label>`;
  if (kind === "country") {
    const have = new Set(S.lists.map((x) => x.id));
    const opts = S.country_codes.filter((cc) => !have.has(cc)).map((cc) => [cc, countryName(cc)])
      .sort((a, b) => a[1].localeCompare(b[1], LANG));
    return `<label class="field"><span>${esc(t("ls.cc"))}</span><input type="text" id="l-src" dir="ltr" list="cc-list" maxlength="2" placeholder="${esc(t("ls.cc_ph"))}" style="text-transform:lowercase">
      <datalist id="cc-list">${opts.map(([cc, n]) => `<option value="${cc}">${esc(n)}</option>`).join("")}</datalist>
      <span class="hint">${esc(t("ls.cc_hint"))}</span></label>`;
  }
  if (kind === "asn") {
    return nameField(t("ls.asn_name_ph")) + `<label class="field"><span>${esc(t("ls.asn"))}</span><textarea id="l-src" dir="ltr" style="min-height:80px" placeholder="${esc(t("ls.asn_ph"))}">${esc(l ? l.source : "")}</textarea>
      <span class="hint">${esc(t("ls.asn_hint"))}</span></label>`;
  }
  if (kind === "url") {
    return nameField() + `<label class="field"><span>${esc(t("ls.urls"))}</span><textarea id="l-src" dir="ltr" style="min-height:90px" placeholder="https://example.com/list.txt">${esc(l ? l.source : "")}</textarea>
      <span class="hint">${esc(t("ls.urls_hint"))}</span></label>`;
  }
  if (kind === "domains") {
    return nameField(t("ls.domains_name_ph")) + `<label class="field"><span>${esc(t("ls.domains"))}</span><textarea id="l-src" dir="ltr" spellcheck="false" placeholder="${esc(t("ls.domains_ph"))}">${esc(l ? l.source || "" : "")}</textarea>
      <span class="hint">${esc(t("ls.domains_hint"))}</span></label>
      <p class="small muted" style="margin:0 0 10px">${esc(t("ls.domains_how"))}</p>
      ${S.sni && S.sni.quic && S.sni.quic !== "on" ? `<p class="small warn-text" style="margin:0 0 10px">${esc(t("ls.quic_off"))}</p>` : ""}`;
  }
  return nameField(t("ls.manual_ph")) + `<label class="field"><span>${esc(t("ls.cidrs"))}</span><textarea id="l-src" dir="ltr" placeholder="203.0.113.0/24&#10;198.51.100.7">${esc(l ? l.source : "")}</textarea>
    <span class="hint">${esc(t("ls.cidrs_hint"))}</span></label>`;
}
/** списки, созданные в окне правила, чьё правило так и не сохранили, — удалить (сервер не тронет нужный где-то ещё) */
async function dropNewLists(ids) {
  if (!ids.length) return;
  for (const id of ids) {
    try { await api("DELETE", "lists/" + id); } catch { /* уже в правиле или удалён */ }
  }
  refresh();
}
/** Окно правила. ok(правило, новые списки) — сохранить (страница) или положить в черновик (окно клиента); false —
    остаться в окне. del — удалить правило (нет — новое). Готовых правил стран здесь нет (владелец, 2026-11-20): список
    страны — просто список; адреса и домены страны со своим DNS — только кнопки «Применить для …». */
function ruleWindow(rule0, { title, okLabel, ok, del = null, at = 0, pick = null, top = false, pk = null }) {
  const r = structuredClone(rule0);
  // ключ балансировки правила (сколько клиентов на каждом выходе): общее правило — id, своё правило клиента — «клиент|id»
  const balKey = pk ? `${pk}|${r.id}` : r.id;
  const made = [];               // списки, созданные в этом окне: «Отмена» — удалить их
  let form = null;               // открытая форма списка: {kind, id}
  let timer = null;
  // pick — первой строкой выбор клиента («Правила клиентов» → «+ Добавить правило», 1.24.0): {choices: [[ключ, подпись]],
  // hint(ключ) → подсказка под выбором}; выбранный ключ — третьим аргументом ok
  const pickHtml = pick ? `<label class="field"><span>${esc(t("cr.client"))}</span><select id="rw-pk"><option value="">${esc(t("cr.pick"))}</option>${pick.choices.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("")}</select>
    <span class="hint" id="rw-pk-hint"></span></label>` : "";
  const body = `${pickHtml}
    <label class="field"><span>${esc(t("rw.name"))}</span><input type="text" id="rw-name" maxlength="80" value="${esc(r.comment || "")}" placeholder="${esc(t("re.comment_ph"))}"></label>
    <div class="field"><span>${esc(t("rw.lists"))}</span><div id="rw-lists"></div></div>
    <div id="rw-dns"></div>
    <label class="field"><span>${esc(t("rw.exit"))}</span><select id="rw-out"><option value="balance" ${r.balance && r.balance.length ? "selected" : ""}>${esc(t("bal.option"))}</option>${outOptions(r.balance && r.balance.length ? "" : r.outbound)}</select></label>
    <div class="panel panel-pad bal-box rw-bal" id="rw-bal" ${r.balance && r.balance.length ? "" : "hidden"}>
      <p class="small muted" style="margin-top:0">${esc(t("rbal.hint"))}</p>
      <div class="field"><span>${esc(t("bal.exits"))}</span>${S.upstreams.length ? `<div class="check-cols">${S.upstreams.map((u) => {
    // как у балансировки «По умолчанию»: сколько клиентов правила на выходе или почему он сейчас не в работе
    const on = (r.balance || []).includes(u.id), n = (S.rule_balance && S.rule_balance[balKey] || {})[u.id];
    const live = u.enabled !== false && !quotaSwitched(u) && (u.health || {}).healthy;
    const why = !on ? "" : n ? t("ex.bal_clients", { n }) : !u.enabled ? t("bal.off") : quotaSwitched(u) ? t("bal.quota") : live ? "" : t("bal.down");
    return `<label class="check"><input type="checkbox" data-rbal="${esc(u.id)}" ${on ? "checked" : ""}><span><bdi>${esc(u.name)}</bdi>${why ? ` <span class="muted small">— ${esc(why)}</span>` : ""}</span></label>`;
  }).join("")}</div>` : `<p class="small muted" style="margin:0">${esc(t("bal.no_exits"))}</p>`}</div>
      <label class="field" style="margin-bottom:0"><span>${esc(t("bal.fallback"))}</span>
        <select id="rw-bal-fb">${outOptions(r.balance_fb || "block")}</select><span class="hint">${esc(t("rbal.fb_hint"))}</span></label>
    </div>
    ${S.rule_traffic && S.rule_traffic.state === "ok" || r.quota ? `<div class="row2">
      <label class="field"><span>${esc(t("rq.quota"))}</span>
        <input type="number" id="rw-quota" data-field="rule_quota_${at}" min="0" step="any" inputmode="decimal" placeholder="${esc(t("cl.no_limit"))}" value="${r.quota ? +(r.quota / 1024 ** 3).toFixed(3) : ""}"></label>
      <label class="field"><span>${esc(t("ex.quota_action"))}</span>
        <select id="rw-qa" data-field="rule_quota_action_${at}">${quotaOptions({ id: null, quota_action: r.quota_action || "notify" })}</select></label>
    </div>
    <p class="small muted" style="margin:-6px 0 14px">${esc(t("rq.hint", { time: monthResetLocal() }))}</p>` : ""}
    <label class="check"><input type="checkbox" id="rw-en" ${r.enabled !== false ? "checked" : ""}><span>${esc(t("re.enabled"))}</span></label>
    ${top && r.id && S.rule_traffic && S.rule_traffic.state === "ok" ? `<div class="field by-exit rw-top" id="rw-top" hidden><span>${esc(t("rw.top"))}</span><div class="rw-top-list"></div></div>` : ""}`;
  const foot = `${del ? `<button class="btn danger left" id="rw-del">${esc(t("re.delete"))}</button>` : ""}
    <button class="btn" data-close>${esc(t("btn.cancel"))}</button><button class="btn primary" id="rw-ok">${esc(okLabel)}</button>`;
  openModal2(title, body, foot);
  const m = $("#modal2");
  if (pick) $("#rw-pk", m).onchange = (e) => { $("#rw-pk-hint", m).textContent = e.target.value ? pick.hint(e.target.value) : ""; };
  // кто больше всех потратил по правилу за месяц (общие правила, 1.24.0) — отдельным запросом, в опросе этого нет
  if ($("#rw-top", m)) {
    api("GET", "rule-top/" + encodeURIComponent(r.id)).then((res) => {
      const box = $("#rw-top", m);
      if (!box || !res.top || !res.top.length) return;
      $(".rw-top-list", box).outerHTML = res.top.map((x) => `<div><span><bdi>${esc(x.name)}</bdi></span><b><span class="nowrap">↓ ${esc(fmtBytes(x.tx))} ↑ ${esc(fmtBytes(x.rx))}</span></b></div>`).join("");
      box.hidden = false;
    }).catch(() => {});
  }
  m.addEventListener("close", () => { clearTimeout(timer); dropNewLists(made.splice(0)); }, { once: true });
  const keep = () => {
    r.comment = $("#rw-name").value.trim(); r.enabled = $("#rw-en").checked;
    // месячный лимит правила (1.24.0): ГБ из поля — сервер переводит в байты; пусто — без лимита
    if ($("#rw-quota", m)) {
      const q = $("#rw-quota", m).value.trim();
      delete r.quota;
      r.quota_gb = q === "" ? null : q;
      r.quota_action = $("#rw-qa", m).value;
    }
    if ($("#rw-out").value === "balance") {
      // балансировка в правиле (1.24.0): выходы — в порядке вкладки «Выходы»; outbound — первый (для панели до 1.24.0)
      r.balance = $$("[data-rbal]", m).filter((x) => x.checked).map((x) => x.dataset.rbal);
      r.balance_fb = $("#rw-bal-fb", m).value;
      if (r.balance.length) r.outbound = "up:" + r.balance[0];
    } else {
      r.outbound = $("#rw-out").value;
      delete r.balance; delete r.balance_fb;
    }
  };
  $("#rw-out", m).onchange = (e) => { $("#rw-bal", m).hidden = e.target.value !== "balance"; };

  const drawDns = (dom) => {
    const box = $("#rw-dns", m);
    if (!dom) { delete r.dns; box.innerHTML = ""; return; }
    if (box.firstElementChild) return;               // уже есть — не стирать ввод
    box.innerHTML = `<label class="field"><span>${esc(t("re.dns"))}</span><input type="text" id="rw-dns-in" data-field="rule_dns_${at}" dir="ltr" value="${esc((r.dns || []).join(", "))}" placeholder="${esc(t("re.dns_ph"))}" inputmode="decimal" autocomplete="off" spellcheck="false">
      <span class="hint">${esc(t(S.settings.panel_dns ? "re.dns_hint" : "re.dns_off"))}</span></label>`;
    // свой DNS — списком, как его вернёт сервер
    $("#rw-dns-in", m).oninput = (e) => {
      const v = e.target.value.split(/[,\s]+/).filter(Boolean);
      if (v.length) r.dns = v; else delete r.dns;
    };
  };
  /* Списки правила, выбор «+ Добавить список» и форма списка — три части #rw-lists. Строки и выбор рисуются заново
     (скачался список, добавили, убрали), а форма — только когда открыли другую: иначе перерисовка, пока список в правиле
     скачивается (раз в 2,5 с), стирала набранное в форме (проверка 1.23.0). */
  const drawLists = (quiet = false) => {
    const box = $("#rw-lists", m);
    if (!box) return;
    if (!$("#rw-rows", box)) box.innerHTML = `<div id="rw-rows"></div><div id="rw-pick"></div><div id="rw-form" class="rw-form" hidden></div>`;
    const dom = r.lists.some(isDomainList);
    // списки доменов — отдельные правила (по имени сайта, раньше правил по адресам): с сетями не смешиваются
    const addable = S.lists.filter((l) => !r.lists.includes(l.id) && (!r.lists.length || (l.kind === "domains") === dom));
    const kinds = LIST_KINDS.filter((k) => !r.lists.length || (k === "domains") === dom);
    const rows = r.lists.map((id) => {
      const l = listObj(id);
      if (!l) return "";
      return `<div class="rw-list">
        <div class="rw-list-main"><b><bdi>${esc(listName(id))}</bdi></b>${listInfoHtml(l)}</div>
        <div class="rw-list-acts">
          ${l.kind !== "manual" ? `<button type="button" class="icon-btn" data-refresh="${esc(id)}" title="${esc(t("ls.refresh"))}" aria-label="${esc(t("ls.refresh"))}">⟳</button>` : ""}
          ${l.kind !== "country" ? `<button type="button" class="icon-btn" data-edit="${esc(id)}" title="${esc(t("btn.edit"))}" aria-label="${esc(t("btn.edit"))}">✎</button>` : ""}
          <button type="button" class="icon-btn" data-rm="${esc(id)}" title="${esc(t("re.remove_list"))}" aria-label="${esc(t("re.remove_list"))}">✕</button>
        </div></div>`;
    }).join("");
    $("#rw-rows", box).innerHTML = rows;
    // перерисовка по таймеру (quiet), а человек сейчас в выборе списка — не пересоздаём его под рукой
    const pick = $("#rw-pick", box);
    if (!(quiet && pick.contains(document.activeElement))) {
      pick.innerHTML = `<select class="add-list" id="rw-add" aria-label="${esc(t("re.add_list"))}"><option value="">${esc(t("re.add_list"))}</option>${addable.length ? `<optgroup label="${esc(t("rw.ready"))}">${addable.map((l) => `<option value="${esc(l.id)}">${esc(listName(l.id))} · ${esc(t("ls.kind." + l.kind))}</option>`).join("")}</optgroup>` : ""}<optgroup label="${esc(t("re.new_list"))}">${kinds.map((k) => `<option value="new:${k}">＋ ${esc(t("ls.new." + k))}</option>`).join("")}</optgroup></select>`;
    }
    drawDns(dom);
    $$("[data-rm]", box).forEach((b) => b.onclick = () => { r.lists = r.lists.filter((x) => x !== b.dataset.rm); drawLists(); });
    $$("[data-edit]", box).forEach((b) => b.onclick = () => { form = { kind: listObj(b.dataset.edit).kind, id: b.dataset.edit }; drawLists(); });
    $$("[data-refresh]", box).forEach((b) => b.onclick = async () => {
      b.disabled = true;
      try {
        const l = await api("POST", `lists/${b.dataset.refresh}/refresh`);
        if (l.busy) toast(t("ls.refresh_busy", { name: listName(l.id) }));
        else l.error ? toast(tm(l.error), true) : toast(t("ls.refreshed", { name: listName(l.id) }));
      } catch (e) { toast(e.message, true); }
      await refresh(); drawLists();
    });
    $("#rw-add", box).onchange = (e) => {
      const v = e.target.value;
      if (!v) return;
      if (v.startsWith("new:")) { form = { kind: v.slice(4), id: null }; drawLists(); return; }
      addListTo(r, v);
      drawLists();
    };
    // форма — заново только другая (или закрыта): открытая той же — с тем, что в ней уже набрано
    const fb = $("#rw-form", box);
    if (!form) { fb.hidden = true; fb.innerHTML = ""; delete fb.dataset.key; }
    else if (fb.dataset.key !== `${form.kind}:${form.id || ""}`) drawForm();
    // список скачивается — посмотреть ещё раз через пару секунд, пока окно открыто
    clearTimeout(timer);
    if (r.lists.some((id) => (listObj(id) || {}).busy)) {
      timer = setTimeout(async () => { if (m.open) { await refresh(); drawLists(true); } }, 2500);
    }
  };
  const drawForm = () => {
    const box = $("#rw-form", m), l = form.id ? listObj(form.id) : null;
    box.hidden = false;
    box.dataset.key = `${form.kind}:${form.id || ""}`;
    box.innerHTML = `<div class="rw-form-title">${esc(l ? t("ls.edit", { name: listName(l.id) }) : t("ls.new." + form.kind))}</div>
      ${listFormHtml(form.kind, l)}
      <div class="actions"><button type="button" class="btn sm primary" id="lf-save">${esc(t(l ? "btn.save" : "rw.add_list_btn"))}</button><button type="button" class="btn sm" id="lf-cancel">${esc(t("btn.cancel"))}</button></div>`;
    const ta = $("#l-src", box), save = $("#lf-save", box);
    if (l && (form.kind === "manual" || form.kind === "domains")) {
      // текст ручного списка не приходит в /api/state (он бывает в мегабайты) — берём отдельно
      ta.disabled = save.disabled = true;
      ta.placeholder = t("ls.loading");
      api("GET", "lists/" + l.id).then((x) => { ta.value = x.source || ""; ta.disabled = save.disabled = false; })
        .catch((err) => toast(err.message, true));
    }
    (ta || box).focus();
    $("#lf-cancel", box).onclick = () => { form = null; drawLists(); };
    save.onclick = async () => {
      const b = { kind: form.kind, source: ta.value.trim() };
      if ($("#l-name", box)) b.name = $("#l-name", box).value.trim();
      const label = save.textContent;
      save.disabled = true; save.textContent = t("ls.loading");
      try {
        const res = l ? await api("PUT", "lists/" + l.id, b) : await api("POST", "lists", b);
        if (!l && res && res.id) { addListTo(r, res.id); made.push(res.id); }
        form = null;
        await refresh();
        drawLists();
        if (res && res.busy) toast(t("ls.saved_busy", { name: listName(res.id) }));
        else if (res && res.error) toast(t("ls.saved_failed", { e: tm(res.error) }), true);
        else if (res) {
          toast(t("ls.saved", { name: listName(res.id), count: t(b.kind === "domains" ? "n.domains" : "n.networks", { n: res.count || 0 }) }));
          if (res.skipped_v6) toast(t("ls.skipped_v6", { n: res.skipped_v6 }));
        }
      } catch (err) { toast(err.message, true); save.disabled = false; save.textContent = label; }
    };
  };
  drawLists();
  $("#rw-ok", m).onclick = async (e) => {
    keep();
    if (pick && !$("#rw-pk", m).value) { toast(t("cr.need_client"), true); $("#rw-pk", m).focus(); return; }
    if (!r.lists.length) { toast(t("rw.need_list"), true); $("#rw-add", m).focus(); return; }
    if (r.balance && !r.balance.length) { toast(t("rbal.need"), true); return; }
    e.target.disabled = true;
    // созданные здесь списки, которые в правило так и не попали (убрали крестиком), удаляются при закрытии окна, как
    // при «Отмене»; остальные уходят вместе с правилом
    const keepIds = new Set(r.lists);
    try {
      if (await ok(r, made.filter((id) => keepIds.has(id)), pick ? $("#rw-pk", m).value : null) !== false) {
        made.splice(0, made.length, ...made.filter((id) => !keepIds.has(id)));
        closeModal2();
        return;
      }
    } catch (err) { toast(err.message, true); markField(err, m); }
    e.target.disabled = false;
  };
  if (del) {
    $("#rw-del", m).onclick = async () => {
      if (!confirm(t("rw.delete_confirm"))) return;
      try { await del.fn(); closeModal2(); } catch (err) { toast(err.message, true); }
    };
  }
}
/** правила с правилом из окна: на месте i (null — в конец) */
function withRule(rules, i, r) {
  const out = [...rules];
  if (i === null) out.push(r); else out[i] = r;
  return out;
}
/** «DNS на сервере» для своего DNS страны. Выключен, а клиенты уже есть — спросить: в выданных конфигах прежний
    DNS, им нужно заново отсканировать QR. false — человек отказался (ничего не применяем). */
function panelDnsAsk(rules) {
  if (S.settings.panel_dns || (rules && !(rules._cc && rules.some((x) => x.dns && x.dns.length)))) return true;
  return !S.clients.length || confirm(t("cp.dns_confirm"));
}
async function panelDnsOn(rules) {
  if (S.settings.panel_dns || (rules && !(rules._cc && rules.some((x) => x.dns && x.dns.length)))) return;
  try {
    await api("PUT", "server", { panel_dns: true });
    toast(t("cp.dns_on"));
  } catch (e) { toast(t("cp.dns_failed", { e: e.message }), true); }
}

/* ================================================================ вкладка «Маршрутизация» */
/** то, что на вкладке сохраняется строкой «несохранённые изменения»: «Остальной трафик», балансировка, «блокировать»
    (правила сохраняются сразу) */
function routingNow() {
  return { default: S.routing.default,
    balance: { on: balOn(), skip: (S.routing.balance && S.routing.balance.skip) || [] }, strict: !!S.routing.strict };
}
function routingDirty() {
  if (!routingDraft) return false;
  return JSON.stringify(routingDraft) !== JSON.stringify(routingNow());
}
/** правила сохранить сейчас: всё остальное — как сохранено (черновик строки сохранения не трогаем) */
async function saveRules(rules) {
  await api("PUT", "routing", { ...routingNow(), rules });
  toast(t("toast.rules_saved"));
  await refresh();
  return true;
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
/** «Применить для России / Китая / Ирана» рядом с «Добавить правило» — всегда (в «Обзоре» — пока правил нет) */
function routingCountryButtons() {
  if (!S.country_presets) return "";
  return (COUNTRY_ORDER[LANG] || COUNTRY_ORDER.ru).filter((cc) => S.country_presets[cc])
    .map((cc) => `<button class="btn" data-cp="${cc}">${esc(t("cp.apply_" + cc))}</button>`).join("");
}
function viewRouting() {
  const rd = routingDraft || routingNow();
  // «+ Добавить правило» и «Применить для …» — своей строкой под заголовком: в шапке рядом с коротким подзаголовком
  // (en, zh) они уезжали вправо (владелец, 2026-11-20)
  return `
  <div class="savebar" id="savebar" hidden><span>${esc(t("rt.unsaved"))}</span>
    <span class="actions"><button class="btn sm" id="g-reset">${esc(t("btn.discard"))}</button><button class="btn sm primary" id="g-save">${esc(t("rt.save"))}</button></span></div>
  <section class="section">
    <div class="section-head"><div><h2>${esc(t("rt.title"))}</h2><p class="muted small">${esc(t("rt.subtitle"))}</p></div></div>
    <div class="add-row rules-add"><button class="btn primary" id="g-add">${esc(t("rw.add"))}</button>${routingCountryButtons()}</div>
    ${S.rule_traffic && S.rule_traffic.state === "off" ? `<p class="small muted" style="margin:0 0 8px">${esc(t("rt.off"))}</p>` : ""}
    <div id="g-rules">${ruleRowsHtml(S.routing.rules, "g")}</div>
    <div class="default-row" style="margin-top:8px">
      <div class="rule-n" style="padding:0">∗</div>
      <div><b>${esc(t("rt.else"))}</b><div class="small muted">${esc(t("rt.else_sub"))}</div><div class="small muted rule-tr" data-rtr="_default"></div></div>
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
      ${S.sni && S.sni.strict ? `<div class="small warn-text">${esc(t("rt.strict_now"))}</div>` : ""}</div>` : ""}
    <div class="ls-hours" style="margin-top:14px"><label for="ls-hours">${esc(t("sy.hours"))}</label>
      <input type="number" id="ls-hours" min="1" max="720" step="1" data-field="list_update_hours" value="${S.settings.list_update_hours}">
      <button type="button" class="btn sm primary" id="ls-hours-save" hidden>${esc(t("btn.save"))}</button></div>
  </section>
  ${clientRulesHtml()}
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
/** окно правила i вкладки (null — новое): «Сохранить» и «Удалить правило» сохраняются сразу */
function openRoutingRule(i) {
  const rules = S.routing.rules;
  const r = i === null ? { lists: [], outbound: "block", enabled: true, comment: "" } : rules[i];
  ruleWindow(r, {
    title: i === null ? t("rw.new") : t("rw.title"), okLabel: t("btn.save"),
    at: i === null ? rules.length : i, top: i !== null,
    ok: async (nr) => saveRules(withRule(S.routing.rules, i, nr)),
    del: i === null ? null : { i, fn: () => saveRules(S.routing.rules.filter((_, j) => j !== i)) },
  });
}
/** строки правил вкладки заново (списки скачались, правило сохранено, правила поменяли в другой вкладке) — без
    перерисовки черновика. rulesDrawn — какие правила сейчас на экране (refresh сравнивает с пришедшими). */
let rulesDrawn = "";
function drawRoutingRules() {
  const box = $("#g-rules");
  if (!box) return;
  box.innerHTML = ruleRowsHtml(S.routing.rules, "g");
  fillRuleTraffic(box);
  rulesDrawn = JSON.stringify(S.routing.rules);
  bindRuleRows(box, S.routing.rules, async (next) => {
    // пока это сохраняется, строки не нажимаются: следующее нажатие считалось бы от прежних правил и отменяло это
    // (два переключателя подряд при медленной связи, проверка 1.23.0)
    box.inert = true;
    try { await saveRules(next); } catch (e) { toast(e.message, true); markField(e, $("#g-rules")); drawRoutingRules(); }
    finally { box.inert = false; }
  }, openRoutingRule);
}
bind.routing = () => {
  const draft = routingDraft || structuredClone(routingNow());
  const upd = () => { routingDraft = draft; $("#savebar").hidden = !routingDirty(); };
  drawRoutingRules();
  fillRuleTraffic();
  bindClientRules();
  upd();
  bindListHours();
  if (scrollToLists) { scrollToLists = false; $("#g-rules").scrollIntoView(); }
  $("#g-add").onclick = () => openRoutingRule(null);
  $$("[data-cp]").forEach((b) => b.onclick = () => applyCountry(b.dataset.cp, b));
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
      await api("PUT", "routing", { ...draft, rules: S.routing.rules });
      routingDraft = null; toast(t("toast.rules_saved")); await refresh();
    } catch (e) { toast(e.message, true); markField(e, $("#main")); }
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
/* как часто обновлять списки: «Сохранить» появляется, когда число изменили; Enter — тоже сохранить */
function bindListHours() {
  const hrs = $("#ls-hours"), hrsSave = $("#ls-hours-save");
  if (!hrs) return;
  hrs.oninput = () => { hrsSave.hidden = String(hrs.value) === String(S.settings.list_update_hours); };
  hrs.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); hrsSave.click(); } };
  hrsSave.onclick = async () => {
    // пусто, 0, дробь или больше 720 сервер молча превратил бы в 1 или 720 — лучше сказать сразу
    const v = hrs.value.trim();
    if (!/^\d+$/.test(v) || +v < 1 || +v > 720) { toast(t("err.hours"), true); markField({ field: "list_update_hours" }, $("#main")); return; }
    hrsSave.disabled = true;
    try { await api("PUT", "settings", { list_update_hours: +hrs.value }); toast(t("toast.settings_saved")); refresh(); }
    catch (e) { toast(e.message, true); hrsSave.disabled = false; }
  };
}
