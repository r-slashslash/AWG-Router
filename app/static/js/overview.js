// Вкладка «Обзор».
"use strict";

/* ================================================================ обзор */
function viewOverview() {
  const counts = {}, assigned = {};
  for (const c of S.clients) {
    const e = isDirect(c.effective) ? "direct" : c.effective;     // «Напрямую» с любого адреса — одна строка
    counts[e] = (counts[e] || 0) + 1;
    assigned[c.default] = (assigned[c.default] || 0) + 1;
  }
  const track = (cls, color, title, meta, side) => `
    <div class="track ${cls}" style="--c:${color}">
      <div class="track-body"><div class="track-title">${title}</div><div class="track-meta">${meta}</div></div>
      <div class="track-side">${side}</div>
    </div>`;
  const countHtml = (k) => {
    const n = counts[k] || 0;
    return `<div class="track-count">${esc(fmtNum(n))}<small>${esc(t("ov.by_default", { n }))}</small></div>`;
  };
  const probeSide = (k) => {
    const p = probes[k];
    const label = !p ? "btn.check" : p === "…" ? null : p.ok ? "btn.refresh" : "btn.again";
    return `<span class="probe-res">${probeHtml(k)}</span>` +
      (label ? ` <button class="btn sm ${p ? "ghost" : ""}" data-probe="${esc(k)}">${esc(t(label))}</button>` : "");
  };

  let lines = "";
  for (const u of S.upstreams) {
    const h = u.health || {};
    const dead = !u.enabled || !h.healthy || quotaSwitched(u);
    const na = assigned["up:" + u.id] || 0;
    const meta = [
      `<span><bdi>${esc(u.endpoint || "")}</bdi></span>`,
      h.healthy ? `<span>${esc(u.kind === "socks5" ? t("ov.socks_ms", { ms: h.latency_ms ?? "?" }) : t("ov.handshake", { ago: fmtAge(h.handshake_age) }))}</span>` : "",
      acctOn() ? `<span>${esc(t("ex.month"))} ${arrows(u.traffic)}</span>`
        : h.rx != null && u.enabled ? `<span>↓ ${esc(fmtBytes(h.rx))} ↑ ${esc(fmtBytes(h.tx))}</span>` : "",
      acctOn() && !dead && (u.rate_down || u.rate_up || Math.max(...(u.speed || [0])) >= 12500) ? `<span>${speedHtml(u)}</span>` : "",
      balOn() && u.balance ? `<span>⚖️ ${esc(t("ex.bal_clients", { n: u.bal_clients }))}</span>` : "",
      dead ? `<span>${esc(na ? t("ov.assigned_now", { n: na }) : t("ov.traffic_goes"))} ${effChip(u.effective)}</span>` : "",
    ].join("");
    lines += track(dead ? "dead" : "", lineVar(u), `<h3><bdi>${esc(u.name)}</bdi></h3>${stateBadge(u)}`, meta,
      countHtml(u.num) + (u.enabled ? probeSide("up:" + u.id) : ""));
  }
  lines += track("direct", "var(--direct)", `<h3>${esc(t("out.direct"))}</h3><span class="muted small">${esc(t("ov.direct_sub"))}</span>`,
    acctOn() ? `<span>${esc(t("ex.month"))} ${arrows(S.direct_traffic)}</span>` : "", countHtml("direct") + probeSide("direct"));
  if (counts.block) lines += track("dead", "var(--block)", `<h3>${esc(t("ov.blocked"))}</h3>`, "", countHtml("block"));

  const evs = [];
  for (const e of S.events) {
    const msg = tm(e.msg);
    const last = evs[evs.length - 1];
    if (last && last.msg === msg) last.n++; else evs.push({ ...e, msg, n: 1 });
  }
  const ev = evs.length
    ? `<ul class="events">${evs.slice(0, 12).map((e) => `<li><time>${esc(fmtTime(e.t))}</time><span class="${e.level}">${esc(e.msg)}${e.n > 1 ? ` <span class="muted">×${esc(fmtNum(e.n))}</span>` : ""}</span></li>`).join("")}</ul>`
    : `<p class="muted small">${esc(t("ov.log_empty"))}</p>`;

  return `
  <div class="ov-grid">
    <div class="section-head ov-head ov-h1"><div><h2>${esc(t("ov.title"))}</h2><p class="muted small">${esc(t("ov.subtitle"))}</p></div>
      <button class="btn" data-goto="exits">${esc(t("ov.add_exit"))}</button></div>
    <div class="section-head ov-head ov-h2"><div><h2>${esc(t("ov.policy"))}</h2><p class="muted small">${esc(t("ov.policy_sub"))}</p></div>
      <button class="btn" data-goto="routing">${esc(t("btn.edit"))}</button></div>
    <div class="map-lines ov-c1">${lines}</div>
    <div class="ov-c2">
      <div class="panel panel-pad">
        ${rulesSummary(S.routing.rules)}
        ${countryButtons()}
        <div style="margin-top:10px">${!balOn() ? th("ov.everything_else", { exit: effChip(S.global_effective, S.routing.default) })
          : balMembers().length ? th("ov.everything_bal", { exits: balMembers().map((id) => outChip("up:" + id)).join(" ") })
          : th("ov.everything_bal_down", { exit: effChip(S.global_effective, S.routing.default) })}</div>
      </div>
      <div class="section-head" style="margin-top:20px"><h2>${esc(t("ov.log"))}</h2></div>
      <div class="panel panel-pad ov-log">${ev}</div>
    </div>
  </div>`;
}
/* Готовые правила стран (решение владельца 2026-11-19): пока общих правил нет совсем — «Применить для …» во всех
   языках, первой страна языка интерфейса. Нажатие: при выданных клиентах и выключенном «DNS на сервере» — сначала
   вопрос; затем список страны, список её доменов и два правила «Напрямую» (POST /api/country-preset), и DNS на
   сервере включается: без него свой DNS страны не работает. */
const COUNTRY_ORDER = { ru: ["ru", "cn", "ir"], zh: ["cn", "ru", "ir"], fa: ["ir", "ru", "cn"] };
function countryButtons() {
  if (S.routing.rules.length || !S.country_presets) return "";
  const order = (COUNTRY_ORDER[LANG] || COUNTRY_ORDER.ru).filter((cc) => S.country_presets[cc]);
  return `<div class="cp-box">
    <div class="cp-btns">${order.map((cc) => `<button class="btn sm" data-cp="${cc}">${esc(t("cp.apply_" + cc))}</button>`).join("")}</div></div>`;
}
async function applyCountry(cc, b) {
  const pseudo = Object.assign([{ dns: S.country_presets[cc].dns }], { _cc: true });
  if (!await panelDnsAsk(pseudo, b)) return;
  $$("[data-cp]").forEach((x) => { x.disabled = true; });
  try {
    await api("POST", "country-preset", { cc, apply: true });
    toast(t("cp.applied", { country: countryName(cc) }));
    await panelDnsOn(pseudo);
    await refresh();
  } catch (e) {
    toast(e.message, true);
    $$("[data-cp]").forEach((x) => { x.disabled = false; });
  }
}

bind.overview = () => {
  $$("[data-goto]").forEach((b) => b.onclick = () => { tab = b.dataset.goto; history.replaceState(null, "", "#" + tab); render(); });
  $$("[data-probe]").forEach((b) => b.onclick = () => runProbe(b.dataset.probe, render));
  $$("[data-cp]").forEach((b) => b.onclick = () => applyCountry(b.dataset.cp, b));
};
