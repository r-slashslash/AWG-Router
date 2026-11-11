"use strict";
/* Проверки формы выполняют настоящий код панели без браузерных сетевых запросов. */
const { test, mock } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

/** Подмены браузерных границ оставляют выбор типа и сборку запроса настоящими. */
function panel() {
  const elements = new Map();
  const element = (selector) => {
    if (!elements.has(selector)) elements.set(selector, {
      value: "", checked: false, hidden: false, disabled: false,
      addEventListener: mock.fn(), setAttribute: mock.fn(),
      classList: { toggle: mock.fn() },
    });
    return elements.get(selector);
  };
  const buttons = ["awg", "socks5", "ikev2"].map((kind) => ({
    dataset: { v: kind }, setAttribute: mock.fn(), disabled: false,
  }));
  const context = vm.createContext({
    document: {
      querySelector: mock.fn(element),
      querySelectorAll: mock.fn((selector) => selector === "#u-kind button" ? buttons : []),
      addEventListener: mock.fn(),
    },
    location: { hash: "#exits" }, window: { addEventListener: mock.fn() },
    fetch: mock.fn(() => new Promise(() => {})),
    t: (key) => key, LANG: "en", LANGS: { en: { name: "English" } },
    captureModal: mock.fn(), captureApi: mock.fn(async () => ({ id: "u_test" })),
    finish: mock.fn(),
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../app/static/app.js"), "utf8"), context);
  vm.runInContext(`S = {upstreams: [], lists: [], routing: {rules: [], default: "direct"}};
    openModal = captureModal; api = captureApi; closeModal = finish; toast = finish; refresh = finish;`, context);
  return { context, element, buttons };
}

test("IKEv2 сохраняет реквизиты и список корпоративных сайтов", async () => {
  const { context, element, buttons } = panel();
  await vm.runInContext("editUpstream(null)", context);
  const html = context.captureModal.mock.calls[0].arguments[1];
  assert.match(html, /data-v="ikev2"/);
  buttons[2].onclick();
  assert.equal(element("#u-ike").hidden, false);
  assert.equal(element("#u-route").hidden, false);
  element("#u-name").value = "Company";
  element("#u-ih").value = "vpn.example.com";
  element("#u-ir").value = "vpn.example.com";
  element("#u-iu").value = "employee";
  element("#u-iw").value = ' p\\a"ss ';
  element("#u-doms").value = "portal.example.com";
  element("#u-fb").value = "block";
  await element("#u-save").onclick();
  const [method, resource, body] = context.captureApi.mock.calls[0].arguments;
  assert.equal(method, "POST");
  assert.equal(resource, "upstreams");
  const conf = JSON.parse(body.config);
  assert.equal(conf.kind, "ikev2");
  assert.equal(conf.password, ' p\\a"ss ');
  assert.equal(conf.host, "vpn.example.com");
  assert.equal(body.routing.domains, "portal.example.com");
  assert.equal(body.fallback, "block");
  assert.equal(body.make_default, false);
});

test("Редактор доменных правил предлагает IKEv2 и SOCKS5", () => {
  const { context } = panel();
  const options = vm.runInContext(`S.upstreams = [
    {id: "ike", name: "Company", kind: "ikev2"},
    {id: "proxy", name: "Proxy", kind: "socks5"},
    {id: "awg", name: "AWG", kind: "awg"}];
    outOptions("up:ike", {domainOnly: true});`, context);
  assert.match(options, /value="up:ike"/);
  assert.match(options, /value="up:proxy"/);
  assert.doesNotMatch(options, /value="up:awg"/);
  assert.doesNotMatch(options, /value="direct"/);
});
