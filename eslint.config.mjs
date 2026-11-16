// Проверка скриптов интерфейса на GitHub (net-tests.yml, задание lint); на сервер eslint не ставится.
// Скрипты — обычные, не модули, и видят верхний уровень друг друга: имена i18n.js, qrcode.js и частей панели
// (app/static/js, порядок — в index.html) берутся из самих файлов, браузерные — из списка ниже. Главное правило — no-undef: опечатка в имени функции иначе
// всплыла бы только у пользователя, на той вкладке, где она вызывается.
import { readdirSync, readFileSync } from "node:fs";

// Имена верхнего уровня файла: function, class и все имена объявления const/let/var — и после запятой
// («let a = 1, b = 2;»: части панели видят b друг у друга). Объявление читается до «;» вне скобок и строк.
const declared = (src, at) => {
  const names = [];
  let depth = 0, part = "", quote = null;
  for (let i = at; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === "/" && src[i + 1] === "/") { i = src.indexOf("\n", i); if (i < 0) break; continue; }
    if (c === "/" && src[i + 1] === "*") { i = src.indexOf("*/", i) + 1; continue; }
    if (c === '"' || c === "'" || c === "`") { quote = c; continue; }
    if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    else if (depth === 0 && (c === "," || c === ";")) {
      const m = part.match(/^\s*([A-Za-z_$][\w$]*)\s*=/);
      if (m) names.push(m[1]);
      part = "";
      if (c === ";") break;
      continue;
    }
    if (depth === 0) part += c;
  }
  return names;
};
const top = (file) => {
  const src = readFileSync(new URL(file, import.meta.url), "utf8");
  const names = [...src.matchAll(/^(?:async\s+)?(?:function\*?|class)\s+([A-Za-z_$][\w$]*)/gm)].map((m) => m[1]);
  for (const m of src.matchAll(/^(?:const|let|var)\s+/gm)) names.push(...declared(src, m.index + m[0].length));
  return Object.fromEntries(names.map((n) => [n, "readonly"]));
};

const BROWSER = [
  "window", "document", "location", "history", "navigator", "screen", "localStorage", "sessionStorage",
  "console", "fetch", "setTimeout", "clearTimeout", "setInterval", "clearInterval", "requestAnimationFrame",
  "performance", "confirm", "alert", "prompt", "getComputedStyle", "matchMedia", "devicePixelRatio",
  "URL", "URLSearchParams", "Blob", "File", "FileReader", "FormData", "AbortSignal", "AbortController",
  "TextEncoder", "TextDecoder", "crypto", "Intl", "Event", "CustomEvent", "KeyboardEvent", "Image",
  "HTMLElement", "Element", "Node", "DOMParser", "atob", "btoa", "structuredClone", "queueMicrotask",
  "CSS", "ClipboardItem", "ResizeObserver", "MutationObserver", "IntersectionObserver", "WebSocket",
];
const browser = Object.fromEntries(BROWSER.map((n) => [n, "readonly"]));
const panel = Object.assign({}, ...readdirSync(new URL("app/static/js/", import.meta.url))
  .filter((f) => f.endsWith(".js")).map((f) => top(`app/static/js/${f}`)));

export default [
  { ignores: ["app/static/qrcode.js"] },     // чужая библиотека (MIT, Kazuhiko Arase) как есть
  {
    files: ["app/static/i18n.js"],
    // esc() задают страницы: js/core.js и share.js (обе грузят i18n.js первым и вызывают t() уже после себя)
    languageOptions: { globals: { esc: "readonly" } },
  },
  {
    files: ["app/static/**/*.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "script",
      globals: { ...browser, ...top("app/static/i18n.js"), ...top("app/static/qrcode.js"), ...panel },
    },
    linterOptions: { reportUnusedDisableDirectives: "off" },
    rules: {
      "no-undef": "error",
      "no-dupe-keys": "error",
      "no-dupe-args": "error",
      "no-duplicate-case": "error",
      "no-unreachable": "error",
      "no-const-assign": "error",
      "no-func-assign": "error",
      "no-self-assign": "error",
      "no-unsafe-negation": "error",
      "use-isnan": "error",
      "valid-typeof": "error",
    },
  },
];
