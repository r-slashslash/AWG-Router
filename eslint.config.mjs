// Проверка скриптов интерфейса на GitHub (net-tests.yml, задание lint); на сервер eslint не ставится.
// Скрипты — обычные, не модули, и видят верхний уровень друг друга: имена i18n.js и qrcode.js берутся из
// самих файлов, браузерные — из списка ниже. Главное правило — no-undef: опечатка в имени функции иначе
// всплыла бы только у пользователя, на той вкладке, где она вызывается.
import { readFileSync } from "node:fs";

const top = (file) => Object.fromEntries(
  [...readFileSync(new URL(file, import.meta.url), "utf8")
    .matchAll(/^(?:async\s+)?(?:function\*?|const|let|var|class)\s+([A-Za-z_$][\w$]*)/gm)]
    .map((m) => [m[1], "readonly"]));

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

export default [
  { ignores: ["app/static/qrcode.js"] },     // чужая библиотека (MIT, Kazuhiko Arase) как есть
  {
    files: ["app/static/i18n.js"],
    // esc() задают страницы: app.js и share.js (обе грузят i18n.js первым и вызывают t() уже после себя)
    languageOptions: { globals: { esc: "readonly" } },
  },
  {
    files: ["app/static/**/*.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "script",
      globals: { ...browser, ...top("app/static/i18n.js"), ...top("app/static/qrcode.js") },
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
