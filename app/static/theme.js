"use strict";
/* Тема панели и личной страницы клиента: светлая или тёмная. Грузится в <head> до первой отрисовки, чтобы
   страница не мигала. Выбор кнопкой «день/ночь» в шапке хранится в браузере (localStorage, только у этого
   человека); без выбора — как в системе, и следует за ней, если та сменится. Тему читают стили
   (:root[data-theme="dark"]) и QR-коды (themeDark(), событие awgr-theme). */
const THEME_KEY = "awgr-theme";
const themeSystem = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
function themeSaved() {
  try { const v = localStorage.getItem(THEME_KEY); return v === "dark" || v === "light" ? v : null; }
  catch { return null; }
}
function themeDark() { return document.documentElement.dataset.theme === "dark"; }
function applyTheme() {
  const v = themeSaved() || (themeSystem && themeSystem.matches ? "dark" : "light");
  if (document.documentElement.dataset.theme === v) return;
  document.documentElement.dataset.theme = v;
  // цвет строки браузера на телефоне — по выбранной теме, а не по системной
  for (const m of document.querySelectorAll('meta[name="theme-color"]')) m.content = v === "dark" ? "#12171d" : "#eef1f4";
  window.dispatchEvent(new Event("awgr-theme"));
}
function toggleTheme() {
  try { localStorage.setItem(THEME_KEY, themeDark() ? "light" : "dark"); }
  catch { document.documentElement.dataset.theme = themeDark() ? "light" : "dark"; window.dispatchEvent(new Event("awgr-theme")); return; }
  applyTheme();
}
applyTheme();
if (themeSystem && themeSystem.addEventListener) themeSystem.addEventListener("change", applyTheme);
