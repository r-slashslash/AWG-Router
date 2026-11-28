// Запуск: тексты страницы и первый запрос состояния. Грузится последним, когда все функции уже есть.
"use strict";

window.addEventListener("beforeunload", (e) => {
  if (routingDirty() || (tab === "server" && srvDirty())) { e.preventDefault(); e.returnValue = ""; }
});
applyStaticTexts();
boot();
