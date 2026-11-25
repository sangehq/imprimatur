import { tabler, typing } from "./ui.js";

/**
 * Two-key shortcuts ("g p": press g, then p) for every palette entry that
 * names one, and ? for the shortcuts sheet, which lists them. Never while the
 * focus is in a field. @param {ParentNode} root
 */
export function startShortcuts(root) {
  const items = /** @type {HTMLAnchorElement[]} */ (Array.from(root.querySelectorAll("a[data-palette-keys]")));
  const sheet = root.querySelector("[data-shortcuts]");
  const list = root.querySelector("[data-shortcuts-list]");
  if (list) {
    for (const a of items) {
      const dt = document.createElement("dt");
      const kbd = document.createElement("kbd");
      kbd.textContent = a.dataset.paletteKeys ?? "";
      dt.append(kbd);
      const dd = document.createElement("dd");
      dd.textContent = a.querySelector(".palette-label")?.textContent ?? "";
      list.append(dt, dd);
    }
  }
  let first = "";
  let timer = 0;
  document.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey || typing(e.target) || document.querySelector(".modal.show")) {
      return;
    }
    if (e.key === "?" && sheet) {
      e.preventDefault();
      tabler()?.Modal?.getOrCreateInstance(sheet).show();
      return;
    }
    const seq = first ? `${first} ${e.key}` : e.key;
    const hit = items.find((a) => a.dataset.paletteKeys === seq);
    if (hit) {
      e.preventDefault();
      first = "";
      hit.click();
      return;
    }
    first = items.some((a) => (a.dataset.paletteKeys ?? "").startsWith(`${e.key} `)) ? e.key : "";
    window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      first = "";
    }, 1200);
  });
}
