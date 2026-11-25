import { tabler } from "./ui.js";

/**
 * The Ctrl+K (⌘K) palette: the modal's input filters its links as you type,
 * arrow keys move, Enter follows. The links are the server's, so the palette
 * offers nothing the menu does not. @param {ParentNode} root
 */
export function startPalette(root) {
  const el = root.querySelector("[data-command-palette]");
  if (!(el instanceof HTMLElement)) {
    return;
  }
  const input = /** @type {HTMLInputElement | null} */ (el.querySelector("[data-palette-input]"));
  const items = /** @type {HTMLAnchorElement[]} */ (Array.from(el.querySelectorAll("a[data-palette-item]")));
  const empty = /** @type {HTMLElement | null} */ (el.querySelector("[data-palette-empty]"));
  let active = -1;
  const visible = () => items.filter((a) => !a.hidden);
  const select = (i) => {
    const v = visible();
    items.forEach((a) => {
      a.classList.remove("active");
      a.setAttribute("aria-selected", "false");
    });
    active = v.length ? (i + v.length) % v.length : -1;
    if (active >= 0) {
      v[active].classList.add("active");
      v[active].setAttribute("aria-selected", "true");
      v[active].scrollIntoView({ block: "nearest" });
      input?.setAttribute("aria-activedescendant", v[active].id || "");
    }
  };
  const filter = (q) => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    for (const a of items) {
      const hay = `${a.textContent ?? ""} ${a.dataset.paletteKeywords ?? ""}`.toLowerCase();
      a.hidden = !words.every((w) => hay.includes(w));
    }
    for (const sec of el.querySelectorAll("[data-palette-section]")) {
      if (sec instanceof HTMLElement) {
        sec.hidden = !sec.querySelector("a[data-palette-item]:not([hidden])");
      }
    }
    if (empty) {
      empty.hidden = visible().length > 0;
    }
    select(0);
  };
  items.forEach((a, i) => {
    a.id = a.id || `palette-${i}`;
  });
  if (/Mac|iPhone|iPad/.test(navigator.platform)) {
    for (const hint of document.querySelectorAll("[data-palette-hint]")) {
      hint.textContent = "⌘K";
    }
  }
  const modal = () => tabler()?.Modal?.getOrCreateInstance(el);
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "k") {
      e.preventDefault();
      modal()?.toggle();
    }
  });
  el.addEventListener("show.bs.modal", () => {
    if (input) {
      input.value = "";
    }
    filter("");
  });
  el.addEventListener("shown.bs.modal", () => input?.focus());
  input?.addEventListener("input", () => filter(input.value));
  input?.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      select(active + (e.key === "ArrowDown" ? 1 : -1));
    } else if (e.key === "Enter" && active >= 0) {
      e.preventDefault();
      modal()?.hide();
      visible()[active].click();
    }
  });
  // A palette entry for a form opens in the side panel; closing the palette
  // first leaves the panel in front.
  for (const a of items) {
    a.addEventListener("click", () => modal()?.hide());
  }
  filter("");
}
