import { tabler } from "./ui.js";

/**
 * A submit button marked data-confirm="<modal id>" opens that Tabler danger
 * modal instead of submitting; the modal's button submits the form with
 * confirm=yes. Without this script the server asks on a page of its own.
 * @param {ParentNode} root
 */
export function startConfirm(root) {
  for (const btn of root.querySelectorAll("[data-confirm]")) {
    if (!(btn instanceof HTMLElement) || btn.dataset.confirmReady) {
      continue;
    }
    btn.dataset.confirmReady = "1";
    btn.addEventListener("click", (e) => {
      const modal = document.getElementById(btn.dataset.confirm ?? "");
      const M = tabler()?.Modal;
      if (!modal || !M) {
        return; // the server's own confirmation page asks instead
      }
      e.preventDefault();
      M.getOrCreateInstance(modal).show();
    });
  }
}
