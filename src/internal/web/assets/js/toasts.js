import { tabler } from "./ui.js";

/** Hides a flash toast after a while; its close button works at once. @param {ParentNode} root */
export function startToasts(root) {
  for (const el of root.querySelectorAll("[data-toast]")) {
    const T = tabler()?.Toast;
    if (T) {
      T.getOrCreateInstance(el, { delay: 8000 }).show();
    }
  }
}
