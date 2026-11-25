// imprimatur web UI: the entry module. Every page works without it; these
// modules only add conveniences, and never build HTML from strings.
import { startPalette } from "./js/palette.js";
import { startShortcuts } from "./js/shortcuts.js";
import { startSidePanel } from "./js/side-panel.js";
import { startConfirm } from "./js/confirm.js";
import { startToasts } from "./js/toasts.js";
import { startCopy } from "./js/copy.js";
import { startEvents } from "./js/events.js";

const start = () => {
  startSidePanel(document);
  startConfirm(document);
  startToasts(document);
  startCopy(document);
  startPalette(document);
  startShortcuts(document);
  startEvents(document);
};

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
