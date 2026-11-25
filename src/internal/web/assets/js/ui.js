// Shared helpers: Tabler's bundled Bootstrap components, which tabler.min.js
// exposes as window.tabler (deferred, so read them when needed).

/** Tabler's component classes, or null before tabler.min.js has run. */
export const tabler = () => /** @type {any} */ (window).tabler ?? /** @type {any} */ (window).bootstrap ?? null;

/** Whether the focus is in a field, where single-key shortcuts must not fire. @param {EventTarget | null} t */
export const typing = (t) => t instanceof HTMLElement && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));

/** The page's CSRF token. */
export const csrf = () => document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") ?? "";
