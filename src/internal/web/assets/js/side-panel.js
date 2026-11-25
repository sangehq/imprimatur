import { tabler } from "./ui.js";

/** The request header that asks the server for a page's content alone. */
const PANEL_HEADER = "X-Impr-Panel";

/** The answer header that sends the whole page somewhere after a change. */
const LOCATION_HEADER = "X-Impr-Location";

/** Whether a path is one of this server's, and not an asset. @param {string} p */
const local = (p) => p.startsWith("/") && !p.startsWith("//") && !p.startsWith("/\\") && !p.startsWith("/assets/");

/**
 * The side panel: a link or form marked data-inline opens in Tabler's
 * offcanvas instead of a page of its own, and every form inside the panel
 * continues there. The server renders the page's content alone when the
 * request carries X-Impr-Panel; after a change it answers X-Impr-Location,
 * and the whole page goes there, so its message (a toast) shows. Without
 * this script every such link and form is an ordinary page.
 * @param {ParentNode} root
 */
export function startSidePanel(root) {
  const el = root.querySelector("[data-side-panel]");
  if (!(el instanceof HTMLElement)) {
    return;
  }
  const body = /** @type {HTMLElement} */ (el.querySelector("[data-side-panel-body]"));
  const title = el.querySelector("[data-side-panel-title]");
  const full = el.querySelector("[data-side-panel-full]");
  const panel = () => tabler()?.Offcanvas?.getOrCreateInstance(el);

  /** @param {string} url @param {RequestInit} init */
  const load = async (url, init) => {
    const target = new URL(url, window.location.href);
    if (target.origin !== window.location.origin || !local(target.pathname)) {
      return;
    }
    panel()?.show();
    el.setAttribute("aria-busy", "true");
    try {
      const res = await fetch(target.href, { ...init, credentials: "same-origin", headers: { [PANEL_HEADER]: "1" } });
      const go = res.headers.get(LOCATION_HEADER);
      if (go && local(go)) {
        window.location.assign(go);
        return;
      }
      const doc = new DOMParser().parseFromString(await res.text(), "text/html");
      const page = doc.querySelector("[data-panel-page]") ?? doc.querySelector("main") ?? doc.body;
      body.replaceChildren(document.importNode(page, true));
      if (title) {
        title.textContent = page.getAttribute("data-title") ?? doc.title;
      }
      if (full instanceof HTMLAnchorElement) {
        full.href = target.pathname + target.search;
      }
      wire(body);
      const h = body.querySelector("h1, h2, h3");
      if (h instanceof HTMLElement) {
        h.tabIndex = -1;
        h.focus({ preventScroll: true });
      }
    } catch (err) {
      const p = document.createElement("div");
      p.className = "alert alert-danger";
      p.setAttribute("role", "alert");
      p.textContent = `The page could not be loaded: ${String(err)}`;
      body.replaceChildren(p);
    } finally {
      el.removeAttribute("aria-busy");
    }
  };

  /** @param {HTMLFormElement} form @param {HTMLElement | null} submitter */
  const submit = (form, submitter) => {
    const method = (form.getAttribute("method") ?? "get").toUpperCase();
    const data = new FormData(form, submitter ?? undefined);
    const action = new URL(form.getAttribute("action") ?? window.location.href, window.location.href);
    if (method === "GET") {
      action.search = new URLSearchParams(/** @type {any} */ (data)).toString();
      return load(action.href, { method: "GET" });
    }
    const multipart = form.enctype === "multipart/form-data";
    return load(action.href, { method, body: multipart ? data : new URLSearchParams(/** @type {any} */ (data)) });
  };

  /** Marks links and forms in scope to open in the panel. @param {ParentNode} scope */
  const wire = (scope) => {
    for (const a of scope.querySelectorAll("a[data-inline]")) {
      if (!(a instanceof HTMLAnchorElement) || a.dataset.inlineReady) {
        continue;
      }
      a.dataset.inlineReady = "1";
      a.addEventListener("click", (e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) {
          return;
        }
        e.preventDefault();
        load(a.href, { method: "GET" });
      });
    }
    const forms = scope === body ? scope.querySelectorAll("form") : scope.querySelectorAll("form[data-inline]");
    for (const f of forms) {
      if (!(f instanceof HTMLFormElement) || f.dataset.inlineReady || f.hasAttribute("data-panel-skip")) {
        continue;
      }
      f.dataset.inlineReady = "1";
      f.addEventListener("submit", (e) => {
        e.preventDefault();
        submit(f, /** @type {SubmitEvent} */ (e).submitter);
      });
    }
  };

  el.addEventListener("hidden.bs.offcanvas", () => body.replaceChildren());
  wire(document);
}
