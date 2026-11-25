/**
 * The events page's live list: a table body marked data-events-live with
 * data-events-src (the stream's URL) gets each new event at the top, as text.
 * Without the script, the page shows the events as of its loading.
 * @param {ParentNode} root
 */
export function startEvents(root) {
  const tbody = root.querySelector("tbody[data-events-live]");
  if (!(tbody instanceof HTMLElement) || !window.EventSource) {
    return;
  }
  const status = document.querySelector("[data-events-status]");
  const src = new EventSource(tbody.dataset.eventsSrc ?? "/events/stream");
  src.addEventListener("open", () => {
    if (status) {
      status.textContent = "Live";
    }
  });
  src.addEventListener("error", () => {
    if (status) {
      status.textContent = "Reconnecting…";
    }
  });
  src.addEventListener("message", (e) => {
    let ev;
    try {
      ev = JSON.parse(e.data);
    } catch {
      return;
    }
    const tr = document.createElement("tr");
    for (const [label, value] of [["Time", ev.time], ["Type", ev.type], ["Subject", ev.subject]]) {
      const td = document.createElement("td");
      td.dataset.label = label;
      td.textContent = String(value ?? "");
      tr.append(td);
    }
    tbody.querySelector("[data-events-empty]")?.remove();
    tbody.prepend(tr);
    while (tbody.rows.length > 200) {
      tbody.deleteRow(-1);
    }
  });
}
