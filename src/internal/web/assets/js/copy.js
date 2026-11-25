/**
 * A button marked data-copy="<element id>" copies that element's text, once:
 * a token shown once is copied, then the button says so. @param {ParentNode} root
 */
export function startCopy(root) {
  for (const btn of root.querySelectorAll("button[data-copy]")) {
    if (!(btn instanceof HTMLButtonElement) || btn.dataset.copyReady) {
      continue;
    }
    btn.dataset.copyReady = "1";
    btn.addEventListener("click", async () => {
      const src = document.getElementById(btn.dataset.copy ?? "");
      if (!src) {
        return;
      }
      try {
        await navigator.clipboard.writeText(src.textContent?.trim() ?? "");
        btn.textContent = "Copied";
        btn.disabled = true;
      } catch {
        btn.textContent = "Select the text and copy it";
      }
    });
  }
}
