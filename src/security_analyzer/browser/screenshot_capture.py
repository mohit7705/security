# src/security_analyzer/browser/screenshot_capture.py
from __future__ import annotations

from typing import Any

from security_analyzer.core.workspace import WorkspaceManager

_MASK_PII_SCRIPT = """
() => {
  const emailRe = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}/g;
  const phoneRe = /\\+?[0-9][0-9\\-\\s().]{7,}[0-9]/g;
  const jwtRe = /eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}/g;
  const bearerRe = /\\bBearer\\s+[A-Za-z0-9._~+\\/-]{8,}={0,2}/gi;
  const secretAssignmentRe = /\\b(?:access[_-]?token|refresh[_-]?token|api[_-]?key|client[_-]?secret|password|passwd|authorization|session[_-]?id)\\s*[:=]\\s*[^\\s&,;]+/gi;

  document.querySelectorAll('input, textarea, select').forEach((el) => {
    const type = (el.getAttribute('type') || '').toLowerCase();
    const name = (el.getAttribute('name') || '').toLowerCase();
    const id = (el.getAttribute('id') || '').toLowerCase();
    if (['password', 'email', 'tel'].includes(type) ||
        /token|secret|password|passwd|email|phone|mobile|address|ssn|session|auth|account|user.?id/.test(name + ' ' + id)) {
      if ('value' in el) el.value = '[REDACTED]';
      el.setAttribute('value', '[REDACTED]');
      if (el.tagName === 'TEXTAREA') el.textContent = '[REDACTED]';
    }
  });

  document.querySelectorAll('*').forEach((el) => {
    for (const attr of Array.from(el.attributes || [])) {
      if (/token|secret|password|passwd|email|phone|mobile|address|ssn|session|authorization|cookie/i.test(attr.name)) {
        el.setAttribute(attr.name, '[REDACTED]');
      } else if (attr.value && (new RegExp(emailRe.source).test(attr.value) || new RegExp(phoneRe.source).test(attr.value) || new RegExp(jwtRe.source).test(attr.value))) {
        el.setAttribute(attr.name, '[REDACTED]');
      }
    }
  });

  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    if (!node.nodeValue) continue;
    const updated = node.nodeValue
      .replace(jwtRe, '[REDACTED_TOKEN]')
      .replace(bearerRe, '[REDACTED_TOKEN]')
      .replace(secretAssignmentRe, '[REDACTED_SECRET]')
      .replace(emailRe, '[REDACTED_EMAIL]')
      .replace(phoneRe, '[REDACTED_PHONE]');
    if (updated !== node.nodeValue) {
      node.nodeValue = updated;
    }
  }
}
"""


class ScreenshotCapture:
    """Captures bounded viewport screenshots with pre-capture PII/token DOM masking."""

    def __init__(
        self,
        workspace: WorkspaceManager,
        max_screenshots: int = 15,
        relative_dir: str = "browser/screenshots",
    ) -> None:
        self.workspace = workspace
        self.max_screenshots = max(0, int(max_screenshots))
        self.relative_dir = relative_dir.strip("/\\")
        self.records: list[dict[str, Any]] = []

    @property
    def artifacts(self) -> list[dict[str, Any]]:
        """Compatibility alias; screenshot records are already JSON-ready."""
        return list(self.records)

    def capture(self, page: Any, url: str) -> dict[str, Any] | None:
        if len(self.records) >= self.max_screenshots:
            return None
        index = len(self.records) + 1
        rel_path = f"{self.relative_dir}/page_{index:03d}.png"
        target_path = self.workspace.resolve_path(rel_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        # A screenshot containing unmasked secrets is not acceptable evidence.
        # Abort capture if the masking script cannot execute.
        page.evaluate(_MASK_PII_SCRIPT)
        page.screenshot(path=str(target_path), full_page=False)
        from urllib.parse import urlsplit, urlunsplit
        parsed = urlsplit(url)
        safe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "[REDACTED]" if parsed.query else "", ""))
        record = {
            "index": index,
            "url": safe_url,
            "relative_path": rel_path,
            "sha256": self.workspace.file_sha256(rel_path),
        }
        self.records.append(record)
        return record