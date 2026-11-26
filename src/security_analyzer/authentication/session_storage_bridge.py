from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from security_analyzer.authentication.storage_state_store import StorageStateStore


class SessionStorageBridge:
    """Captures and restores browser sessionStorage, which Playwright storage_state omits."""

    def __init__(self, store: StorageStateStore) -> None:
        self.store = store

    def save_for_identity(
        self,
        identity_id: str,
        session_storage_by_origin: dict[str, dict[str, str]],
    ) -> Path:
        payload = {"origins": session_storage_by_origin}
        return self.store.write_secret_json(f"{identity_id}_session_storage.json", payload)

    @staticmethod
    def capture_from_page(page: Any) -> tuple[str, dict[str, str]]:
        """Extract window.sessionStorage from an active Playwright page."""
        raw = page.evaluate(
            """() => {
                const entries = {};
                for (let i = 0; i < window.sessionStorage.length; i++) {
                    const k = window.sessionStorage.key(i);
                    if (k !== null) {
                        entries[k] = window.sessionStorage.getItem(k) || '';
                    }
                }
                return { origin: window.location.origin, entries };
            }"""
        )
        origin = str(raw.get("origin", "")).strip()
        entries = {str(k): str(v) for k, v in (raw.get("entries") or {}).items()}
        return origin, entries

    @staticmethod
    def apply_to_browser_context(
        context: Any,
        session_storage_by_origin: dict[str, dict[str, str]],
    ) -> None:
        """Inject an init script that populates window.sessionStorage per matching origin."""
        if not session_storage_by_origin:
            return

        normalized_map: dict[str, dict[str, str]] = {}
        for raw_origin, entries in session_storage_by_origin.items():
            parsed = urlsplit(raw_origin.strip())
            if parsed.scheme and parsed.netloc:
                origin_key = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
                normalized_map[origin_key] = dict(entries)

        if not normalized_map:
            return

        serialized_map = json.dumps(normalized_map)
        script = f"""(() => {{
            const storeByOrigin = {serialized_map};
            const currentOrigin = window.location.origin.toLowerCase();
            const entries = storeByOrigin[currentOrigin];
            if (!entries) return;
            for (const [k, v] of Object.entries(entries)) {{
                try {{
                    window.sessionStorage.setItem(k, String(v));
                }} catch (e) {{}}
            }}
        }})();"""
        context.add_init_script(script)
