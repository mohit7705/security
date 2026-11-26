from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

from security_analyzer.utils.request_safety import is_destructive_request

STATIC_ASSET_EXT_RE = re.compile(
    r"(?i)\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|webm|pdf|zip)$"
)

SPA_ROUTE_LITERAL_RE = re.compile(
    r"""["'](/(?:api|v1|v2|v3|app|account|profile|settings|orders|users|dashboard|auth|graphql)[a-zA-Z0-9_./:-]{0,80})["']"""
)


@dataclass(frozen=True)
class DiscoveredForm:
    action_url: str
    method: str
    input_names: list[str]
    is_potentially_mutating: bool


class RouteDiscovery:
    """Extracts internal links, HTML form contracts, and SPA client routes without triggering state changes."""

    @staticmethod
    def is_safe_navigation_target(url: str, label_hint: str = "") -> bool:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return False
        if STATIC_ASSET_EXT_RE.search(parsed.path or ""):
            return False
        if is_destructive_request(url, method="GET", label_hint=label_hint):
            return False
        return True

    def extract_from_page(self, page: Any, current_url: str) -> dict[str, Any]:
        dom_snapshot = page.evaluate(
            """() => {
                const links = Array.from(document.querySelectorAll('a[href]')).map(a => ({
                    href: a.getAttribute('href') || '',
                    text: (a.innerText || a.getAttribute('aria-label') || '').trim().slice(0, 80)
                }));
                const forms = Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.getAttribute('action') || '',
                    method: (f.getAttribute('method') || 'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input[name], select[name], textarea[name]'))
                        .map(el => el.getAttribute('name'))
                        .filter(Boolean)
                }));
                const inlineScripts = Array.from(document.querySelectorAll('script:not([src])'))
                    .map(s => s.textContent || '')
                    .join('\\n')
                    .slice(0, 100000);
                return { links, forms, inlineScripts, locationHref: window.location.href };
            }"""
        )

        safe_links: list[str] = []
        skipped_mutating_links: list[str] = []
        seen_links: set[str] = set()

        for item in dom_snapshot.get("links", []):
            raw_href = str(item.get("href", "")).strip()
            label = str(item.get("text", "")).strip()
            if not raw_href or raw_href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            resolved = urljoin(current_url, raw_href).split("#", 1)[0]
            if resolved in seen_links:
                continue
            seen_links.add(resolved)

            if self.is_safe_navigation_target(resolved, label):
                safe_links.append(resolved)
            else:
                skipped_mutating_links.append(resolved)

        discovered_forms: list[DiscoveredForm] = []
        for form in dom_snapshot.get("forms", []):
            raw_action = str(form.get("action", "")).strip()
            action_url = urljoin(current_url, raw_action or current_url).split("#", 1)[0]
            method = str(form.get("method", "GET")).upper()
            inputs = sorted({str(name) for name in form.get("inputs", []) if name})
            mutating = is_destructive_request(action_url, method=method)
            discovered_forms.append(
                DiscoveredForm(
                    action_url=action_url,
                    method=method,
                    input_names=inputs,
                    is_potentially_mutating=mutating,
                )
            )

        spa_routes: list[str] = []
        inline_code = str(dom_snapshot.get("inlineScripts", ""))
        for match in SPA_ROUTE_LITERAL_RE.findall(inline_code):
            candidate = urljoin(current_url, match)
            if candidate not in seen_links:
                seen_links.add(candidate)
                if is_destructive_request(candidate, method="GET"):
                    skipped_mutating_links.append(candidate)
                else:
                    spa_routes.append(candidate)

        return {
            "links": safe_links,
            "skipped_mutating_links": skipped_mutating_links,
            "forms": discovered_forms,
            "spa_routes": spa_routes,
        }
