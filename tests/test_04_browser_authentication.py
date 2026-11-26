from __future__ import annotations


# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step3_browser.py
# -----------------------------------------------------------------------------

import threading as src1_threading
from http.server import BaseHTTPRequestHandler as src1_BaseHTTPRequestHandler, ThreadingHTTPServer as src1_ThreadingHTTPServer
from pathlib import Path as src1_Path
from unittest.mock import patch as src1_patch
import pytest as src1_pytest
from security_analyzer.browser import RouteDiscovery as src1_RouteDiscovery, is_playwright_installed as src1_is_playwright_installed, run_browser_capture as src1_run_browser_capture
from security_analyzer.browser.har_recorder import HarRecorder as src1_HarRecorder
from security_analyzer.core.coverage_tracker import CoverageTracker as src1_CoverageTracker
from security_analyzer.core.orchestrator import ExecutionContext as src1_ExecutionContext
from security_analyzer.core.scope_engine import ScopeEngine as src1_ScopeEngine, ScopePolicy as src1_ScopePolicy
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src1_STAGE_DEFINITIONS, StageStatus as src1_StageStatus
from security_analyzer.core.workspace import WorkspaceManager as src1_WorkspaceManager

class src1__SpaTestHandler(src1_BaseHTTPRequestHandler):

    def do_GET(self) -> None:
        if self.path == '/':
            html = '<!doctype html>\n            <html>\n              <head><title>SPA Home</title></head>\n              <body>\n                <a href="/orders">View Orders</a>\n                <a href="/logout">Logout</a>\n                <a href="https://evil.example/phish">External Link</a>\n                <form action="/api/orders/search" method="GET">\n                  <input name="status" />\n                </form>\n                <script src="https://evil.example/tracker.js"></script>\n                <script>\n                  console.error("Auth failed with Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig");\n                  fetch(\'/api/orders?status=open&token=my_secret_token\');\n                </script>\n              </body>\n            </html>'
            self._reply(200, 'text/html', html)
        elif self.path == '/orders':
            self._reply(200, 'text/html', '<html><head><title>Orders</title></head><body>Orders Page</body></html>')
        elif self.path.startswith('/api/orders'):
            self._reply(200, 'application/json', '{"orders":[{"id":101}]}')
        elif self.path == '/logout':
            self._reply(200, 'text/plain', 'SHOULD_NEVER_BE_VISITED')
        else:
            self._reply(404, 'text/plain', 'not found')

    def _reply(self, code: int, ctype: str, body: str) -> None:
        raw = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args) -> None:
        return

def test_no_synthetic_routes_when_playwright_unavailable(tmp_path: Path) -> None:
    ws = src1_WorkspaceManager(project_root=tmp_path)
    ws.init_scan('https://authorized.example')
    engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['authorized.example']))
    cov = src1_CoverageTracker(ws)
    stage_def = next((s for s in src1_STAGE_DEFINITIONS if s.stage_id == 'browser_capture'))
    ctx = src1_ExecutionContext(target='https://authorized.example', workspace=ws, scope_engine=engine, coverage=cov, config={}, upstream_artifacts={'domain_enumeration': {'discovery/subdomains.json': {'hosts': [{'hostname': 'authorized.example', 'url': 'https://authorized.example/'}]}}})
    with src1_patch('security_analyzer.browser.application_crawler.is_playwright_installed', return_value=False):
        result = src1_run_browser_capture(ctx, stage_def)
    assert result.status == src1_StageStatus.SKIPPED
    assert not ws.resolve_path('inventory/unified_endpoints.json').exists()
    assert not ws.resolve_path('browser/crawl_routes.json').exists()

def test_route_discovery_blocks_mutating_actions() -> None:
    assert src1_RouteDiscovery.is_safe_navigation_target('https://example.com/orders', 'View Orders') is True
    assert src1_RouteDiscovery.is_safe_navigation_target('https://example.com/logout', 'Logout') is False
    assert src1_RouteDiscovery.is_safe_navigation_target('https://example.com/items/1', 'Delete Item') is False
    assert src1_RouteDiscovery.is_safe_navigation_target('https://example.com/account', 'Delete Account') is False

def test_native_har_sensitive_values_are_redacted(tmp_path: Path) -> None:
    ws = src1_WorkspaceManager(project_root=tmp_path)
    ws.init_scan('https://authorized.example')
    recorder = src1_HarRecorder(ws)
    target = recorder.prepare_path()
    target.write_text('{"log":{"entries":[{"request":{"url":"https://authorized.example/api?token=secret123","headers":[{"name":"Authorization","value":"Bearer secret"}],"queryString":[{"name":"token","value":"secret123"}],"postData":{"text":"password=secret"}},"response":{"headers":[]}}]}}', encoding='utf-8')
    recorder.redact_sensitive_data()
    saved = target.read_text(encoding='utf-8')
    assert 'secret123' not in saved
    assert 'Bearer secret' not in saved
    assert 'password=secret' not in saved
    assert '[REDACTED]' in saved

@src1_pytest.mark.skipif(not src1_is_playwright_installed(), reason='Playwright not installed')
def test_live_playwright_spa_crawl_har_and_inventory(tmp_path: Path) -> None:
    server = src1_ThreadingHTTPServer(('127.0.0.1', 0), src1__SpaTestHandler)
    port = server.server_address[1]
    thread = src1_threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f'http://127.0.0.1:{port}'
        ws = src1_WorkspaceManager(project_root=tmp_path)
        scan_dir = ws.init_scan(base_url)
        policy = src1_ScopePolicy(allowed_domains=['127.0.0.1'], allowed_ports=[port], allow_private_ips=True)
        engine = src1_ScopeEngine(policy)
        cov = src1_CoverageTracker(ws)
        stage_def = next((s for s in src1_STAGE_DEFINITIONS if s.stage_id == 'browser_capture'))
        ctx = src1_ExecutionContext(target=base_url, workspace=ws, scope_engine=engine, coverage=cov, config={'scope': {'check_dns': False}, 'browser': {'headless': True, 'max_pages': 10, 'max_depth': 1, 'settle_wait_ms': 500, 'capture_screenshots': True, 'record_har': True}}, upstream_artifacts={'domain_enumeration': {'discovery/subdomains.json': {'hosts': [{'hostname': '127.0.0.1', 'url': f'{base_url}/'}]}}})
        result = src1_run_browser_capture(ctx, stage_def)
        if result.status == src1_StageStatus.SKIPPED:
            src1_pytest.skip(result.summary)
        assert result.status == src1_StageStatus.SUCCESS
        assert (scan_dir / 'browser/traffic.har').exists()
        assert (scan_dir / 'browser/console_events.json').exists()
        assert (scan_dir / 'browser/screenshots/page_001.png').exists()
        crawl = ws.read_json('browser/crawl_routes.json')
        visited_urls = {p['url'] for p in crawl['visited_pages']}
        assert f'{base_url}/' in visited_urls
        assert f'{base_url}/orders' in visited_urls
        assert f'{base_url}/logout' not in visited_urls
        assert crawl['blocked_out_of_scope_requests_count'] >= 1
        console_data = ws.read_json('browser/console_events.json')
        assert any(('[REDACTED_SECRET]' in ev['message'] for ev in console_data['events']))
        inv = ws.read_json('inventory/unified_endpoints.json')
        paths = {ep['path'] for ep in inv['endpoints']}
        assert '/api/orders' in paths
        assert '/api/orders/search' in paths
    finally:
        server.shutdown()

def test_network_capture_records_body_schema_without_body_values():
    from security_analyzer.browser.network_capture import _body_schema
    schema = _body_schema('{"email":"person@example.com","password":"not-to-store","profile":{"age":31}}', 'application/json')
    assert schema == {'format': 'json', 'schema': {'email': 'string', 'password': 'string', 'profile': {'age': 'number'}}}
    assert 'person@example.com' not in str(schema)
    assert 'not-to-store' not in str(schema)

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step4_browser_lab.py
# -----------------------------------------------------------------------------

from security_analyzer.authentication.session_storage_bridge import SessionStorageBridge as src2_SessionStorageBridge
from security_analyzer.browser.route_discovery import RouteDiscovery as src2_RouteDiscovery
from security_analyzer.core.config_validation import validate_settings as src2_validate_settings
from security_analyzer.core.egress import policy_is_lab_only as src2_policy_is_lab_only, resolve_browser_egress as src2_resolve_browser_egress
from security_analyzer.core.scope_engine import ScopePolicy as src2_ScopePolicy

def src2__env(monkeypatch, proxy='', enforced=''):
    monkeypatch.delenv('SECURITY_ANALYZER_PROXY', raising=False)
    monkeypatch.delenv('SECURITY_ANALYZER_EGRESS_ENFORCED', raising=False)
    if proxy:
        monkeypatch.setenv('SECURITY_ANALYZER_PROXY', proxy)
    if enforced:
        monkeypatch.setenv('SECURITY_ANALYZER_EGRESS_ENFORCED', enforced)

def test_default_blocks_without_proxy(monkeypatch):
    src2__env(monkeypatch)
    policy = src2_ScopePolicy(allowed_domains=['localhost'], allow_private_ips=True)
    assert src2_resolve_browser_egress(src2_validate_settings({}), policy).mode == 'blocked'

def test_proxy_mode_wins(monkeypatch):
    src2__env(monkeypatch, 'http://127.0.0.1:3128', '1')
    policy = src2_ScopePolicy(allowed_domains=['app.example'])
    assert src2_resolve_browser_egress(src2_validate_settings({}), policy).mode == 'proxy'

def test_lab_mode_allowed_only_for_private_scope(monkeypatch):
    src2__env(monkeypatch)
    config = src2_validate_settings({'browser': {'lab_mode': True}})
    lab = src2_ScopePolicy(allowed_domains=['localhost', '127.0.0.1'], allow_private_ips=True)
    assert src2_resolve_browser_egress(config, lab).mode == 'lab'
    public = src2_ScopePolicy(allowed_domains=['app.example'], allow_private_ips=True)
    assert src2_resolve_browser_egress(config, public).mode == 'blocked'
    no_private = src2_ScopePolicy(allowed_domains=['localhost'], allow_private_ips=False)
    assert src2_resolve_browser_egress(config, no_private).mode == 'blocked'
    assert src2_policy_is_lab_only(lab) is True

def test_lab_mode_must_be_boolean():
    import pytest
    from security_analyzer.core.exceptions import ConfigurationError
    with pytest.raises(ConfigurationError):
        src2_validate_settings({'browser': {'lab_mode': 'yes'}})

class src2__FakePage:

    def evaluate(self, _script):
        return {'origin': 'http://localhost:3000', 'entries': {'k': 'v'}}

def test_capture_from_page_reads_session_storage():
    origin, entries = src2_SessionStorageBridge.capture_from_page(src2__FakePage())
    assert origin == 'http://localhost:3000' and entries == {'k': 'v'}

def test_crawler_skips_logout_pay_delete_actions():
    safe = src2_RouteDiscovery.is_safe_navigation_target
    assert safe('https://t.example/dashboard')
    for bad in ('/logout', '/checkout', '/account/delete', '/api/transfer'):
        assert not safe(f'https://t.example{bad}')
    assert not safe('https://t.example/profile', label_hint='Delete account')

def test_shared_proxy_policy_accepts_host_and_compose_proxy(monkeypatch):
    from security_analyzer.core.egress import is_trusted_scope_proxy
    assert is_trusted_scope_proxy('http://127.0.0.1:3128')
    assert is_trusted_scope_proxy('http://[::1]:3128')
    monkeypatch.setenv('SECURITY_ANALYZER_PROXY_TRANSPORT', 'docker')
    assert is_trusted_scope_proxy('http://egress-proxy:3128')
    monkeypatch.delenv('SECURITY_ANALYZER_PROXY_TRANSPORT', raising=False)
    assert not is_trusted_scope_proxy('http://egress-proxy:3128')
    assert not is_trusted_scope_proxy('http://egress-proxy:8080')
    assert not is_trusted_scope_proxy('http://proxy.example:3128')
    assert not is_trusted_scope_proxy('http://user:pass@127.0.0.1:3128')
    assert not is_trusted_scope_proxy('https://127.0.0.1:3128')
    assert not is_trusted_scope_proxy('http://127.0.0.1:3128/proxy.pac')
    assert not is_trusted_scope_proxy('http://egress-proxy:3128/extra')

def test_proxy_mode_rejects_untrusted_proxy_endpoint(monkeypatch):
    src2__env(monkeypatch, 'http://proxy.example:3128', '1')
    policy = src2_ScopePolicy(allowed_domains=['app.example'])
    result = src2_resolve_browser_egress(src2_validate_settings({}), policy)
    assert result.mode == 'blocked'
    assert 'not an approved' in result.reason

def test_proxy_mode_accepts_docker_compose_scope_proxy(monkeypatch):
    src2__env(monkeypatch, 'http://egress-proxy:3128', '1')
    monkeypatch.setenv('SECURITY_ANALYZER_PROXY_TRANSPORT', 'docker')
    policy = src2_ScopePolicy(allowed_domains=['app.example'])
    result = src2_resolve_browser_egress(src2_validate_settings({}), policy)
    assert result.mode == 'proxy'
    assert result.proxy_url == 'http://egress-proxy:3128'

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step5_browser_auth_integration.py
# -----------------------------------------------------------------------------

from pathlib import Path as src3_Path
from types import SimpleNamespace as src3_SimpleNamespace
from security_analyzer.browser.browser_manager import ScopedBrowserManager as src3_ScopedBrowserManager
from security_analyzer.browser.network_capture import sanitize_headers as src3_sanitize_headers
from security_analyzer.browser.application_crawler import _identity_browser_settings as src3__identity_browser_settings
from security_analyzer.core.config_validation import validate_settings as src3_validate_settings
from security_analyzer.core.scope_engine import ScopeEngine as src3_ScopeEngine, ScopePolicy as src3_ScopePolicy
from security_analyzer.core.resource_governor import ResourceGovernor as src3_ResourceGovernor
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src3_STAGE_DEFINITIONS
from security_analyzer.core.workspace import WorkspaceManager as src3_WorkspaceManager
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer as src3_EndpointNormalizer

class src3__Request:

    def __init__(self, url: str, headers: dict[str, str] | None=None) -> None:
        self.url = url
        self.headers = headers or {}

class src3__Route:

    def __init__(self, url: str, headers: dict[str, str] | None=None) -> None:
        self.request = src3__Request(url, headers)
        self.continued_headers = None
        self.aborted = False

    def continue_(self, headers=None) -> None:
        self.continued_headers = headers

    def abort(self, reason: str='') -> None:
        self.aborted = True

def test_browser_auth_headers_are_bound_to_exact_origins() -> None:
    engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['example.com', 'cdn.example.net']))
    manager = src3_ScopedBrowserManager(engine, auth_headers={'Authorization': 'Bearer identity-token'}, auth_origins={'https://app.example.com'}, check_dns=False)
    same_origin = src3__Route('https://app.example.com/api/me', {'accept': 'application/json'})
    manager._intercept_route(same_origin)
    assert same_origin.continued_headers['Authorization'] == 'Bearer identity-token'
    other_in_scope_origin = src3__Route('https://cdn.example.net/assets/app.js', {'accept': '*/*', 'Authorization': 'Bearer identity-token', 'cookie': 'sid=identity-cookie'})
    manager._intercept_route(other_in_scope_origin)
    assert other_in_scope_origin.continued_headers is not None
    assert 'Authorization' not in other_in_scope_origin.continued_headers
    assert 'cookie' not in other_in_scope_origin.continued_headers
    assert not other_in_scope_origin.aborted

def test_browser_manager_honors_dns_setting() -> None:

    class _Engine:
        called_with = None

        def evaluate_url(self, url: str, *, check_dns: bool=False):
            self.called_with = check_dns

            class _Decision:
                allowed = True
                normalized_url = url
                reason = ''
            return _Decision()
    engine = _Engine()
    manager = src3_ScopedBrowserManager(engine, check_dns=False)
    route = src3__Route('https://example.com/')
    manager._intercept_route(route)
    assert engine.called_with is False

def test_browser_capture_depends_on_authentication_lifecycle() -> None:
    definition = next((stage for stage in src3_STAGE_DEFINITIONS if stage.stage_id == 'browser_capture'))
    assert 'auth_session_lifecycle' in definition.dependencies

def test_endpoint_normalizer_accepts_and_persists_page_title() -> None:
    engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['example.com']))
    normalizer = src3_EndpointNormalizer(engine)
    endpoint = normalizer.normalize('https://example.com/account', title='Account Overview', source='playwright_navigation')
    assert endpoint is not None
    assert endpoint.title == 'Account Overview'

def test_browser_settings_validate_identity_and_capture_limits() -> None:
    cfg = src3_validate_settings({'browser': {'max_pages': 12, 'max_identities': 3, 'max_depth': 2, 'navigation_timeout_ms': 10000, 'settle_wait_ms': 100, 'max_screenshots': 4, 'max_console_events': 100, 'viewport': {'width': 1280, 'height': 720}}})
    assert cfg['browser']['max_identities'] == 3
    try:
        src3_validate_settings({'browser': {'max_identities': 0}})
    except Exception as exc:
        assert 'browser.max_identities' in str(exc)
    else:
        raise AssertionError('Invalid max_identities value was accepted')

def test_identity_browser_settings_filter_auth_and_session_storage_origins(tmp_path: Path) -> None:
    state_file = tmp_path / 'state.json'
    state_file.write_text('{"cookies": [], "origins": []}', encoding='utf-8')
    context = src3_SimpleNamespace(authenticated=True, session_valid=True, headers={'Authorization': 'Bearer identity-token'}, session_storage_by_origin={'https://app.example.com': {'tab': 'user-a'}, 'https://evil.test': {'tab': 'must-not-be-injected'}}, storage_state_path=state_file, to_playwright_storage_state=lambda default_origin: {'cookies': [{'name': 'sid', 'value': 'cookie-value', 'domain': '.example.com'}], 'origins': [{'origin': 'https://app.example.com', 'localStorage': [{'name': 'role', 'value': 'user'}]}, {'origin': 'https://evil.test', 'localStorage': [{'name': 'role', 'value': 'attacker'}]}]})
    profile = src3_SimpleNamespace(browser_auth_origins=['https://app.example.com', 'https://evil.test'])
    execution = src3_SimpleNamespace(target='https://app.example.com/', scope_engine=src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['example.com'])))
    headers, origins, session_storage, storage_path = src3__identity_browser_settings(execution, 'user_a', context, profile, check_dns=False)
    assert headers == {'Authorization': 'Bearer identity-token'}
    assert origins == {'https://app.example.com'}
    assert session_storage == {'https://app.example.com': {'tab': 'user-a'}}
    assert storage_path == {'cookies': [{'name': 'sid', 'value': 'cookie-value', 'domain': '.example.com'}], 'origins': [{'origin': 'https://app.example.com', 'localStorage': [{'name': 'role', 'value': 'user'}]}]}

def test_network_capture_redacts_custom_session_and_secret_headers() -> None:
    safe = src3_sanitize_headers({'Authorization': 'Bearer token', 'X-Session-ID': 'session-secret', 'X-Client-Secret': 'client-secret', 'X-Request-ID': 'req-123', 'Accept': 'application/json'})
    assert safe['Authorization'] == '[REDACTED]'
    assert safe['X-Session-ID'] == '[REDACTED]'
    assert safe['X-Client-Secret'] == '[REDACTED]'
    assert safe['X-Request-ID'] == 'req-123'
    assert safe['Accept'] == 'application/json'

def test_browser_capture_uses_separate_authenticated_identity_contexts(tmp_path: Path, monkeypatch) -> None:
    from types import SimpleNamespace as src3_SimpleNamespace
    from security_analyzer.browser import application_crawler
    from security_analyzer.core.coverage_tracker import CoverageTracker
    from security_analyzer.core.orchestrator import ExecutionContext
    from security_analyzer.core.stage_registry import StageStatus
    from security_analyzer.core.workspace import WorkspaceManager as src3_WorkspaceManager

    class _FakePage:

        def __init__(self, url: str) -> None:
            self.url = url
            self.listeners = {}

        def on(self, event, callback) -> None:
            self.listeners[event] = callback

        def set_default_navigation_timeout(self, timeout) -> None:
            pass

        def set_default_timeout(self, timeout) -> None:
            pass

        def goto(self, url, **kwargs):
            self.url = url
            return src3_SimpleNamespace(status=200)

        def wait_for_timeout(self, timeout) -> None:
            pass

        def title(self) -> str:
            return 'Identity-aware test page'

        def evaluate(self, script):
            return {'links': [], 'forms': [], 'inlineScripts': '', 'locationHref': self.url}
    manager_calls = []

    class _FakeBrowserManager:

        def __init__(self, scope_engine, **kwargs) -> None:
            self.kwargs = kwargs
            self.blocked_requests = []
            self.budget_blocked_requests = 0
            self.page = _FakePage('about:blank')
            manager_calls.append(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def new_page(self, timeout_ms=15000):
            return self.page
    monkeypatch.setattr(application_crawler, 'is_playwright_installed', lambda: True)
    monkeypatch.setattr(application_crawler, 'ScopedBrowserManager', _FakeBrowserManager)
    monkeypatch.setenv('SECURITY_ANALYZER_PROXY', 'http://127.0.0.1:8080')
    monkeypatch.setenv('SECURITY_ANALYZER_EGRESS_ENFORCED', '1')
    workspace = src3_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://app.example.com')
    engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['example.com']))
    coverage = CoverageTracker(workspace)
    storage_state = tmp_path / 'identity-storage.json'
    storage_state.write_text('{"cookies": [], "origins": []}', encoding='utf-8')
    anonymous = src3_SimpleNamespace(identity_id='anonymous', role='anonymous', authenticated=False, session_valid=True, headers={}, session_storage_by_origin={}, storage_state_path=None)
    user_a = src3_SimpleNamespace(identity_id='user_a', role='standard_user', authenticated=True, session_valid=True, headers={'Authorization': 'Bearer user-a-token'}, session_storage_by_origin={'https://app.example.com': {'role': 'user'}}, storage_state_path=storage_state, to_playwright_storage_state=lambda default_origin: {'cookies': [{'name': 'sid', 'value': 'cookie-value', 'domain': '.example.com'}], 'origins': [{'origin': 'https://app.example.com', 'localStorage': [{'name': 'role', 'value': 'user'}]}]})

    class _AuthManager:
        profiles = {'anonymous': None, 'user_a': src3_SimpleNamespace(browser_auth_origins=['https://app.example.com'])}

        def list_identities(self):
            return ['anonymous', 'user_a']

        def get_context(self, identity_id):
            return {'anonymous': anonymous, 'user_a': user_a}[identity_id]
    context = ExecutionContext(target='https://app.example.com/', workspace=workspace, scope_engine=engine, coverage=coverage, config={'scope': {'check_dns': False}, 'browser': {'headless': True, 'max_pages': 2, 'max_depth': 0, 'navigation_timeout_ms': 3000, 'settle_wait_ms': 0, 'capture_screenshots': False, 'record_har': False, 'max_identities': 5}}, upstream_artifacts={'domain_enumeration': {'discovery/subdomains.json': {'hosts': [{'hostname': 'app.example.com', 'url': 'https://app.example.com/'}]}}}, auth_manager=_AuthManager())
    stage = next((item for item in src3_STAGE_DEFINITIONS if item.stage_id == 'browser_capture'))
    result = application_crawler.run_browser_capture(context, stage)
    assert result.status == StageStatus.SUCCESS
    assert len(manager_calls) == 2
    user_call = next((call for call in manager_calls if call['auth_headers']))
    assert user_call['auth_headers'] == {'Authorization': 'Bearer user-a-token'}
    assert user_call['auth_origins'] == {'https://app.example.com'}
    assert user_call['storage_state'] == {'cookies': [{'name': 'sid', 'value': 'cookie-value', 'domain': '.example.com'}], 'origins': [{'origin': 'https://app.example.com', 'localStorage': [{'name': 'role', 'value': 'user'}]}]}
    assert user_call['session_storage_by_origin'] == {'https://app.example.com': {'role': 'user'}}
    crawl = workspace.read_json('browser/crawl_routes.json')
    assert [item['identity_id'] for item in crawl['identity_captures']] == ['anonymous', 'user_a']
    assert len(crawl['visited_pages']) == 2
    assert all((item['identity_id'] in {'anonymous', 'user_a'} for item in crawl['visited_pages']))
    for capture in crawl['identity_captures']:
        assert workspace.resolve_path(capture['artifacts']['console']).is_file()

def test_browser_requests_obey_scan_wide_request_budget() -> None:
    engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['example.com']))
    governor = src3_ResourceGovernor({'max_total_requests': 1, 'max_external_processes': 2, 'max_concurrent_processes': 1, 'max_response_bytes': 1024, 'max_process_output_bytes': 1024, 'max_scan_duration_sec': 30, 'requests_per_host_per_sec': 100, 'max_concurrent_requests': 1})
    manager = src3_ScopedBrowserManager(engine, resource_governor=governor, check_dns=False)
    first = src3__Route('https://example.com/')
    manager._intercept_route(first)
    assert not first.aborted
    second = src3__Route('https://example.com/second')
    manager._intercept_route(second)
    assert second.aborted
    assert manager.budget_blocked_requests == 1
    assert governor.requests_used == 1

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step4_authentication.py
# -----------------------------------------------------------------------------

import os as src4_os
import stat as src4_stat
import threading as src4_threading
from http.server import BaseHTTPRequestHandler as src4_BaseHTTPRequestHandler, ThreadingHTTPServer as src4_ThreadingHTTPServer
from pathlib import Path as src4_Path
from security_analyzer.authentication import AuthManager as src4_AuthManager, run_auth_session_lifecycle as src4_run_auth_session_lifecycle
from security_analyzer.authentication.session_storage_bridge import SessionStorageBridge as src4_SessionStorageBridge
from security_analyzer.core.coverage_tracker import CoverageTracker as src4_CoverageTracker
from security_analyzer.core.orchestrator import ExecutionContext as src4_ExecutionContext
from security_analyzer.core.scope_engine import ScopeEngine as src4_ScopeEngine, ScopePolicy as src4_ScopePolicy
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src4_STAGE_DEFINITIONS, StageStatus as src4_StageStatus
from security_analyzer.core.workspace import WorkspaceManager as src4_WorkspaceManager

def test_session_storage_is_scoped_to_origin() -> None:

    class _FakeBrowserContext:
        script = ''

        def add_init_script(self, script: str) -> None:
            self.script = script
    context = _FakeBrowserContext()
    src4_SessionStorageBridge.apply_to_browser_context(context, {'https://Example.com/': {'role_hint': 'user_a'}})
    assert 'https://example.com' in context.script
    assert '"role_hint": "user_a"' in context.script

class src4__AuthTestHandler(src4_BaseHTTPRequestHandler):
    active_tokens = {'token_a_v1', 'token_a_v2', 'token_b'}
    expired_tokens = {'token_a_expired'}

    def do_POST(self) -> None:
        if self.path == '/api/login':
            self._reply(200, '{"access_token":"token_a_v1","refresh_token":"refresh_a_1"}', headers={'Set-Cookie': 'sid=cookie_a; Path=/; HttpOnly'})
        elif self.path == '/api/refresh':
            self._reply(200, '{"access_token":"token_a_v2","refresh_token":"refresh_a_2"}')
        elif self.path == '/api/logout':
            auth = self.headers.get('Authorization', '')
            tok = auth.replace('Bearer ', '').strip()
            self.active_tokens.discard(tok)
            self._reply(200, '{"logged_out":true}')
        else:
            self._reply(404, '{"error":"not_found"}')

    def do_GET(self) -> None:
        auth = self.headers.get('Authorization', '')
        tok = auth.replace('Bearer ', '').strip()
        if self.path == '/api/me':
            if tok in self.expired_tokens:
                self._reply(401, '{"error":"token_expired"}')
            elif tok in self.active_tokens:
                self._reply(200, f'{{"user":"{tok}"}}')
            else:
                self._reply(401, '{"error":"unauthenticated"}')
        elif self.path == '/api/admin':
            if tok in self.active_tokens:
                self._reply(403, '{"error":"forbidden_role"}')
            else:
                self._reply(401, '{"error":"unauthenticated"}')
        else:
            self._reply(404, '{"error":"not_found"}')

    def _reply(self, code: int, body: str, headers: dict[str, str] | None=None) -> None:
        raw = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args) -> None:
        return

def test_isolated_identities_refresh_and_secret_permissions(tmp_path: Path, monkeypatch) -> None:
    server = src4_ThreadingHTTPServer(('127.0.0.1', 0), src4__AuthTestHandler)
    port = server.server_address[1]
    thread = src4_threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f'http://127.0.0.1:{port}'
        monkeypatch.setenv('TEST_USER_B_TOK', 'token_b')
        profiles_yaml = tmp_path / 'auth_profiles.yaml'
        profiles_yaml.write_text(f'\nverify_logout_invalidation: true\nidentities:\n  user_a:\n    role: "user"\n    auth_method: "api_login"\n    login_url: "{base_url}/api/login"\n    whoami_url: "{base_url}/api/me"\n    refresh_url: "{base_url}/api/refresh"\n    logout_url: "{base_url}/api/logout"\n    credentials:\n      username: "alice@example.com"\n      password: "Password123!"\n    extra_headers:\n      X-Tenant-ID: "tenant-a"\n    session_storage:\n      "{base_url}":\n        tab_role: "alice"\n  user_b:\n    role: "user"\n    auth_method: "bearer_token"\n    whoami_url: "{base_url}/api/me"\n    token: "${{TEST_USER_B_TOK}}"\n', encoding='utf-8')
        ws = src4_WorkspaceManager(project_root=tmp_path)
        ws.init_scan(base_url)
        engine = src4_ScopeEngine(src4_ScopePolicy(allowed_domains=['127.0.0.1'], allowed_ports=[port], allow_private_ips=True))
        cov = src4_CoverageTracker(ws)
        stage_def = next((s for s in src4_STAGE_DEFINITIONS if s.stage_id == 'auth_session_lifecycle'))
        ctx = src4_ExecutionContext(target=base_url, workspace=ws, scope_engine=engine, coverage=cov, config={'auth_profiles_path': str(profiles_yaml)})
        result = src4_run_auth_session_lifecycle(ctx, stage_def)
        assert result.status == src4_StageStatus.SUCCESS
        audit = ws.read_json('analysis/auth_sessions.json')
        assert next((r for r in audit['records'] if r['identity']['identity_id'] == 'user_a'))['logout_invalidation']['server_invalidated_session'] is True
        mgr: src4_AuthManager = ctx.auth_manager
        ctx_a = mgr.get_context('user_a')
        ctx_b = mgr.get_context('user_b')
        ctx_anon = mgr.get_context('anonymous')
        assert ctx_a.headers['Authorization'] == 'Bearer token_a_v1'
        assert ctx_a.headers['X-Tenant-ID'] == 'tenant-a'
        assert ctx_b.headers['Authorization'] == 'Bearer token_b'
        assert 'Authorization' not in ctx_anon.headers
        client_a = ctx_a.create_http_client(engine, check_dns=False)
        client_b = ctx_b.create_http_client(engine, check_dns=False)
        client_anon = ctx_anon.create_http_client(engine, check_dns=False)
        try:
            assert client_a.session.headers['Authorization'] == 'Bearer token_a_v1'
            assert client_a.session.headers['X-Tenant-ID'] == 'tenant-a'
            assert client_b.session.headers['Authorization'] == 'Bearer token_b'
            assert 'Authorization' not in client_anon.session.headers
            assert client_a.session.cookies.get('sid') == 'cookie_a'
            assert client_b.session.cookies.get('sid') is None
            assert client_anon.session.cookies.get('sid') is None
        finally:
            client_a.session.close()
            client_b.session.close()
            client_anon.session.close()
        assert ctx_a.storage_state_path is not None and ctx_a.storage_state_path.exists()
        assert ctx_a.session_storage_path is not None and ctx_a.session_storage_path.exists()
        if src4_os.name == 'posix':
            mode = src4_stat.S_IMODE(ctx_a.storage_state_path.stat().st_mode)
            assert mode == 384
        report_text = ws.resolve_path('analysis/auth_sessions.json').read_text(encoding='utf-8')
        assert 'token_a_v1' not in report_text
        assert 'token_b' not in report_text
        assert 'cookie_a' not in report_text
        ctx_a.access_token = 'token_a_expired'
        ctx_a.headers['Authorization'] = 'Bearer token_a_expired'
        val_outcome = mgr.session_manager.validate_session(mgr.profiles['user_a'], ctx_a, auto_refresh=True)
        assert val_outcome['state'] == 'expired_recovered'
        assert val_outcome['refresh']['token_rotated'] is True
        assert ctx_a.access_token == 'token_a_v2'
        admin_profile = mgr.profiles['user_a']
        admin_profile.whoami_url = f'{base_url}/api/admin'
        forbid_outcome = mgr.session_manager.validate_session(admin_profile, ctx_a, auto_refresh=False)
        assert forbid_outcome['state'] == 'authenticated_forbidden'
        assert ctx_a.session_valid is True
        assert ctx_a.expired_detected is False
    finally:
        server.shutdown()
        server.server_close()


# Step 1 shared destructive-path and redirect-evidence regression tests.
def test_har_redacts_sensitive_values_in_absolute_and_relative_location_headers(tmp_path: Path) -> None:
    import json
    from security_analyzer.browser.har_recorder import HarRecorder
    from security_analyzer.core.workspace import WorkspaceManager

    workspace = WorkspaceManager(project_root=tmp_path)
    workspace.init_scan("https://authorized.example")
    har_path = workspace.resolve_path("browser/traffic.har")
    har_path.parent.mkdir(parents=True, exist_ok=True)
    har_path.write_text(
        json.dumps({
            "log": {"entries": [{
                "request": {
                    "url": "https://authorized.example/start?token=request-secret",
                    "headers": [],
                },
                "response": {
                    "headers": [
                        {"name": "Location", "value": "https://authorized.example/next?access_token=redirect-secret"},
                        {"name": "Location", "value": "/login?session_id=relative-secret"},
                        {"name": "Location", "value": "/continue/eyJhbGciOiJIUzI1NiJ9.payloadSegment123.signatureSegment456"},
                        {"name": "Location", "value": "/redirect?next=https%3A%2F%2Fauthorized.example%2Fcallback%3Ftoken%3Dnested-secret"},
                    ],
                    "redirectURL": "https://authorized.example/final?password=redirect-password",
                },
            }]},
        }),
        encoding="utf-8",
    )

    HarRecorder(workspace).sanitize_and_summarize()
    saved = har_path.read_text(encoding="utf-8")
    for secret in (
        "request-secret",
        "redirect-secret",
        "relative-secret",
        "redirect-password",
        "eyJhbGciOiJIUzI1NiJ9.payloadSegment123.signatureSegment456",
        "nested-secret",
    ):
        assert secret not in saved
    assert "[REDACTED]" in saved


def test_route_discovery_uses_shared_destructive_request_policy() -> None:
    from types import SimpleNamespace
    from security_analyzer.browser.route_discovery import RouteDiscovery

    snapshot = {
        "links": [
            {"href": "/account/profile", "text": "Profile"},
            {"href": "/account/unsubscribe", "text": "Unsubscribe"},
            {"href": "/api/orders/submit", "text": "Continue"},
            {"href": "/account/preferences", "text": "Delete account"},
        ],
        "forms": [
            {"action": "/api/search", "method": "GET", "inputs": ["q"]},
            {"action": "/api/orders/submit", "method": "GET", "inputs": ["id"]},
            {"action": "/api/orders", "method": "POST", "inputs": ["id"]},
        ],
        "inlineScripts": "const a='/api/profile'; const b='/api/submit';",
        "locationHref": "https://authorized.example/",
    }
    page = SimpleNamespace(evaluate=lambda _script: snapshot)
    result = RouteDiscovery().extract_from_page(page, "https://authorized.example/")

    assert "https://authorized.example/account/profile" in result["links"]
    assert "https://authorized.example/account/unsubscribe" not in result["links"]
    assert "https://authorized.example/api/orders/submit" not in result["links"]
    assert "https://authorized.example/account/preferences" not in result["links"]

    forms = result["forms"]
    assert forms[0].is_potentially_mutating is False
    assert forms[1].is_potentially_mutating is True
    assert forms[2].is_potentially_mutating is True
    assert "https://authorized.example/api/profile" in result["spa_routes"]
    assert "https://authorized.example/api/submit" not in result["spa_routes"]


def test_expired_authenticated_identity_makes_auth_stage_partial(tmp_path: Path, monkeypatch) -> None:
    from security_analyzer.authentication import auth_manager as auth_module
    from security_analyzer.core.orchestrator import ExecutionContext
    from security_analyzer.core.stage_registry import STAGE_DEFINITIONS, StageStatus
    from security_analyzer.authentication.auth_manager import run_auth_session_lifecycle

    class _ExpiredAuthManager:
        def __init__(self, **_kwargs):
            pass

        def initialize_all(self, *, stage_id: str):
            return {
                "total_identities": 1,
                "authenticated_identities": 1,
                "records": [{
                    "identity": {
                        "identity_id": "user_a",
                        "auth_method": "bearer_token",
                        "authenticated": True,
                        "session_valid": False,
                    },
                    "validation": {"state": "expired", "session_valid": False},
                }],
            }

    monkeypatch.setattr(auth_module, "AuthManager", _ExpiredAuthManager)
    workspace = src4_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan("https://example.test/")
    engine = src4_ScopeEngine(src4_ScopePolicy(allowed_domains=["example.test"]))
    context = ExecutionContext(
        target="https://example.test/",
        workspace=workspace,
        scope_engine=engine,
        coverage=src4_CoverageTracker(workspace),
        config={},
    )
    stage = next(item for item in STAGE_DEFINITIONS if item.stage_id == "auth_session_lifecycle")
    result = run_auth_session_lifecycle(context, stage)
    assert result.status == StageStatus.PARTIAL
    assert result.metrics["targets_skipped"] == 1
