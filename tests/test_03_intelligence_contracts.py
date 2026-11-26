from __future__ import annotations


# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step3_intelligence_contracts.py
# -----------------------------------------------------------------------------

import json as src1_json
from types import SimpleNamespace as src1_SimpleNamespace
from security_analyzer.intelligence.graphql_analyzer import GraphQlAnalyzer as src1_GraphQlAnalyzer
from security_analyzer.intelligence.js_bundle_analyzer import JsBundleAnalyzer as src1_JsBundleAnalyzer
from security_analyzer.intelligence.openapi_analyzer import OpenApiAnalyzer as src1_OpenApiAnalyzer

class src1__Decision:
    allowed = True
    normalized_url = ''

class src1__Scope:

    def evaluate_url(self, url, check_dns=True):
        return src1__Decision()

class src1__Response:

    def __init__(self, body, content_type='application/json', status=200):
        self.status_code = status
        self.headers = {'Content-Type': content_type}
        if isinstance(body, bytes):
            self.content = body
            self.text = body.decode('utf-8', errors='replace')
        elif isinstance(body, str):
            self.text = body
            self.content = body.encode()
        else:
            self.content = src1_json.dumps(body).encode()
            self.text = self.content.decode()

    def json(self):
        return src1_json.loads(self.text)

    # Keep the historical helper name for any consolidated tests that use it.
    def src1_json(self):
        return self.json()

class src1__Client:

    def __init__(self, responses):
        self.scope_engine = src1__Scope()
        self.responses = responses
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(('GET', url))
        return self.responses[url]

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get('json_body')))
        queue = self.responses[url]
        if isinstance(queue, list):
            return queue.pop(0)
        return queue

def test_openapi_resolves_nested_refs_allof_and_swagger2_body_parameters():
    spec = {'swagger': '2.0', 'host': 'api.example.test', 'schemes': ['https'], 'basePath': '/v1', 'paths': {'/profiles/{profileId}': {'parameters': [{'$ref': '#/parameters/ProfileId'}], 'post': {'parameters': [{'$ref': '#/parameters/ProfileBody'}]}}}, 'parameters': {'ProfileId': {'name': 'profileId', 'in': 'path', 'required': True, 'type': 'string'}, 'ProfileBody': {'name': 'body', 'in': 'body', 'schema': {'$ref': '#/definitions/ProfileInput'}}}, 'definitions': {'ProfileInput': {'allOf': [{'type': 'object', 'properties': {'displayName': {'type': 'string'}}}, {'$ref': '#/definitions/PrivilegedFields'}]}, 'PrivilegedFields': {'type': 'object', 'properties': {'role': {'type': 'string'}, 'verified': {'type': 'boolean'}}}}}
    fields = src1_OpenApiAnalyzer._extract_body_properties(spec['paths']['/profiles/{profileId}']['post'], spec, shared_parameters=spec['paths']['/profiles/{profileId}']['parameters'])
    assert fields == ['displayName', 'role', 'verified']
    resolved = src1_OpenApiAnalyzer._resolve_local_ref({'$ref': '#/parameters/ProfileId'}, spec)
    assert resolved['name'] == 'profileId'

def test_openapi_does_not_resolve_external_refs():
    assert src1_OpenApiAnalyzer._resolve_local_ref({'$ref': 'https://attacker.invalid/schema.json'}, {}) is None

def test_swagger2_host_basepath_and_refs_produce_scoped_operations():
    spec_url = 'https://docs.example.test/swagger.json'
    spec = {'swagger': '2.0', 'host': 'api.example.test', 'schemes': ['https'], 'basePath': '/v1', 'paths': {'/profiles/{profileId}': {'parameters': [{'$ref': '#/parameters/ProfileId'}], 'post': {'parameters': [{'$ref': '#/parameters/ProfileBody'}]}}}, 'parameters': {'ProfileId': {'name': 'profileId', 'in': 'path', 'required': True, 'type': 'string'}, 'ProfileBody': {'name': 'body', 'in': 'body', 'schema': {'$ref': '#/definitions/ProfileInput'}}}, 'definitions': {'ProfileInput': {'allOf': [{'type': 'object', 'properties': {'displayName': {'type': 'string'}}}, {'$ref': '#/definitions/PrivilegedFields'}]}, 'PrivilegedFields': {'type': 'object', 'properties': {'role': {'type': 'string'}, 'verified': {'type': 'boolean'}}}}}
    client = src1__Client({spec_url: src1__Response(spec)})
    specs, operations, findings = src1_OpenApiAnalyzer(client).discover_and_parse([], [spec_url])
    assert len(specs) == 1
    assert len(operations) == 1
    operation = operations[0]
    assert operation.url == 'https://api.example.test/v1/profiles/{profileId}'
    assert operation.path_params == ['profileId']
    assert operation.body_fields == ['displayName', 'role', 'verified']

def test_openapi_server_variables_use_declared_defaults():
    spec_url = 'https://docs.example.test/openapi.json'
    spec = {'openapi': '3.0.3', 'servers': [{'url': 'https://{subdomain}.example.test/v1', 'variables': {'subdomain': {'default': 'api'}}}], 'paths': {'/profiles': {'get': {'operationId': 'profiles.list'}}}}
    client = src1__Client({spec_url: src1__Response(spec)})
    _, operations, _ = src1_OpenApiAnalyzer(client).discover_and_parse([], [spec_url])
    assert operations[0].url == 'https://api.example.test/v1/profiles'

def test_openapi_server_template_without_default_is_not_guessed():
    spec_url = 'https://docs.example.test/openapi.json'
    spec = {'openapi': '3.0.3', 'servers': [{'url': 'https://{subdomain}.example.test/v1'}], 'paths': {'/profiles': {'get': {'operationId': 'profiles.list'}}}}
    client = src1__Client({spec_url: src1__Response(spec)})
    specs, operations, _ = src1_OpenApiAnalyzer(client).discover_and_parse([], [spec_url])
    assert specs == []
    assert operations == []

def test_graphql_type_ref_unwraps_non_null_and_list():
    from security_analyzer.intelligence.graphql_analyzer import _type_ref_label
    kind, name = _type_ref_label({'kind': 'NON_NULL', 'name': None, 'ofType': {'kind': 'LIST', 'name': None, 'ofType': {'kind': 'OBJECT', 'name': 'Profile'}}})
    assert kind == 'NON_NULL'
    assert name == 'Profile'

def test_javascript_source_map_requires_embedded_source_content():
    js_url = 'https://app.example.test/assets/app.js'
    map_url = 'https://app.example.test/assets/app.js.map'
    js = b'const x = 1;\\n//# sourceMappingURL=app.js.map'
    source_map = {'version': 3, 'sources': ['../src/profile.ts'], 'sourcesContent': ['export const privateImplementation = true;']}
    client = src1__Client({js_url: src1__Response(js, 'application/javascript'), map_url: src1__Response(source_map)})
    analyzer = src1_JsBundleAnalyzer(client)
    records, routes, findings = analyzer.analyze_bundles([js_url])
    assert len(records) == 1
    assert records[0]['source_map_exposed'] is True
    assert records[0]['source_map_content_exposed'] is True
    assert records[0]['source_map_metadata']['embedded_sources_count'] == 1
    assert any((item['category'] == 'source_map_source_content_exposed' for item in findings))
    assert 'privateImplementation' not in src1_json.dumps(records + findings)

def test_javascript_source_map_without_sources_content_is_not_called_source_exposure():
    js_url = 'https://app.example.test/assets/app.js'
    map_url = 'https://app.example.test/assets/app.js.map'
    client = src1__Client({js_url: src1__Response(b'const x = 1;', 'application/javascript'), map_url: src1__Response({'version': 3, 'sources': ['../src/app.ts']})})
    records, _, findings = src1_JsBundleAnalyzer(client).analyze_bundles([js_url])
    assert records[0]['source_map_exposed'] is True
    assert records[0]['source_map_content_exposed'] is False
    assert not any((item['category'] == 'source_map_source_content_exposed' for item in findings))

def test_graphql_catalog_records_field_arguments_and_return_type():
    from security_analyzer.intelligence.graphql_analyzer import GraphQlAnalyzer as src1_GraphQlAnalyzer
    url = 'https://app.example.test/graphql'
    introspection = {'data': {'__schema': {'queryType': {'name': 'Query'}, 'mutationType': {'name': 'Mutation'}, 'types': [{'name': 'Query', 'kind': 'OBJECT', 'fields': [{'name': 'me', 'args': [], 'type': {'kind': 'OBJECT', 'name': 'Profile'}}, {'name': 'profile', 'args': [{'name': 'id', 'defaultValue': None, 'type': {'kind': 'NON_NULL', 'name': None, 'ofType': {'kind': 'SCALAR', 'name': 'ID'}}}], 'type': {'kind': 'OBJECT', 'name': 'Profile'}}]}, {'name': 'Mutation', 'kind': 'OBJECT', 'fields': [{'name': 'updateProfile', 'args': [], 'type': {'kind': 'SCALAR', 'name': 'Boolean'}}]}, {'name': 'Profile', 'kind': 'OBJECT', 'fields': []}]}}}
    client = src1__Client({url: [src1__Response({'data': {'__typename': 'Query'}}), src1__Response(introspection)]})
    endpoints, operations, findings = src1_GraphQlAnalyzer(client).analyze([], [url])
    me = next((item for item in operations if item.graphql_field == 'me'))
    profile = next((item for item in operations if item.graphql_field == 'profile'))
    mutation = next((item for item in operations if item.graphql_field == 'updateProfile'))
    assert me.graphql_returns_object is True
    assert profile.graphql_args[0]['required'] is True
    assert mutation.tags == ['graphql', 'mutation']
    assert endpoints[0]['query_field_details'][0]['name'] == 'me'

def test_workflow_models_are_hypotheses_and_never_execute_transitions():
    from security_analyzer.deep_checks.business_logic import _build_workflow_models
    models = _build_workflow_models([{'operation_id': 'order.create', 'method': 'POST', 'path': '/api/orders', 'source': 'openapi'}, {'operation_id': 'order.validate', 'method': 'POST', 'path': '/api/orders/{id}/validate', 'source': 'openapi'}, {'operation_id': 'order.pay', 'method': 'POST', 'path': '/api/orders/{id}/pay', 'source': 'openapi'}, {'operation_id': 'order.refund', 'method': 'POST', 'path': '/api/orders/{id}/refund', 'source': 'openapi'}, {'operation_id': 'graphql.query', 'method': 'POST', 'path': '/graphql', 'source': 'graphql'}], [])
    assert len(models) == 1
    model = models[0]
    assert model['resource_path'] == '/api/orders'
    assert {item['action'] for item in model['actions']} == {'create', 'validate', 'pay', 'refund'}
    assert model['state_changing_requests_performed'] is False
    assert all((item['validated'] is False for item in model['candidate_transitions']))
    assert all((item['approval_required'] for item in model['candidate_transitions']))
    assert model['human_approval_gate']['execution_enabled'] is False
    assert 'graphql' not in str(models)

def test_authenticated_discovery_context_does_not_prove_endpoint_is_protected():
    from security_analyzer.deep_checks.authorization_idor import _endpoint_declared_protected
    endpoint = src1_SimpleNamespace(method='GET', path='/api/profile', authenticated=True)
    assert _endpoint_declared_protected([], endpoint) is False
    assert _endpoint_declared_protected([{'method': 'GET', 'path': '/api/profile', 'requires_auth': True}], endpoint) is True

def test_graphql_introspection_disabled_keeps_endpoint_without_crashing():
    url = 'https://app.example.test/graphql'
    client = src1__Client({url: [src1__Response({'data': {'__typename': 'Query'}}), src1__Response({'errors': [{'message': 'introspection disabled'}]})]})
    endpoints, operations, findings = src1_GraphQlAnalyzer(client).analyze([], [url])
    assert len(endpoints) == 1
    assert endpoints[0]['introspection_enabled'] is False
    assert operations == []

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step5_intelligence_scanners.py
# -----------------------------------------------------------------------------

import json as src2_json
import threading as src2_threading
from http.server import BaseHTTPRequestHandler as src2_BaseHTTPRequestHandler, ThreadingHTTPServer as src2_ThreadingHTTPServer
from pathlib import Path as src2_Path
from unittest.mock import patch as src2_patch
from security_analyzer.core.coverage_tracker import CoverageTracker as src2_CoverageTracker
from security_analyzer.core.orchestrator import ExecutionContext as src2_ExecutionContext
from security_analyzer.core.scope_engine import ScopeEngine as src2_ScopeEngine, ScopePolicy as src2_ScopePolicy
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src2_STAGE_DEFINITIONS, StageStatus as src2_StageStatus
from security_analyzer.core.workspace import WorkspaceManager as src2_WorkspaceManager
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer as src2_EndpointNormalizer
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory as src2_UnifiedEndpointInventory
from security_analyzer.intelligence import run_api_js_intelligence as src2_run_api_js_intelligence
from security_analyzer.scanners import parse_nuclei_jsonl as src2_parse_nuclei_jsonl, run_nuclei_assessment as src2_run_nuclei_assessment, run_security_review as src2_run_security_review

class src2__ApiAndJsTestHandler(src2_BaseHTTPRequestHandler):

    def do_GET(self) -> None:
        if self.path == '/':
            html = '<html><head><script src="/static/app.js"></script></head><body>API App</body></html>'
            self._reply(200, 'text/html', html, extra_headers={'Access-Control-Allow-Origin': 'https://untrusted-origin.example'})
        elif self.path == '/openapi.json':
            spec = {'openapi': '3.0.3', 'info': {'title': 'Orders API', 'version': '1.0.0'}, 'paths': {'/api/orders/{orderId}': {'get': {'operationId': 'getOrder', 'parameters': [{'name': 'orderId', 'in': 'path', 'required': True}], 'security': []}}}}
            self._reply(200, 'application/json', src2_json.dumps(spec))
        elif self.path == '/static/app.js':
            js = 'const ep = "/api/v1/internal/export"; const key = "AKIA1234567890ABCDEF";'
            self._reply(200, 'application/javascript', js)
        else:
            self._reply(404, 'text/plain', 'not found')

    def do_POST(self) -> None:
        if self.path == '/graphql':
            length = int(self.headers.get('Content-Length', '0'))
            raw = self.rfile.read(length).decode('utf-8')
            if '__schema' in raw:
                resp = {'data': {'__schema': {'queryType': {'name': 'Query'}, 'mutationType': {'name': 'Mutation'}, 'types': [{'name': 'Query', 'kind': 'OBJECT', 'fields': [{'name': 'userProfile'}]}, {'name': 'Mutation', 'kind': 'OBJECT', 'fields': [{'name': 'deleteUser'}]}]}}}
            else:
                resp = {'data': {'__typename': 'Query'}}
            self._reply(200, 'application/json', src2_json.dumps(resp))
        else:
            self._reply(404, 'text/plain', 'not found')

    def _reply(self, code: int, ctype: str, body: str, extra_headers: dict[str, str] | None=None) -> None:
        raw = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(raw)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args) -> None:
        return

def test_openapi_graphql_js_and_header_scanners(tmp_path: Path) -> None:
    server = src2_ThreadingHTTPServer(('127.0.0.1', 0), src2__ApiAndJsTestHandler)
    port = server.server_address[1]
    thread = src2_threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f'http://127.0.0.1:{port}'
        ws = src2_WorkspaceManager(project_root=tmp_path)
        ws.init_scan(base_url)
        engine = src2_ScopeEngine(src2_ScopePolicy(allowed_domains=['127.0.0.1'], allowed_ports=[port], allow_private_ips=True))
        cov = src2_CoverageTracker(ws)
        inv = src2_UnifiedEndpointInventory(ws)
        norm = src2_EndpointNormalizer(engine)
        root_ep = norm.normalize(f'{base_url}/', method='GET', source='http_probing', status_code=200, content_type='text/html', reachable=True)
        assert root_ep is not None
        inv.upsert_endpoint(root_ep)
        inv.save()
        ctx = src2_ExecutionContext(target=base_url, workspace=ws, scope_engine=engine, coverage=cov, config={'scope': {'check_dns': False}})
        sec_def = next((s for s in src2_STAGE_DEFINITIONS if s.stage_id == 'security_review'))
        sec_res = src2_run_security_review(ctx, sec_def)
        assert sec_res.status == src2_StageStatus.SUCCESS
        sec_data = ws.read_json('analysis/security_headers.json')
        assert any((f['category'] == 'cors_origin_reflection' for f in sec_data['findings']))
        api_def = next((s for s in src2_STAGE_DEFINITIONS if s.stage_id == 'api_js_intelligence'))
        api_res = src2_run_api_js_intelligence(ctx, api_def)
        assert api_res.status == src2_StageStatus.SUCCESS
        catalog = ws.read_json('analysis/api_catalog.json')
        assert len(catalog['openapi_specs']) == 1
        assert len(catalog['graphql_endpoints']) == 1
        assert catalog['graphql_endpoints'][0]['introspection_enabled'] is True
        js_raw_text = ws.resolve_path('analysis/javascript_intel.json').read_text(encoding='utf-8')
        assert 'AKIA1234567890ABCDEF' not in js_raw_text
        assert '[REDACTED]' in js_raw_text
        updated_inv = ws.read_json('inventory/unified_endpoints.json')
        paths = {ep['path'] for ep in updated_inv['endpoints']}
        assert '/api/orders/1' in paths
        assert '/graphql' in paths
        assert '/api/v1/internal/export' in paths
    finally:
        server.shutdown()
        server.server_close()

def test_nuclei_jsonl_parser_and_missing_binary_skip(tmp_path: Path) -> None:
    sample_jsonl = [src2_json.dumps({'template-id': 'exposed-env', 'host': 'https://example.com', 'matched-at': 'https://example.com/.env', 'info': {'name': 'Exposed .env File', 'severity': 'high', 'tags': ['exposure']}})]
    parsed = src2_parse_nuclei_jsonl(sample_jsonl, {'https://example.com/.env': 'ep_12345'})
    assert len(parsed) == 1
    assert parsed[0]['severity'] == 'HIGH'
    assert parsed[0]['endpoint_id'] == 'ep_12345'
    ws = src2_WorkspaceManager(project_root=tmp_path)
    ws.init_scan('https://example.com')
    engine = src2_ScopeEngine(src2_ScopePolicy(allowed_domains=['example.com']))
    cov = src2_CoverageTracker(ws)
    ctx = src2_ExecutionContext(target='https://example.com', workspace=ws, scope_engine=engine, coverage=cov, config={})
    nuc_def = next((s for s in src2_STAGE_DEFINITIONS if s.stage_id == 'nuclei_assessment'))
    with src2_patch('security_analyzer.scanners.nuclei_runner.shutil.which', return_value=None):
        res = src2_run_nuclei_assessment(ctx, nuc_def)
    assert res.status == src2_StageStatus.SKIPPED

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step6_intelligence_hardening.py
# -----------------------------------------------------------------------------

from types import SimpleNamespace as src3_SimpleNamespace
from security_analyzer.core.scope_engine import ScopeDecision as src3_ScopeDecision, ScopeEngine as src3_ScopeEngine, ScopePolicy as src3_ScopePolicy
from security_analyzer.intelligence.graphql_analyzer import GraphQlAnalyzer as src3_GraphQlAnalyzer
from security_analyzer.intelligence.js_bundle_analyzer import JsBundleAnalyzer as src3_JsBundleAnalyzer
from security_analyzer.intelligence.openapi_analyzer import OpenApiAnalyzer as src3_OpenApiAnalyzer

class src3_FakeResponse:

    def __init__(self, status=200, content=b'', content_type='application/json', payload=None):
        self.status_code = status
        self.content = content
        self.text = content.decode('utf-8')
        self.headers = {'Content-Type': content_type}
        self._payload = payload

    def json(self):
        return self._payload

class src3_FakeClient:

    def __init__(self, response):
        self.response = response
        self.scope_engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['example.com']))
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(('GET', url))
        return self.response

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        return self.response

def test_oversized_openapi_document_not_parsed():
    client = src3_FakeClient(src3_FakeResponse(content=b' ' * 1500001))
    specs, ops, findings = src3_OpenApiAnalyzer(client).discover_and_parse([], ['https://example.com/openapi.json'])
    assert specs == ops == findings == []

def test_oversized_js_bundle_not_partially_analyzed():
    client = src3_FakeClient(src3_FakeResponse(content=b'A' * 2048))
    bundles, routes, findings = src3_JsBundleAnalyzer(client, max_bundle_bytes=1024).analyze_bundles(['https://example.com/app.js'])
    assert bundles == routes == findings == []

def test_graphql_introspection_is_informational():

    class GqlClient(src3_FakeClient):

        def request(self, method, url, **kwargs):
            query = kwargs['json_body']['query']
            if '__schema' in query:
                return src3_FakeResponse(payload={'data': {'__schema': {'queryType': {'name': 'Query'}, 'mutationType': None, 'types': [{'name': 'Query', 'fields': [{'name': 'health'}]}]}}})
            return src3_FakeResponse(payload={'data': {'__typename': 'Query'}})
    client = GqlClient(None)
    client.scope_engine.evaluate_url = lambda url, check_dns=True: src3_ScopeDecision(True, url, 'unit-test scope')
    info, ops, findings = src3_GraphQlAnalyzer(client).analyze([], ['https://example.com/graphql'])
    assert info[0]['introspection_enabled'] is True
    assert len(ops) == 1
    assert findings[0]['severity'] == 'INFO'


def test_javascript_bundle_analyzer_rejects_unresolved_route_templates() -> None:
    assert src1_JsBundleAnalyzer._has_unresolved_template("https://example.test/api/orders/{order_id}")
    assert not src1_JsBundleAnalyzer._has_unresolved_template("https://example.test/api/orders/123")
