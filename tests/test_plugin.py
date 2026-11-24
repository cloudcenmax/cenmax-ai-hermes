import importlib.util
import json
import pathlib
import sys
import types
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
registered = []
providers = types.ModuleType('providers')
providers.register_provider = registered.append
base = types.ModuleType('providers.base')
class ProviderProfile:
    def __init__(self, **kwargs):
        self.model_capabilities = {}
        self.__dict__.update(kwargs)
base.ProviderProfile = ProviderProfile
sys.modules.setdefault('providers', providers)
sys.modules.setdefault('providers.base', base)
spec = importlib.util.spec_from_file_location('cenmax_plugin', ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(spec)
sys.modules['cenmax_plugin'] = plugin
spec.loader.exec_module(plugin)
oauth = plugin.oauth

TOKEN = {'access_token': 'test-access', 'refresh_token': 'test-refresh', 'expires_in': 3600, 'token_type': 'Bearer'}
DEVICE = {'device_code': 'test-device', 'user_code': 'ABCD-EFGH', 'verification_uri': oauth.ORIGIN + '/oauth/device', 'expires_in': 600, 'interval': 5}

class Response:
    def __init__(self, payload, status=200):
        self.payload = json.dumps(payload).encode()
        self.status = status
    def read(self, n):
        return self.payload[:n]
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass

class PluginTests(unittest.TestCase):
    def test_registered_oauth_profile_has_no_fallback_entitlements(self):
        profile = registered[0]
        self.assertEqual(profile.name, 'cenmax-ai')
        self.assertEqual(profile.auth_type, 'oauth_device_code')
        self.assertEqual(profile.fallback_models, ())
        self.assertEqual(profile.runtime_base_url(api_key='x', default='https://evil.example', env_url='https://evil.example'), oauth.BASE_URL)

    def test_token_validation_and_expiry(self):
        with patch.object(oauth.time, 'time', return_value=100):
            result = oauth.tokens(TOKEN)
        self.assertEqual(result['expires_at_ms'], 3700000)
        self.assertEqual(result['refresh_token'], 'test-refresh')
        for override in ({'access_token': 'x\r\ny'}, {'expires_in': float('nan')}, {'expires_in': True}, {'refresh_token': ''}, {'token_type': 'Other'}):
            with self.subTest(override=override), self.assertRaises(oauth.OAuthError):
                oauth.tokens({**TOKEN, **override})

    def test_approval_url_is_constructed_and_validated(self):
        with patch.object(oauth, 'request', return_value={**DEVICE, 'verification_uri_complete': 'https://evil.example'}):
            result = oauth.start()
        self.assertEqual(result['verification_url'], oauth.ORIGIN + '/oauth/device?user_code=ABCD-EFGH')
        for url in ('https://console.ai.cenmax.in.evil.example/oauth/device', 'http://console.ai.cenmax.in/oauth/device', oauth.ORIGIN + '/oauth/device#x'):
            with self.subTest(url=url), patch.object(oauth, 'request', return_value={**DEVICE, 'verification_uri': url}), self.assertRaises(oauth.OAuthError):
                oauth.start()
        with patch.object(oauth, 'request', return_value={**DEVICE, 'user_code': '\x1b[31m'}), self.assertRaises(oauth.OAuthError):
            oauth.start()

    def state(self):
        return {'device_code': 'test-device', 'deadline': 200, 'interval': 5, 'next_poll': 100}

    def test_poll_honors_initial_interval(self):
        with patch.object(oauth.time, 'monotonic', return_value=99), patch.object(oauth, 'request') as req:
            self.assertEqual(oauth.poll(self.state())['status'], 'pending')
            req.assert_not_called()

    def test_poll_slowdown_and_pending(self):
        state = self.state()
        with patch.object(oauth.time, 'monotonic', return_value=100), patch.object(oauth, 'request', side_effect=oauth.OAuthError('slow_down')):
            self.assertEqual(oauth.poll(state)['interval'], 10)
        self.assertEqual(state['next_poll'], 110)
        with patch.object(oauth.time, 'monotonic', return_value=110), patch.object(oauth, 'request', side_effect=oauth.OAuthError('authorization_pending')):
            self.assertEqual(oauth.poll(state)['interval'], 10)

    def test_expired_poll_never_sends_device_code(self):
        with patch.object(oauth.time, 'monotonic', return_value=201), patch.object(oauth, 'request') as req, self.assertRaises(oauth.OAuthError):
            oauth.poll(self.state())
        req.assert_not_called()

    def test_poll_success_and_denial(self):
        with patch.object(oauth.time, 'monotonic', return_value=100), patch.object(oauth, 'request', return_value=TOKEN):
            self.assertEqual(oauth.poll(self.state())['status'], 'authorized')
        with patch.object(oauth.time, 'monotonic', return_value=100), patch.object(oauth, 'request', side_effect=oauth.OAuthError('access_denied')), self.assertRaises(oauth.OAuthError):
            oauth.poll(self.state())

    def test_refresh_returns_rotated_pair(self):
        entry = types.SimpleNamespace(provider='cenmax-ai', base_url=oauth.BASE_URL, refresh_token='test-old')
        with patch.object(oauth, 'request', return_value=TOKEN) as req:
            rotated = plugin.refresh_credential(entry)
        self.assertEqual(rotated['refresh_token'], 'test-refresh')
        self.assertEqual(req.call_args.kwargs['fields']['refresh_token'], 'test-old')
        entry.base_url = 'https://evil.example'
        with patch.object(oauth, 'request') as req, self.assertRaises(oauth.OAuthError):
            plugin.refresh_credential(entry)
        req.assert_not_called()

    def test_uncertain_refresh_is_terminal_to_prevent_replay(self):
        constants = types.ModuleType('hermes_cli.auth_constants')
        class AuthError(Exception):
            def __init__(self, message, **kwargs):
                super().__init__(message)
                self.__dict__.update(kwargs)
        constants.AuthError = AuthError
        entry = types.SimpleNamespace(provider='cenmax-ai', base_url=oauth.BASE_URL, refresh_token='test-old')
        for code in ('request_failed', 'invalid_response', 'invalid_grant'):
            with patch.dict(sys.modules, {'hermes_cli.auth_constants': constants}), patch.object(oauth, 'refresh', side_effect=oauth.OAuthError(code)), self.assertRaises(AuthError) as exc:
                plugin.refresh_credential(entry)
            self.assertTrue(exc.exception.relogin_required)
            self.assertEqual(exc.exception.code, 'invalid_grant')

    def test_http_errors_are_redacted_and_redirects_blocked(self):
        opener = types.SimpleNamespace(open=lambda *a, **kw: Response({'error': 'invalid_grant', 'error_description': 'SECRET'}, 400))
        with patch.object(oauth.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(oauth.OAuthError) as exc:
                oauth.request('/oauth/token', fields={'refresh_token': 'test-secret'})
        self.assertEqual(exc.exception.code, 'invalid_grant')
        self.assertNotIn('SECRET', str(exc.exception))
        with self.assertRaises(oauth.OAuthError):
            oauth.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.example')
        with self.assertRaises(oauth.OAuthError):
            oauth.request('https://evil.example')

    def test_revocation_accepts_successful_empty_list_and_body_without_weakening_token_validation(self):
        for payload, status in [(b'[]', 200), (b'', 204), (b'{}', 200)]:
            response = Response({}, status)
            response.payload = payload
            opener = types.SimpleNamespace(open=lambda *a, **kw: response)
            with self.subTest(status=status, payload=payload), patch.object(oauth.urllib.request, 'build_opener', return_value=opener):
                self.assertEqual(oauth.request('/oauth/revoke', fields={'token': 'test-refresh', 'token_type_hint': 'refresh_token'}), {})
        opener = types.SimpleNamespace(open=lambda *a, **kw: Response([]))
        with patch.object(oauth.urllib.request, 'build_opener', return_value=opener), self.assertRaises(oauth.OAuthError):
            oauth.request('/oauth/token', fields={'refresh_token': 'test-refresh'})
        response = Response({}, 200)
        response.payload = b'x' * (oauth.MAX_BODY + 1)
        opener = types.SimpleNamespace(open=lambda *a, **kw: response)
        with patch.object(oauth.urllib.request, 'build_opener', return_value=opener), self.assertRaises(oauth.OAuthError):
            oauth.request('/oauth/revoke', fields={'token': 'test-refresh'})

    def test_logout_revokes_before_declining_to_host_local_cleanup(self):
        pool = types.ModuleType('agent.credential_pool')
        entries = [types.SimpleNamespace(access_token='test-access', refresh_token='test-refresh')]
        pool.load_pool = lambda provider: types.SimpleNamespace(entries=lambda: entries)
        with patch.dict(sys.modules, {'agent.credential_pool': pool}), patch.object(oauth, 'revoke') as revoke:
            self.assertFalse(plugin.auth_handler('logout', types.SimpleNamespace()))
            revoke.assert_called_once_with('test-refresh', hint='refresh_token')
        with patch.dict(sys.modules, {'agent.credential_pool': pool}), patch.object(oauth, 'revoke', side_effect=oauth.OAuthError()), self.assertRaises(oauth.OAuthError):
            plugin.auth_handler('logout', types.SimpleNamespace())

    def test_catalogue_entitlements_and_public_identity(self):
        profile = registered[0]
        with patch.object(oauth, 'request', return_value={'data': [{'id': 'pro', 'owned_by': 'Cenmax AI', 'context_window': 32000}]}):
            self.assertEqual(profile.fetch_models(api_key='test'), ['pro'])
            self.assertEqual(profile.model_capabilities['pro']['context_window'], 32000)
        with patch.object(oauth, 'request', return_value={'data': []}):
            self.assertEqual(profile.fetch_models(api_key='test'), [])
            self.assertEqual(profile.model_capabilities, {})
        self.assertEqual(profile.fetch_models(), [])
        for row in ({'id': 'private/model', 'owned_by': 'Cenmax AI'}, {'id': 'pro', 'owned_by': 'Other'}, {'id': 'pro\x1b', 'owned_by': 'Cenmax AI'}):
            with patch.object(oauth, 'request', return_value={'data': [row]}), self.assertRaises(oauth.OAuthError):
                profile.fetch_models(api_key='test')
        with self.assertRaises(oauth.OAuthError):
            profile.fetch_models(api_key='test', base_url='https://evil.example')

    def test_guarded_sdk_client_contract(self):
        captured = {}
        httpx = types.ModuleType('httpx')
        sdk = types.ModuleType('openai')
        httpx.Client = lambda **kw: captured.update(http=kw) or kw
        sdk.OpenAI = lambda **kw: captured.update(sdk=kw) or kw
        with patch.dict(sys.modules, {'httpx': httpx, 'openai': sdk}):
            registered[0].create_client(api_key='test-access', base_url='https://evil.example', http_client=object())
        self.assertFalse(captured['http']['follow_redirects'])
        self.assertFalse(captured['http']['trust_env'])
        self.assertEqual(captured['sdk']['base_url'], oauth.BASE_URL)
        guard = captured['http']['event_hooks']['request'][0]
        url = types.SimpleNamespace(scheme='https', host='console.ai.cenmax.in', port=None, path='/app/v1/chat/completions', username='', password='', query=b'')
        guard(types.SimpleNamespace(url=url))
        for field, value in [('host', 'evil.example'), ('path', '/oauth/token'), ('query', b'key=leak'), ('scheme', 'http')]:
            bad = types.SimpleNamespace(**{**url.__dict__, field: value})
            with self.assertRaises(oauth.OAuthError):
                guard(types.SimpleNamespace(url=bad))

if __name__ == '__main__':
    unittest.main()
