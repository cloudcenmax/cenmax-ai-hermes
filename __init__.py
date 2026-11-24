"""Cenmax AI subscription access for Hermes Agent."""
from __future__ import annotations

import re
import uuid

from providers import register_provider
from providers.base import ProviderProfile
from . import oauth

PROVIDER = "cenmax-ai"


def save_credential(credential):
    from agent.credential_pool import AUTH_TYPE_OAUTH, PooledCredential, load_pool
    load_pool(PROVIDER).add_entry(PooledCredential(
        provider=PROVIDER, id=uuid.uuid4().hex, label="Cenmax AI",
        auth_type=AUTH_TYPE_OAUTH, priority=0, source="manual:cenmax_device",
        access_token=credential["access_token"], refresh_token=credential["refresh_token"],
        expires_at_ms=credential["expires_at_ms"], base_url=oauth.BASE_URL))


def auth_handler(action, args):
    if action == "add":
        save_credential(oauth.login())
        print("Signed in to Cenmax AI. Run hermes model to select an available model.")
        return True
    if action == "logout":
        from agent.credential_pool import load_pool
        # Revoke remotely before Hermes removes its local rows. On network failure
        # retain the rows so the user can retry revocation.
        for entry in load_pool(PROVIDER).entries():
            if entry.refresh_token:
                oauth.revoke(entry.refresh_token, hint="refresh_token")
            else:
                oauth.revoke(entry.access_token)
    # Status, refresh and local removal stay with Hermes' credential manager.
    return False


def refresh_credential(entry):
    # Hermes calls this under its cross-process credential-store lock and persists
    # the replacement before releasing the lock. Do not retry a spent refresh token.
    if entry.provider != PROVIDER or entry.base_url not in (None, oauth.BASE_URL):
        raise oauth.OAuthError("invalid_endpoint")
    try:
        return oauth.refresh(entry.refresh_token)
    except oauth.OAuthError:
        # A timeout, malformed success or server error may follow a completed
        # rotation. Never let the host retry a possibly spent refresh token.
        from hermes_cli.auth_constants import AuthError
        raise AuthError("Cenmax AI sign-in needs renewal. Run hermes auth add cenmax-ai.",
                        code="invalid_grant", relogin_required=True) from None



class CenmaxProfile(ProviderProfile):
    def runtime_base_url(self, *, api_key, default, env_url):
        return oauth.BASE_URL

    def fetch_models(self, *, api_key=None, base_url=None, timeout=8.0):
        if base_url and base_url.rstrip("/") != oauth.BASE_URL:
            raise oauth.OAuthError("invalid_endpoint")
        if not api_key:
            return []
        payload = oauth.request("/app/v1/models", access_token=api_key, timeout=timeout)
        rows = payload.get("data")
        if not isinstance(rows, list):
            raise oauth.OAuthError("invalid_response")
        result = []
        current_capabilities = {}
        for row in rows:
            if not isinstance(row, dict):
                raise oauth.OAuthError("invalid_response")
            model = row.get("id")
            if not isinstance(model, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", model) or row.get("owned_by") != "Cenmax AI":
                raise oauth.OAuthError("invalid_response")
            result.append(model)
            caps = row.get("capabilities", {})
            metadata = {}
            if isinstance(caps, dict):
                for public, hermes in (("tools", "supports_tools"), ("vision", "supports_vision"), ("reasoning", "supports_reasoning")):
                    if isinstance(caps.get(public), bool):
                        metadata[hermes] = caps[public]
            context = row.get("context_window")
            if isinstance(context, int) and not isinstance(context, bool) and context > 0:
                metadata["context_window"] = context
            current_capabilities[model] = metadata
        self.model_capabilities = current_capabilities
        return list(dict.fromkeys(result))

    def create_client(self, **kwargs):
        import httpx
        from openai import OpenAI
        def guard(request):
            url = request.url
            if (url.scheme != "https" or url.host != "console.ai.cenmax.in" or url.port not in (None, 443)
                    or url.path not in {"/app/v1/chat/completions", "/app/v1/models"}
                    or url.username or url.password or url.query):
                raise oauth.OAuthError("invalid_endpoint")
        # No configurable destination, redirect following, ambient proxy, or
        # caller-supplied HTTP transport can carry this subscription credential.
        client = httpx.Client(follow_redirects=False, trust_env=False,
                              event_hooks={"request": [guard]}, timeout=60)
        return OpenAI(api_key=oauth.secret(kwargs.get("api_key")), base_url=oauth.BASE_URL,
                      http_client=client, max_retries=0)


register_provider(CenmaxProfile(
    name=PROVIDER, display_name="Cenmax AI", description="Use your Cenmax AI subscription",
    signup_url=oauth.ORIGIN, base_url=oauth.BASE_URL, models_url=oauth.BASE_URL + "/models",
    api_mode="chat_completions", auth_type="oauth_device_code",
    auth_handler=auth_handler, refresh_credential=refresh_credential,
    fallback_models=(), default_aux_model="", env_vars=(),
))
