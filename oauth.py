"""Cenmax AI device authorization. Only the public Cenmax AI service is trusted."""
from __future__ import annotations

import json
import math
import re
import time
import urllib.error
import urllib.parse
import urllib.request

ORIGIN = "https://console.ai.cenmax.in"
BASE_URL = ORIGIN + "/app/v1"
CLIENT_ID = "cenmax-hermes"
MAX_BODY = 1024 * 1024


class OAuthError(RuntimeError):
    def __init__(self, code="request_failed"):
        self.code = code
        super().__init__("Cenmax AI authorization failed. Please retry or sign in again.")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OAuthError("redirect_refused")


def request(path, *, fields=None, access_token=None, timeout=15):
    if path not in {"/oauth/device/code", "/oauth/token", "/oauth/revoke", "/app/v1/models"}:
        raise OAuthError("invalid_endpoint")
    headers = {"Accept": "application/json", "User-Agent": "cenmax-ai-hermes/0.1.0"}
    data = None
    if fields is not None:
        data = urllib.parse.urlencode(fields).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if access_token:
        headers["Authorization"] = "Bearer " + secret(access_token)
    req = urllib.request.Request(ORIGIN + path, data=data, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        try:
            response = opener.open(req, timeout=min(max(float(timeout), 0.1), 30))
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise OAuthError("invalid_response")
            # Revocation succeeds by HTTP status; the service may return an
            # empty body or an empty JSON list instead of an object.
            if path == "/oauth/revoke" and 200 <= response.status < 300:
                return {}
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise OAuthError("invalid_response")
            if response.status >= 300:
                code = payload.get("error")
                allowed = {"authorization_pending", "slow_down", "expired_token", "access_denied", "invalid_grant", "invalid_client", "unauthorized_client", "invalid_token"}
                raise OAuthError(code if isinstance(code, str) and code in allowed else "request_failed")
            return payload
    except OAuthError:
        raise
    except Exception:
        raise OAuthError() from None


def secret(value):
    if not isinstance(value, str) or not value or len(value) > 16384 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise OAuthError("invalid_response")
    return value


def number(value, *, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= maximum:
        raise OAuthError("invalid_response")
    return float(value)


def tokens(payload):
    if str(payload.get("token_type", "")).lower() != "bearer":
        raise OAuthError("invalid_response")
    lifetime = number(payload.get("expires_in"), maximum=86400)
    return {"access_token": secret(payload.get("access_token")),
            "refresh_token": secret(payload.get("refresh_token")),
            "expires_at_ms": int((time.time() + lifetime) * 1000), "expires_in": lifetime}


def start():
    payload = request("/oauth/device/code", fields={"client_id": CLIENT_ID, "scope": "chat"})
    device = secret(payload.get("device_code"))
    code = payload.get("user_code")
    if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z0-9-]{4,32}", code):
        raise OAuthError("invalid_response")
    # Construct the approval URL rather than following a server-supplied URL.
    if payload.get("verification_uri") != ORIGIN + "/oauth/device":
        raise OAuthError("invalid_response")
    lifetime = number(payload.get("expires_in"), maximum=600)
    interval = number(payload.get("interval", 5), maximum=60)
    return {"user_code": code, "verification_url": ORIGIN + "/oauth/device?" + urllib.parse.urlencode({"user_code": code}),
            "expires_in": lifetime, "interval": interval,
            "state": {"device_code": device, "deadline": time.monotonic() + lifetime, "interval": interval, "next_poll": time.monotonic() + interval}}


def poll(state):
    remaining = state["deadline"] - time.monotonic()
    if remaining <= 0:
        raise OAuthError("expired_token")
    if time.monotonic() < state["next_poll"]:
        return {"status": "pending", "interval": state["interval"]}
    state["next_poll"] = time.monotonic() + state["interval"]
    try:
        payload = request("/oauth/token", fields={"client_id": CLIENT_ID,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": secret(state["device_code"])}, timeout=min(15, remaining))
        return {"status": "authorized", "credential": tokens(payload)}
    except OAuthError as exc:
        if exc.code in {"authorization_pending", "slow_down"}:
            if exc.code == "slow_down":
                state["interval"] = min(state["interval"] + 5, 60)
                state["next_poll"] = time.monotonic() + state["interval"]
            return {"status": "pending", "interval": state["interval"]}
        raise


def login(*, output=print, sleep=time.sleep):
    flow = start()
    output("Sign in with Cenmax AI: " + flow["verification_url"])
    output("Approval code: " + flow["user_code"])
    while True:
        remaining = flow["state"]["deadline"] - time.monotonic()
        if remaining <= 0:
            raise OAuthError("expired_token")
        sleep(min(flow["state"]["interval"], remaining))
        result = poll(flow["state"])
        if result["status"] == "authorized":
            return result["credential"]


def refresh(refresh_token):
    return tokens(request("/oauth/token", fields={"client_id": CLIENT_ID,
        "grant_type": "refresh_token", "refresh_token": secret(refresh_token)}))


def revoke(access_token, *, hint="access_token"):
    request("/oauth/revoke", fields={"client_id": CLIENT_ID,
        "token": secret(access_token), "token_type_hint": hint})
