# Cenmax AI for Hermes Agent

Use your Cenmax AI subscription in Hermes Agent with device authorization. No API key is required. The browser approval page lets you choose the account that supplies the allowance. Only the models returned for that account are offered; there is no hardcoded fallback catalogue.

Source repository: [cloudcenmax/cenmax-ai-hermes](https://github.com/cloudcenmax/cenmax-ai-hermes).

## Service prerequisite

Before live use, Cenmax AI must register the public OAuth client `cenmax-hermes` with the device-code and refresh-token grants and the `chat` scope. This package does not register clients or contain a client secret. Registration and live service availability have not been verified by the offline tests.

Public authorization origin: `https://console.ai.cenmax.in`. Model requests use its `/app/v1` API. Destinations cannot be changed through plugin environment variables.

## Install

Qualified against **Hermes v0.23.4**, Python **3.14.10**, and its locked OpenAI SDK **2.54.0** on 24 November 2026. This Hermes release requires Python 3.14. The plugin uses the model-provider `auth_handler`, `refresh_credential`, `runtime_base_url` and `create_client` hooks documented at [Model Provider Plugins](https://hermes-agent.nousresearch.com/docs/developer-guide/model-provider-plugin). Hermes supplies `openai` and `httpx`; this plugin does not install packages at runtime. See [qualification](./QUALIFICATION.md) for the live checks.

Copy this directory to `~/.hermes/plugins/model-providers/cenmax-ai/` (or the corresponding directory under the selected profile's `HERMES_HOME`). Keep `__init__.py`, `oauth.py`, and `plugin.yaml` together. Restart Hermes after installing.

```sh
hermes auth add cenmax-ai
hermes model
```

Open the printed Cenmax AI approval URL and approve the displayed code. Then choose Cenmax AI and one of the available models in `hermes model`. Public model IDs such as `pro` and `worker` appear only when available to the signed-in account. Auxiliary tasks use the selected model unless explicitly configured otherwise.

For a headless profile, select the provider and an entitled model before launching chat; a fresh unconfigured profile otherwise starts Hermes's setup wizard. For example, when `worker` is available:

```sh
hermes config set model.provider cenmax-ai
hermes config set model.default worker
hermes chat --provider cenmax-ai --model worker -q "Hello"
```

```sh
hermes auth status cenmax-ai
hermes auth refresh cenmax-ai
hermes auth logout cenmax-ai
```

Logout revokes grants before Hermes removes its local credentials; if the service is unreachable, retry logout. Refresh tokens are single-use and rotate through Hermes' credential-pool lock and persistence. An uncertain refresh result requires a new sign-in; it is never retried with the old refresh token. Do not copy `auth.json` between running profiles or computers. Hermes manages credential-file permissions; this plugin creates no separate token store. Treat the Hermes profile directory as sensitive.

Model discovery fails closed when the catalogue is unavailable. The transport rejects redirects, alternate destinations, ambient HTTP proxies and unsupported API paths. TLS certificate verification stays enabled. No telemetry is added. Approval URLs contain an expiring user code; do not share them. The package does not grant access to conversations, files, tools, or account-management APIs.

## Tests and release

```sh
python3 -m unittest discover -s tests -v
```

Unit tests mock network and Hermes host interfaces. They cover OAuth errors, polling intervals, expiry, refresh rotation, catalogue boundaries, manifest registration, successful revocation response shapes and endpoint safety. Separate live qualification exercised native login, model discovery, a real file-tool round trip, streamed output, conversation resumption, native refresh and native logout. Concurrent-process refresh stress and quota exhaustion were not part of that live run.

Export only `__init__.py`, `oauth.py`, `plugin.yaml`, `README.md`, `QUALIFICATION.md`, `LICENSE`, and `tests/test_plugin.py`, plus reviewed public CI/security metadata. Do not publish profile directories, credentials, `.env` files, logs or Python caches. This directory is independently distributable under the MIT license.
