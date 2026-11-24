# Hermes qualification

Tested on 24 November 2026 using the published Hermes `v0.23.4` Git tag (commit `8fc037444731`), managed Python 3.14.10, and the release's locked dependencies in a disposable Linux container. No harness source changes or substitute inference service were used.

| Check | Result |
| --- | --- |
| Discover the installed model-provider plugin | Passed; Cenmax AI OAuth profile registered |
| Native `hermes auth add cenmax-ai` device login | Passed |
| Discover entitled public models using the signed-in credential | Passed |
| Real file-reading tool and streamed final response | Passed; synthetic file contents returned |
| Native `hermes auth refresh cenmax-ai` | Passed; refresh token changed and expiry renewed |
| Resume the same conversation after refresh | Passed; previous file content recalled without another tool call |
| Native `hermes auth logout cenmax-ai` | Passed; zero local test credentials remain |
| Request models with the revoked access token | Rejected with HTTP 401 |

The live run caught a successful-revocation response parsing issue; it was fixed, covered by a regression, and native logout was retested successfully. A successful revocation is determined by HTTP status, including when its body is `[]` or empty.

The test authorization was revoked and the container removed afterward. No account identifiers, tokens, or raw session exports are included. Repeat qualification for other harness versions. This run does not establish performance under concurrent refresh stress or quota exhaustion.
