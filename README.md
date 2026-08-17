# Bifrost plugin: Anthropic Inference hooks

Serves Claude Enterprise **Inference hooks** from inside Bifrost. Anthropic POSTs a
signed prompt frame before every governed inference request (claude.ai, Claude Code,
Cowork); this plugin verifies the signature, scans the transcript, and answers
`allow` or `deny`.

This is the inbound direction — Anthropic calls you. It is not the same as routing
inference through the gateway, and it covers Cowork, which a proxy cannot.

## What it does

- Verifies the Standard Webhooks signature over the raw body, with a 5-minute
  timestamp tolerance and support for multiple secrets during rotation.
- Rejects unsigned requests unless `allow_unsigned` is on (only needed for the
  connection test before your org's first save).
- Scans text blocks, tool inputs, tool results and extracted attachment text
  against your regex rules.
- Always answers HTTP 200 with a parseable verdict. A non-200 is a *webhook
  failure*, not a deny, and sustained failures trip Anthropic's circuit breaker.
- Dedupes on `webhook-id`, and answers before writing the audit record.
- Shadow mode: log what would be denied, always return allow.

## Build

```bash
make build          # go build -buildmode=plugin -o build/...so main.go
```

Build on the same OS/arch as Bifrost with the same Go version (1.26.1) —
cross-compiling plugins does not work. The plugin deliberately imports nothing
from `bifrost/core`, so you avoid the usual "built with a different version of
package" breakage on Bifrost upgrades. It still needs a matching Go toolchain.

## Configure

Copy the `plugins` block from `config.example.json` into Bifrost's `config.json`.
Start with `"shadow_mode": true` until the rules are tuned.

| Key | Meaning |
| --- | --- |
| `listen_addr` | Port the verdict server binds. Separate from Bifrost's own port. |
| `path` | Any path you like — the whole configured URL is the endpoint. |
| `signing_secrets` | `whsec_…` values. Keep the old one here for ~a minute after rotating. |
| `fail_mode` | Verdict when the body can't be read or parsed. `allow` or `deny`. |
| `max_body_bytes` | Transcripts arrive untruncated, up to 10 MB. |

Then in claude.ai: Organization settings → Data and privacy → Inference hooks →
Configure, paste your public URL, save once to reveal the signing secret, and use
**Test connection**.

## Deployment notes

- **Public certificate required.** Anthropic needs an `https://` URL on port 443,
  publicly routable, no redirects, with a cert that validates against the public CA
  trust store. An internal/private-CA cert on the ALB will fail the TLS handshake.
- **Body limits.** Raise anything in front of the plugin — nginx defaults to 1 MB;
  the ALB is fine. A rejected body counts as a webhook failure.
- **Source IPs.** Requests come from `160.79.106.0/24`. Allowlist it on the
  security group, but keep signature verification — that range carries other
  Anthropic egress too.
- **Latency.** The verdict timeout is 1–10,000 ms (5,000 default) and covers
  connect, TLS, request and response. Keep the ALB idle timeout above it so
  connections stay warm.
- **Health.** `GET /healthz` for the target group. Point the health check there,
  not at the verdict path.

## Extending

- `evaluate()` is the policy hook. Swap the regex loop for a call to your DLP
  service, a classifier, or Bedrock Guardrails — just stay inside the timeout.
- `audit()` runs after the response is written. Ship the frame to CloudWatch, S3
  or a SIEM there. Join on `reference_id`: every denial appears in the Claude
  Activity Feed as `inference_hooks_request_denied` carrying the value you returned.
- To apply the same rules to traffic going *through* the gateway, add a
  `PreLLMHook` in the same file:

```go
func PreLLMHook(ctx *schemas.BifrostContext, req *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.LLMPluginShortCircuit, error) {
    // scan req, return a short-circuit to block
    return req, nil, nil
}
```

That one does import `bifrost/core`, so the version-matching rules come back.

## Caveats

- Inference hooks are in beta. Field names and shapes may change before GA.
- Only the `prompt` event exists today — pre-inference. Response-side enforcement
  is planned but not available, so this cannot inspect Claude's output.
- Not available on the API, Bedrock or Vertex — Claude Enterprise surfaces only.
