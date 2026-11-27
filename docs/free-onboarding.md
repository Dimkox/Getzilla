# Opt-in free onboarding

Issues #308 and #277 have separate cloud and local qualification criteria. This source adds candidate admission to the existing continuation policy. It does not qualify a native adapter or launch a model. Inspect the declaration with:

```sh
getzilla status --onboarding
```

`qualification: NOT_TESTED` and `dispatch_permitted: false` are deliberate. Configuration, fixture tests and successful API responses cannot establish an accepted coding task. The [profile matrix](free-onboarding-profile-matrix.json) records the host observation and missing qualification.

## OpenRouter free-only admission

In a disposable project, explicitly add `admission` to its existing `.getzilla/config/model-continuation.json`. Keep your ordinary paid project and user settings unchanged. Do not run `setup-agent` over your paid configuration to try this scenario. The policy still needs its existing schema version, enabled flag, complete candidate list and finite bounds. The additional object has this form; names and timestamps below are synthetic, not usable provider evidence:

```json
{
  "profile": "openrouter-free",
  "observed_epoch": 1000,
  "expires_epoch": 1060,
  "models": [
    {
      "id": "vendor/example:free",
      "pricing": {"prompt": "0", "completion": "0", "request": "0"}
    }
  ]
}
```

Each candidate, including writer, reviewer, auxiliary and fallback candidates, must use provider `openrouter`, an explicit `vendor/model:free` ID and a matching catalog entry. Unqualified aliases such as `openrouter/free`, paid candidates, unknown models, duplicate/extra/missing catalog rows and unknown or nonzero rates refuse admission. Keep every additional advertised pricing component: any nonzero or malformed value refuses. Mandatory prompt/completion/request rates cannot be omitted. A free suffix alone does not establish price or compatibility.

Price observations expire in at most 300 seconds and are rechecked whenever the existing journal loads policy. They are operator-supplied facts, not authenticated price evidence. A future qualified adapter must obtain current official facts and apply this same restriction immediately before every request, including native subagents and server-side fallback routes. This passive path does not intercept someone running Qwen or another client directly. Do not present it as an enforced live free-only client until that adapter is independently qualified. Paid plugins, web tools and routing extras require their own zero-price evidence; otherwise keep them disabled.

Existing attempt/request/deadline/cost limits, terminal model-failure classification and cancellation remain in use. The existing positive cost ceiling remains a finite accounting cap; the profile additionally refuses any nonzero inference-charge reservation. It is not permission to spend that cap. Neither price nor admission failure introduces a rotation trigger. Quota/429 and unavailability preserve the work; retry consumes the existing overall budget. No credit purchase or paid fallback is added.

OpenRouter processes the request with the selected provider. Code sent to a cloud model leaves the local computer. Free inference is not zero hardware, human-time or CI cost. Quotas and availability vary; record the date, endpoint/model and actual applicable limit. Do not embed a fixed daily allowance as a product promise. Failed requests may consume quota; never exhaust live quota to test this behavior. The controlled regression fixtures cover exhaustion, bounded retries, paid escape and cancellation.

## Local Qwen Code and Ollama declaration

The first local candidate is Qwen Code plus Ollama over the OpenAI-compatible loopback endpoint. Other clients, LAN servers, models and platforms need separate qualification. No daemon, download, account or model purchase runs when reading this profile.

For this profile, every existing continuation candidate must use provider `ollama`, account reference `local` and a model in the exact declared inventory. Its additional `admission` object has these fields:

```json
{
  "profile": "ollama-local-qwen",
  "endpoint": "http://127.0.0.1:11434/v1",
  "network": "closed",
  "client": "qwen",
  "client_version": "1.0.0",
  "server_version": "1.0.0",
  "os": "linux-x64",
  "resources": {
    "memory_bytes": 1000000000,
    "disk_bytes": 1000000000,
    "max_output_bytes": 1000000
  },
  "models": [{
    "id": "local-code:q4",
    "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "tokenizer": "example-v1",
    "format": "gguf",
    "quantization": "Q4_K_M",
    "context_tokens": 8192,
    "tools": true
  }]
}
```

These values are synthetic examples. Replace them with verified versions, model digest, tokenizer/format/quantization/license and measured host limits. Keep the existing finite attempt/request/deadline bounds. Missing versions, tools capability, model identity or resource bounds refuse. Cloud or unknown candidates and non-loopback endpoints refuse. A declaration is not OS-enforced isolation or proof that a model supports tools. Status reports it as `declared_matrix`, with `network_isolation_verified: false`.

### Preview, apply and undo a local profile

Start at the root of a disposable installed project with its default disabled continuation policy. Save a complete policy as `ollama-profile.json` in that directory. Set `schema_version` to 1 and `enabled` to true. Paste the local `admission` object above using the actual inventory for your model. Add one `candidates` entry with `provider: ollama`, `account_ref: local` and the exact model ID from that inventory. Supply finite `bounds`, for example `{"max_attempts":1,"max_requests":1,"deadline_seconds":60,"max_cost_usd":1}`. Local profile setup reads these declarations offline. If you lack the model digest or version information, obtain those facts before applying a profile.

```sh
getzilla setup-agent ollama preview
getzilla setup-agent ollama apply "$TOKEN"
getzilla status --onboarding
getzilla setup-agent ollama rollback "$TOKEN"
```

Set `TOKEN` to the token printed by preview before applying or rolling back. Preview prints the project-relative policy path, exact diff and token. Apply saves the previous bytes under `.getzilla/runtime/ollama-setup/` and updates only the disposable project policy. A repeat with identical bytes is a no-op. An edited policy must be inspected before rollback. The result stays `NOT_TESTED` with `dispatch_permitted: false`; this command performs no probes, model downloads, Qwen settings changes or inference.

Before a real run, prepare the selected artifacts separately. Check their hashes and licenses. Start only the selected local server under finite CPU/RAM/VRAM/disk/time/output limits. Use a disposable Qwen profile with the local endpoint, verified context/tool settings and a local placeholder credential only when the installed client requires one. Preserve normal user settings. Disable cloud features, updates/downloads, telemetry, web tools and external reviewers/fallback. Do not rely on an environment variable or missing API key as proof. Bind client, server and descendants to monitored network isolation allowing only the declared local connection. The guard above does not install these host controls.

Predefine a small coding task, failing behavioral test and accepted result before model execution. Retain input/output snapshots, real checks, review, all attempts, denied and successful network connections, timings and resource peaks. Prove the monitoring with one intentional denied external control. Test unavailable server, unsupported tools, insufficient resources, timeout and cancellation without external fallback or leaked owned processes. Preserve partial work and user data. Report unknown costs as unknown. If no task is accepted, do not report cost per accepted task as zero.

Stage A is the real local coding workflow. Stage B separately qualifies authorized local retrieval/embedding, exact source citations and no data egress after the retrieval integration exists. Stage A does not prove Stage B. Neither stage substitutes for mandatory external CI, merge or actual DEV delivery.

## Current qualification and primary sources

On claw, 2026-11-19, the installed Qwen package metadata reports 0.24.7. No Ollama executable was found. An anonymous, proxy-disabled, two-second loopback `/api/tags` read was unavailable; it made no generation request. No model, tools, context or network-isolation qualification is claimed. Install and pin an explicitly selected local model within an approved resource/download budget before qualification. This source change neither installs it nor invents that budget.

Official documentation checked on 2026-11-19: [OpenRouter limits](https://openrouter.ai/docs/api_reference/limits), [model fallback routing](https://openrouter.ai/docs/guides/routing/model-fallbacks), [data processing](https://openrouter.ai/docs/guides/privacy/data-collection), [Ollama FAQ](https://docs.ollama.com/faq), and [Qwen model providers](https://qwenlm.github.io/qwen-code-docs/en/users/configuration/model-providers/). Refresh those facts for the exact selected versions before a run. Source references do not qualify this host or a client.
