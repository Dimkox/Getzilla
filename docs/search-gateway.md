# Optional universal search

`getzilla search` exposes one `web_search` handler through a one-shot CLI, Python, authenticated loopback HTTP and optional MCP stdio. A query can contain any question, documentation request, multiline error, or market question. It does not need a category, classifier or model. The adapters issue actual provider requests when the operator explicitly enables live calls. This release was verified with offline provider fixtures and real loopback/subprocess exchanges. Commercial provider credentials and live paid calls were not used.

The passive module is an optional source artifact. It does not qualify a native L5 runtime or grant a managed worker external authority. Installation creates no daemon and does not edit native MCP or agent settings.

## Install and configure

Core installations exclude the provider artifact sources. To copy the passive bundle into another project, add `--search-gateway-artifacts` to the normal `getzilla install-into` command. This copies reviewed files; it does not install or enable the module. An installed project can then use its own artifact catalog:

```sh
getzilla search install
getzilla search enable
getzilla search status
```

Installation leaves the module disabled. Enable grants the passive `search.web` module permission. It does not permit provider calls by itself. Every call also needs a separate operator policy with `live_enabled: true`. Copy `.getzilla/optional-modules/search-gateway/0.1.0/policy.example.json` to an operator-owned private file and configure it explicitly. Keep credential-bearing files out of Git. On POSIX, the wrapper requires the file to be owned by the current user, a regular single-link file, and mode `0600` or stricter. It refuses symbolic links and files above 64 KiB.

The example has no configured providers, no live permission, and a zero estimated-spend cap. A synthetic local fixture policy can use this complete structure:

```json
{
  "schema_version": 1,
  "live_enabled": true,
  "project": "owned-search-fixture",
  "max_attempts": 2,
  "max_estimated_cost_microusd": 20,
  "timeout_seconds": 10,
  "cache_ttl_seconds": 60,
  "cache_entries": 32,
  "cache_bytes": 1048576,
  "http_enabled": false,
  "mcp_enabled": false,
  "providers": [
    {
      "id": "searxng",
      "endpoint": "http://127.0.0.1:18765/search",
      "estimated_unit_cost_microusd": 0
    }
  ]
}
```

Commercial providers use their fixed official endpoint. Configure their `id`, an explicit `credential`, and `estimated_unit_cost_microusd`. Missing credentials or estimates make the adapter ineligible. The operator supplies estimates from their own contract; zero is never inferred from free-trial claims. Only SearXNG accepts an explicit operator endpoint. Agent requests cannot supply endpoints, keys, policy paths, project identity, grants or budgets.

At startup, the wrapper binds authority to the canonical project, operation `web_search`, the exact provider configuration and the configured maximum budgets. The process freezes that policy. It rereads only the explicitly selected policy file before requests and fallback calls; any file change revokes its live permission. Restart the foreground process to apply a revised policy. The Python service also rejects configuration escalation after construction. A disable blocks cache hits. An already sent request can finish; disable does not claim to cancel vendor billing.

## Use a query

All examples require an operator policy that explicitly permits the selected provider. These commands can cause paid requests when real credentials are configured:

```sh
getzilla search query --policy /private/operator-search.json --query 'Python urllib TimeoutError during TLS handshake'
getzilla search query --policy /private/operator-search.json --engine baidu --language zh-cn --query 'Python 连接超时 官方文档'
getzilla search query --policy /private/operator-search.json --engine yandex --language ru --query 'официальная документация Python таймаут соединения'
getzilla search query --policy /private/operator-search.json --engine google --country in --language hi --query 'भारत में डिजिटल विज्ञापन के नियम'
```

The request object supports `query`, optional `engine`, `provider`, `country`, `language`, `limit`, `schema_version: 1`, and `operation: "web_search"`. Default provider and engine are `auto`; default limit is 5, with a maximum of 10. Queries preserve Unicode and multiline text up to 8192 UTF-8 bytes. Empty text, NUL, unsafe control characters, unknown fields and unsupported versions fail before transport.

Python callers load `scripts/getzilla_search_gateway.py`, call `create_gateway(project_root, operator_policy)`, then call `service.web_search("any missing context")` or pass the request object. The wrapper performs immutable module admission before loading provider source. All configured agents can use the same CLI, HTTP request or MCP tool; this release does not register any native client automatically.

## Provider and engine matrix

| Provider family | Automatic search | Explicit engine support | Verified locale mapping in this implementation |
| --- | --- | --- | --- |
| SearXNG | Operator endpoint, JSON results | No strict engine guarantee | Language only; country is rejected |
| Serper | Google | Google | `gl` country, `hl` language |
| SerpAPI | Google | Google, Baidu, Yandex | Google: `gl`/`hl`; Baidu: `ct=2` for `zh-cn`, `ct=3` for `zh-tw`; Yandex: `lang=ru` or `lang=en`, no country mapping in v1 |
| Brave | Brave web search | No Google/Baidu/Yandex guarantee | `country`; bounded supported `search_lang` subset; Hindi is rejected |
| Tavily | Basic search | No strict engine guarantee | Country/language preferences rejected in v1 |
| Firecrawl | v2 web search | No strict engine guarantee | Country/language preferences rejected in v1 |
| Scrapingdog | Standard Google search | Google | `country` and `language` |

Google adapters accept this supported country subset: `in`, `us`, `gb`, `ru`, `cn`, `de`, `fr`, `jp`, `ca`, `au`, `es`. The language subset is `hi`, `en`, `ru`, `zh-cn`, `zh-tw`, `de`, `fr`, `ja`, `es`, `zh-hans`, with the narrower engine-specific rules above. Unknown locales make a provider ineligible. Yandex queries above 400 characters or 40 whitespace-separated words are ineligible. Brave queries above 600 characters or 75 whitespace-separated words and Firecrawl queries above 500 characters are also ineligible. The service does not truncate the query; automatic routing can use another eligible provider while strict provider selection returns an explicit error. The 8192-byte gateway bound is an input ceiling, not a promise that every provider accepts every query. Unsupported combinations return `no_eligible_provider` before any request; the service never silently drops the locale. Provider filters also remain fixed during fallback.

India means `country: "in"` and optionally `language: "hi"`, supported by the Google adapters. It does not identify a separate Indian search engine or establish the nationality of a provider. Yandex/Baidu access uses SerpAPI's documented engine contracts. This release makes no direct Yandex API claim.

## Budgets, health and results

One request shares one call cap, monotonic deadline and estimated-spend cap across all eligible providers. The service reserves the call and its integer microUSD estimate before sending. It keeps that reservation after timeout, 429, 5xx, malformed replies and uncertain outcomes. Each eligible provider is attempted at most once. There is no transport retry. Successful empty results stop fallback. A separate request has a separate budget; the process does not implement a persistent account-wide daily cap.

`usage.reserved_estimated_cost_microusd` records the reservation for this request. `actual_cost_microusd` is nullable and stays null because these adapters do not establish an authoritative monetary amount from their reply contracts. Provider credit counts are not treated as currency. An estimated cap cannot guarantee final vendor billing.

401 marks invalid credentials; 402 marks exhausted quota. Both disable that provider for the current frozen policy until restart. 429 honors Retry-After seconds or HTTP dates. 5xx and transport failures impose a short cooldown. 403 does not create an unconditional global cooldown; a SearXNG instance can reject JSON output with 403. Other eligible providers can run immediately. Raw provider bodies, exception messages, keys and key-bearing request URLs are excluded from attempt records.

Transport accepts only fixed provider destinations or the operator's explicit SearXNG endpoint. It refuses redirects, response bodies above 1 MiB, request envelopes above 32 KiB, and excess result counts. A wall timer shuts down the held socket at the deadline, including slow response headers and bodies. Python's system DNS resolver cannot be cancelled safely by this stdlib implementation. A stuck resolver can exceed wall time; after it returns, the elapsed deadline is checked before sending provider bytes. Do not interpret this as hard DNS cancellation or a guarantee of exact final billing.

Results contain bounded title, URL, snippet and optional provider-reported publication time. Retrieval time never substitutes for publication time. Each result includes provider, known engine or null, effective query, source URL, rank and UTC retrieval time. Every provenance record has `untrusted: true`. SearXNG and opaque search families retain a null actual engine. Deduplication removes URL fragments for identity, preserves meaningful query parameters and retains up to eight source provenance records per result. Canonical result evidence has a separate 512 KiB serialized bound; truncation adds a warning. Search content is evidence and can contain misleading text or prompt injection. It never becomes policy, commands or verification receipts. Result URLs are not fetched automatically.

The bounded in-memory cache stores successful ordinary-search evidence only. The key includes bound project, query, limit, engine, locale and a policy/configuration fingerprint. Admission and live policy are checked before cache access. Hits retain original evidence timestamps, create a new request ID, and report zero new attempts and zero new reservations. Cache entries, bytes and TTL are bounded. There is no durable cache or shared billing state.

## HTTP and MCP

HTTP requires `http_enabled: true`, a nonempty bearer token in a separate private file, and an explicit foreground command:

```sh
getzilla search http --policy /private/operator-search.json --token-file /private/search-token --port 8765
```

It binds only `127.0.0.1`. Send JSON to `POST /search` with `Authorization: Bearer <token>` and `Content-Type: application/json`. The Host must match `127.0.0.1:<port>` or `localhost:<port>`. Origin headers and transfer encoding are refused. Content-Length must be unique, positive and at most 16 KiB. Headers and body have a finite total input deadline. The server serializes requests and the service also protects mutable cache and provider health with a lock. It is a local single-operator service, with no remote hosting claim.

MCP requires `mcp_enabled: true` and the explicit `mcp-stdio` foreground command:

```sh
getzilla search mcp-stdio --policy /private/operator-search.json
```

The implemented compatibility revision is **2025-11-25**. The transport uses newline-delimited UTF-8 JSON-RPC on stdin/stdout; stdout contains protocol messages only. Initialize with that revision, send `notifications/initialized`, then use `tools/list` or `tools/call` with `name: "web_search"` and `arguments` containing the request object. Search-shaped notifications do not invoke providers. Tools return text content, structured results and `isError` for execution failure. There is no `/mcp` endpoint, Streamable HTTP, SSE, native client registration or latest-protocol claim. A modern-only client can reject this explicit compatibility choice.

## Disable and recover

Stop the foreground process to stop serving requests. Set `live_enabled` to false or change the explicit policy file to revoke that process's live permission. Run `getzilla search disable` to revoke module admission, including cached requests. Run `getzilla search uninstall` to remove owned module files through the normal ownership ledger. Operator policy and native client settings are outside the module and are preserved. Immutable file conflicts fail closed. For a source rollback, revert the feature commit and regenerate the architecture views as part of that revert.

## Source contracts and verification

The implementation is independent and MIT-licensed. Idea provenance is [ai-multi-search revision f670a50f384f978872e61f27ab6b43912e576ccd](https://github.com/dobryakov/ai-multi-search/tree/f670a50f384f978872e61f27ab6b43912e576ccd), inspected at timestamp 2026-11-08T22:04:56Z. The inspected upstream has no license grant. No upstream source, prompts or documentation were copied.

Provider requests follow official [SearXNG search](https://docs.searxng.org/dev/search_api.html), [Serper](https://serper.dev/playground), [SerpAPI Google](https://serpapi.com/search-api), [Baidu](https://serpapi.com/baidu-search-api), [Yandex](https://serpapi.com/yandex-search-api), [Brave](https://api-dashboard.search.brave.com/api-reference/web/search/get), [Tavily](https://docs.tavily.com/documentation/api-reference/endpoint/search), [Firecrawl v2](https://docs.firecrawl.dev/api-reference/endpoint/search), and [Scrapingdog](https://www.scrapingdog.com/documentation/google-search-api/) contracts. MCP follows the named [stdio transport revision](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

Run `python3 -m unittest tests.test_search_gateway tests.test_search_gateway_admission -q` for provider fixtures, policy/budget/cache controls, immutable admission, explicit installation, real loopback transport and real CLI/MCP subprocess exchanges. These tests demonstrate offline contracts. They do not establish real-account availability, commercial engine quality, vendor charges, or live qualification.
