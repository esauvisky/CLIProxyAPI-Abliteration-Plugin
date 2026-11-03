# CLIProxyAPI Abliteration.ai Plugin

This ABI v1 plugin adds the **Abliteration.ai gateway** (`abliteration`, https://api.abliteration.ai) to CLIProxyAPI as an API-key provider. There is no OAuth: access uses a bearer key (`Authorization: Bearer <key>`) created in the Abliteration.ai web console.

- **API-key credentials**: upload a JSON credential such as `{"type":"abliteration","api_key":"..."}`. A missing or empty `api_key` is an error. There is no login, token exchange, or refresh flow.
- **Live model catalog**: `model.for_auth` calls `GET /v1/models` with the stored key and lists the model IDs that key can call. A failed call is returned as an error. There is no static fallback catalog.
- **Single protocol**: every model is sent to `POST /v1/chat/completions` in OpenAI Chat Completions format. Requests whose format is not `openai` are rejected.
- **Streaming** is passed through as server-sent events with `stream_options.include_usage` set.

Not implemented: `count_tokens` (returns HTTP 501), thinking-level suffixes such as `model(high)` (rejected with `unsupported_thinking_suffix`), the Responses and Messages endpoints, and any admin or organization endpoint. Quota reporting is not implemented because the Abliteration.ai docs do not document a balance or usage endpoint.

## Build

```bash
make test
```

Produces `build/abliteration.so`.

## Install from the management interface

Add this registry URL to `plugins.store-sources`:

```yaml
plugins:
  enabled: true
  store-sources:
    - "https://raw.githubusercontent.com/esauvisky/CLIProxyAPI-Abliteration-Plugin/main/registry.json"
```

## Configuration

```yaml
plugins:
  enabled: true
  configs:
    abliteration:
      enabled: true
      priority: 10
      base_url: "https://api.abliteration.ai"
```
