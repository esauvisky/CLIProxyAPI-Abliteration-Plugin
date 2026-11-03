package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const mgmtLoginRoutePath = "/plugins/abliteration/login"

type loginSubmission struct {
	State  string `json:"state"`
	APIKey string `json:"api_key"`
}

func handleManagementRegister() ([]byte, error) {
	return okEnvelope(pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{
				Method:      http.MethodPost,
				Path:        mgmtLoginRoutePath,
				Description: "Stores the Abliteration.ai API key for a pending login started by auth.login.start.",
			},
		},
		Resources: []pluginapi.ResourceRoute{
			{
				Path:        loginResourcePath,
				Description: "Page where the Abliteration.ai API key is entered to finish login.",
			},
		},
	})
}

func handleResponseInterceptAfter(raw []byte) ([]byte, error) {
	var req pluginapi.ResponseInterceptRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return nil, errUnmarshal
		}
	}
	observeOriginFromHeaders(req.RequestHeaders)
	return okEnvelope(pluginapi.ResponseInterceptResponse{})
}

func handleManagementHandle(raw []byte) ([]byte, error) {
	var req pluginapi.ManagementRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	observeOriginFromHeaders(req.Headers)
	cleanedPath := strings.TrimRight(strings.TrimSpace(req.Path), "/")
	if strings.HasSuffix(cleanedPath, mgmtLoginRoutePath) {
		if strings.EqualFold(req.Method, http.MethodPost) {
			return handleLoginSubmit(req.Body)
		}
		return nil, fmt.Errorf("abliteration management %s %s: unsupported method", req.Method, req.Path)
	}

	// /v0/resource/plugins/abliteration/login serves only the static UI asset.
	return okEnvelope(pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type":  []string{"text/html; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		Body: []byte(loginPageHTML),
	})
}

func handleLoginSubmit(body []byte) ([]byte, error) {
	var sub loginSubmission
	if errUnmarshal := json.Unmarshal(body, &sub); errUnmarshal != nil {
		return managementJSON(http.StatusBadRequest, map[string]string{"error": "request body must be JSON {state, api_key}: " + errUnmarshal.Error()})
	}
	state := strings.TrimSpace(sub.State)
	apiKey := strings.TrimSpace(sub.APIKey)
	login, errLogin := loadPendingLogin(state)
	if errLogin != nil {
		return managementJSON(http.StatusBadRequest, map[string]string{"error": errLogin.Error()})
	}
	if apiKey == "" {
		return managementJSON(http.StatusBadRequest, map[string]string{"error": "api_key is required"})
	}
	login.apiKey = apiKey
	pendingLogins.Store(state, login)
	return managementJSON(http.StatusOK, map[string]bool{"ok": true})
}

func managementJSON(status int, v any) ([]byte, error) {
	body, errMarshal := marshalJSONNoEscape(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return okEnvelope(pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type":  []string{"application/json; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		Body: body,
	})
}

const loginPageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Abliteration.ai login</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #1d1b18; color: #f6f4f1; font: 14px/1.5 system-ui, -apple-system, sans-serif; }
  main { box-sizing: border-box; width: min(420px, 92vw); background: #262320; border: 1px solid #3a3530; border-radius: 12px; padding: 24px; }
  h1 { font-size: 18px; margin: 0 0 8px; }
  p { margin: 0 0 16px; color: #9c958d; }
  label { display: block; color: #c9c3bb; margin: 14px 0 6px; }
  input { box-sizing: border-box; width: 100%; padding: 8px 10px; background: #151412; color: #f6f4f1; border: 1px solid #5a544d; border-radius: 8px; font: inherit; }
  button { margin-top: 18px; width: 100%; padding: 9px 12px; border: 0; border-radius: 8px; background: #8b8680; color: #151412; font: inherit; font-weight: 600; cursor: pointer; }
  button:disabled { opacity: 0.6; cursor: default; }
  #status { margin-top: 14px; min-height: 1.5em; color: #c9c3bb; word-break: break-word; }
  #status.error { color: #f1b0a6; }
  #status.ok { color: #6ee7b7; }
</style>
</head>
<body>
<main>
  <h1>Abliteration.ai API key</h1>
  <p>Paste your API key, then submit. Return to CLIProxyAPI afterwards to finish the login.</p>
  <div id="mgmtWrap" style="display:none;">
    <label for="mgmtKey">Management key</label>
    <input type="password" id="mgmtKey" autocomplete="off">
  </div>
  <label for="apiKey">API key</label>
  <input type="password" id="apiKey" autocomplete="off">
  <button id="submit" type="button">Submit</button>
  <div id="status"></div>
</main>
<script>
const LOGIN_API_URL = '/v0/management/plugins/abliteration/login';
const statusEl = document.getElementById('status');
const submitBtn = document.getElementById('submit');
const mgmtWrap = document.getElementById('mgmtWrap');
const mgmtInput = document.getElementById('mgmtKey');

function deobfuscateCPASecret(payload) {
  const prefix = 'enc::v1::';
  if (!payload || !payload.startsWith(prefix)) return payload;
  try {
    const bin = atob(payload.slice(prefix.length));
    const data = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) data[i] = bin.charCodeAt(i);
    const keyStr = 'cli-proxy-api-webui::secure-storage|' + window.location.host + '|' + navigator.userAgent;
    const keyBytes = new TextEncoder().encode(keyStr);
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) out[i] = data[i] ^ keyBytes[i % keyBytes.length];
    return new TextDecoder().decode(out);
  } catch (_) {
    return payload;
  }
}

function detectStoredManagementKey() {
  try {
    const authRaw = localStorage.getItem('cli-proxy-auth');
    if (authRaw) {
      const parsed = JSON.parse(authRaw);
      const k = parsed && parsed.state && parsed.state.managementKey;
      if (k && typeof k === 'string' && k.trim()) return k.trim();
    }
    const legacy = localStorage.getItem('managementKey');
    if (legacy) {
      const dec = deobfuscateCPASecret(legacy);
      try {
        const parsed = JSON.parse(dec);
        if (typeof parsed === 'string' && parsed.trim()) return parsed.trim();
      } catch (_) {
        if (typeof dec === 'string' && dec.trim()) return dec.trim();
      }
    }
  } catch (_) {}
  return '';
}

const initialKey = detectStoredManagementKey();
if (initialKey) {
  mgmtInput.value = initialKey;
} else {
  mgmtWrap.style.display = 'block';
}

function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = cls || '';
}

async function submitKey() {
  const state = new URLSearchParams(window.location.search).get('state') || '';
  const managementKey = (mgmtInput.value || detectStoredManagementKey()).trim();
  const apiKey = document.getElementById('apiKey').value.trim();
  submitBtn.disabled = true;
  setStatus('Submitting...');
  try {
    const resp = await fetch(LOGIN_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + managementKey, 'X-Management-Key': managementKey },
      body: JSON.stringify({ state: state, api_key: apiKey }),
      cache: 'no-store',
    });
    const text = await resp.text();
    if (resp.status === 401 || resp.status === 403) {
      mgmtWrap.style.display = 'block';
    }
    if (!resp.ok) {
      setStatus('HTTP ' + resp.status + ': ' + text, 'error');
      return;
    }
    setStatus('API key saved. Return to CLIProxyAPI to finish the login.', 'ok');
  } finally {
    submitBtn.disabled = false;
  }
}

submitBtn.addEventListener('click', submitKey);
document.getElementById('apiKey').addEventListener('keydown', function (event) {
  if (event.key === 'Enter') submitKey();
});
</script>
</body>
</html>
`
