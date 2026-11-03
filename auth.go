package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type storedCredential struct {
	APIKey string `json:"api_key,omitempty"`
}

func handleAuthParse(raw []byte) ([]byte, error) {
	var req pluginapi.AuthParseRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	cred, okParse := parseStoredCredential(req.RawJSON)
	if !okParse {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	authData, errBuild := buildAuthDataFromCredential(cred, req.FileName)
	if errBuild != nil {
		return nil, errBuild
	}
	return okEnvelope(pluginapi.AuthParseResponse{
		Handled: true,
		Auth:    authData,
	})
}

// parseStoredCredential reports whether the payload is an Abliteration.ai credential.
// Validation of the api_key itself happens in credentialAPIKey.
func parseStoredCredential(rawJSON []byte) (storedCredential, bool) {
	trimmed := bytes.TrimSpace(rawJSON)
	if len(trimmed) == 0 {
		return storedCredential{}, false
	}
	var raw map[string]any
	if errUnmarshal := json.Unmarshal(trimmed, &raw); errUnmarshal != nil || raw == nil {
		return storedCredential{}, false
	}
	if strings.ToLower(stringFromMap(raw, "type")) != providerID {
		return storedCredential{}, false
	}
	return storedCredential{
		APIKey: stringFromMap(raw, "api_key"),
	}, true
}

func credentialAPIKey(cred storedCredential) (string, error) {
	if cred.APIKey == "" {
		return "", statusError{
			code:       "invalid_credential",
			message:    "Abliteration.ai credential requires a non-empty api_key",
			httpStatus: http.StatusUnauthorized,
		}
	}
	return cred.APIKey, nil
}

func apiKeyFromStorage(storageJSON []byte) (string, error) {
	cred, okParse := parseStoredCredential(storageJSON)
	if !okParse {
		return "", statusError{
			code:       "unauthorized",
			message:    "auth storage is not an Abliteration.ai credential",
			httpStatus: http.StatusUnauthorized,
		}
	}
	return credentialAPIKey(cred)
}

func buildAuthDataFromCredential(cred storedCredential, fileName string) (pluginapi.AuthData, error) {
	key, errKey := credentialAPIKey(cred)
	if errKey != nil {
		return pluginapi.AuthData{}, errKey
	}
	sum := sha256.Sum256([]byte(key))
	fingerprint := hex.EncodeToString(sum[:])[:12]
	if strings.TrimSpace(fileName) == "" {
		fileName = fmt.Sprintf("abliteration-%s.json", fingerprint)
	}
	id := strings.TrimSpace(fileName)

	storageBytes, errStorage := marshalJSONNoEscape(map[string]any{
		"type":    providerID,
		"api_key": key,
	})
	if errStorage != nil {
		return pluginapi.AuthData{}, errStorage
	}

	return pluginapi.AuthData{
		Provider:    providerID,
		ID:          id,
		FileName:    fileName,
		Label:       "Abliteration.ai",
		StorageJSON: storageBytes,
		Metadata: map[string]any{
			"type":            providerID,
			"key_fingerprint": fingerprint,
		},
		Attributes: map[string]string{
			"api_key":  key,
			"base_url": currentConfig().BaseURL,
		},
	}, nil
}

const (
	loginStateTTL     = 15 * time.Minute
	loginResourcePath = "/v0/resource/plugins/abliteration/login"
)

var (
	pendingLogins        sync.Map
	observedPublicOrigin atomic.Value
)

type pendingLogin struct {
	expiresAt time.Time
	apiKey    string
}

type rpcAuthLoginStartRequest struct {
	pluginapi.AuthLoginStartRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type rpcAuthLoginPollRequest struct {
	pluginapi.AuthLoginPollRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if idx := strings.IndexByte(h, ':'); idx != -1 {
		h = h[:idx]
	}
	return h == "" || h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func observeOriginFromHeaders(headers http.Header) {
	if len(headers) == 0 {
		return
	}
	xfHost := strings.TrimSpace(strings.Split(headers.Get("X-Forwarded-Host"), ",")[0])
	if xfHost != "" && !isLoopbackHost(xfHost) {
		scheme := strings.TrimSpace(strings.Split(headers.Get("X-Forwarded-Proto"), ",")[0])
		if scheme == "" {
			scheme = "https"
		}
		observedPublicOrigin.Store(scheme + "://" + xfHost)
		return
	}
	for _, hdr := range []string{"Origin", "Referer"} {
		if raw := strings.TrimSpace(headers.Get(hdr)); raw != "" {
			if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" && !isLoopbackHost(u.Host) {
				observedPublicOrigin.Store(u.Scheme + "://" + u.Host)
				return
			}
		}
	}
}

func detectOriginFromLogFiles() string {
	for _, dir := range []string{"/CLIProxyAPI/logs", "logs"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		var newestPath string
		var newestMod time.Time
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".log") {
				continue
			}
			info, errInfo := entry.Info()
			if errInfo != nil {
				continue
			}
			if newestPath == "" || info.ModTime().After(newestMod) {
				newestMod = info.ModTime()
				newestPath = filepath.Join(dir, entry.Name())
			}
		}
		if newestPath == "" {
			continue
		}
		f, errOpen := os.Open(newestPath)
		if errOpen != nil {
			continue
		}
		buf := make([]byte, 8192)
		n, _ := f.Read(buf)
		_ = f.Close()
		if n <= 0 {
			continue
		}
		var xfHost, xfProto string
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "x-forwarded-host:") {
				xfHost = strings.TrimSpace(strings.Split(line[len("x-forwarded-host:"):], ",")[0])
			} else if strings.HasPrefix(strings.ToLower(line), "x-forwarded-proto:") {
				xfProto = strings.TrimSpace(strings.Split(line[len("x-forwarded-proto:"):], ",")[0])
			}
		}
		if xfHost != "" && !isLoopbackHost(xfHost) {
			if xfProto == "" {
				xfProto = "https"
			}
			origin := xfProto + "://" + xfHost
			observedPublicOrigin.Store(origin)
			return origin
		}
	}
	return ""
}

func resolveLoginOrigin(fallbackBaseURL string) (*url.URL, error) {
	if pub := strings.TrimSpace(currentConfig().PublicURL); pub != "" {
		if u, err := url.Parse(pub); err == nil && u.Scheme != "" && u.Host != "" {
			return u, nil
		}
	}
	if obs, ok := observedPublicOrigin.Load().(string); ok && obs != "" {
		if u, err := url.Parse(obs); err == nil && u.Scheme != "" && u.Host != "" {
			return u, nil
		}
	}
	if fromLogs := detectOriginFromLogFiles(); fromLogs != "" {
		if u, err := url.Parse(fromLogs); err == nil && u.Scheme != "" && u.Host != "" {
			return u, nil
		}
	}
	base, errBase := url.Parse(strings.TrimSpace(fallbackBaseURL))
	if errBase != nil {
		return nil, fmt.Errorf("parse auth.login.start base URL %q: %w", fallbackBaseURL, errBase)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("auth.login.start requires an absolute base URL from the host, got %q", fallbackBaseURL)
	}
	return base, nil
}

func handleAuthLoginStart(raw []byte) ([]byte, error) {
	var req rpcAuthLoginStartRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	base, errBase := resolveLoginOrigin(req.BaseURL)
	if errBase != nil {
		return nil, errBase
	}
	stateBytes := make([]byte, 32)
	if _, errRand := rand.Read(stateBytes); errRand != nil {
		return nil, fmt.Errorf("generate login state: %w", errRand)
	}
	state := hex.EncodeToString(stateBytes)
	expiresAt := time.Now().UTC().Add(loginStateTTL)
	pendingLogins.Store(state, pendingLogin{expiresAt: expiresAt})

	loginURL := url.URL{
		Scheme:   base.Scheme,
		Host:     base.Host,
		Path:     loginResourcePath,
		RawQuery: url.Values{"state": {state}}.Encode(),
	}
	return okEnvelope(pluginapi.AuthLoginStartResponse{
		Provider:  providerID,
		URL:       loginURL.String(),
		State:     state,
		ExpiresAt: expiresAt,
	})
}

func loadPendingLogin(state string) (pendingLogin, error) {
	loaded, ok := pendingLogins.Load(state)
	if !ok {
		return pendingLogin{}, fmt.Errorf("unknown Abliteration.ai login state")
	}
	login := loaded.(pendingLogin)
	if time.Now().UTC().After(login.expiresAt) {
		pendingLogins.Delete(state)
		return pendingLogin{}, fmt.Errorf("Abliteration.ai login state expired")
	}
	return login, nil
}

func handleAuthLoginPoll(raw []byte) ([]byte, error) {
	var req rpcAuthLoginPollRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	state := strings.TrimSpace(req.State)
	login, errLogin := loadPendingLogin(state)
	if errLogin != nil {
		return nil, errLogin
	}
	if login.apiKey == "" {
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "Waiting for the API key to be entered on the login page",
		})
	}
	authData, errBuild := buildAuthDataFromCredential(storedCredential{APIKey: login.apiKey}, "")
	if errBuild != nil {
		return nil, errBuild
	}
	pendingLogins.Delete(state)
	return okEnvelope(pluginapi.AuthLoginPollResponse{
		Status:  pluginapi.AuthLoginStatusSuccess,
		Message: "Abliteration.ai login complete",
		Auth:    authData,
	})
}

func doHostHTTP(hostCallbackID, method, targetURL string, headers http.Header, body []byte) (pluginapi.HTTPResponse, error) {
	payload := map[string]any{
		"host_callback_id": hostCallbackID,
		"method":           method,
		"url":              targetURL,
		"headers":          headers,
		"body":             body,
	}
	raw, errCall := callHost(pluginabi.MethodHostHTTPDo, payload)
	if errCall != nil {
		return pluginapi.HTTPResponse{}, errCall
	}
	var resp pluginapi.HTTPResponse
	if errUnmarshal := json.Unmarshal(raw, &resp); errUnmarshal != nil {
		return pluginapi.HTTPResponse{}, errUnmarshal
	}
	return resp, nil
}

func stringFromMap(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, okStr := v.(string); okStr && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}
