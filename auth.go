package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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
