package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type rpcAuthModelRequest struct {
	pluginapi.AuthModelRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

func handleModelForAuth(raw []byte) ([]byte, error) {
	var req rpcAuthModelRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	apiKey, errKey := apiKeyFromStorage(req.StorageJSON)
	if errKey != nil {
		return nil, errKey
	}
	ids, errIDs := fetchCatalogModelIDs(req.HostCallbackID, apiKey)
	if errIDs != nil {
		return nil, errIDs
	}
	created := time.Now().Unix()
	models := make([]pluginapi.ModelInfo, 0, len(ids))
	for _, id := range ids {
		models = append(models, modelInfoFor(id, created))
	}
	return okEnvelope(pluginapi.ModelResponse{
		Provider: providerID,
		Models:   models,
	})
}

func fetchCatalogModelIDs(hostCallbackID, apiKey string) ([]string, error) {
	cfg := currentConfig()
	resp, errHTTP := doHostHTTP(hostCallbackID, http.MethodGet, cfg.BaseURL+"/v1/models", http.Header{
		"Authorization": []string{"Bearer " + apiKey},
		"Accept":        []string{"application/json"},
	}, nil)
	if errHTTP != nil {
		return nil, fmt.Errorf("request Abliteration.ai model list: %w", errHTTP)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusError{
			code:       "catalog_error",
			message:    fmt.Sprintf("Abliteration.ai model list HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(resp.Body))),
			httpStatus: resp.StatusCode,
		}
	}
	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if errUnmarshal := json.Unmarshal(resp.Body, &parsed); errUnmarshal != nil {
		return nil, fmt.Errorf("decode Abliteration.ai model list: %w", errUnmarshal)
	}
	ids := make([]string, 0, len(parsed.Data))
	for _, item := range parsed.Data {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			return nil, fmt.Errorf("Abliteration.ai model list contains an entry without id")
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func modelInfoFor(id string, created int64) pluginapi.ModelInfo {
	return pluginapi.ModelInfo{
		ID:          id,
		Object:      "model",
		Created:     created,
		OwnedBy:     providerID,
		DisplayName: id,
		Name:        id,
		Version:     id,
		UserDefined: true,
	}
}
