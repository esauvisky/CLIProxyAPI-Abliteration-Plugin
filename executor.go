package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type rpcExecutorRequest struct {
	pluginapi.ExecutorRequest
	StreamID       string `json:"stream_id,omitempty"`
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type rpcExecutorHTTPRequest struct {
	pluginapi.ExecutorHTTPRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type rpcHostHTTPStreamResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers,omitempty"`
	StreamID   string      `json:"stream_id,omitempty"`
}

type rpcHostHTTPStreamReadResponse struct {
	Payload []byte `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
	Done    bool   `json:"done,omitempty"`
}

type rpcStreamEmitRequest struct {
	StreamID string `json:"stream_id"`
	Payload  []byte `json:"payload,omitempty"`
	Error    string `json:"error,omitempty"`
}

type rpcStreamCloseRequest struct {
	StreamID string `json:"stream_id"`
	Error    string `json:"error,omitempty"`
}

type preparedUpstreamCall struct {
	url     string
	headers http.Header
	payload []byte
}

func handleExecutorExecute(raw []byte) ([]byte, error) {
	var req rpcExecutorRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	resp, errExec := executeNonStream(req)
	if errExec != nil {
		return nil, errExec
	}
	return okEnvelope(resp)
}

func handleExecutorExecuteStream(raw []byte) ([]byte, error) {
	var req rpcExecutorRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	streamID := strings.TrimSpace(req.StreamID)
	if streamID == "" {
		return nil, fmt.Errorf("stream_id is required for executor.execute_stream")
	}

	upstreamStream, errStart := openUpstreamStream(req)
	if errStart != nil {
		return nil, errStart
	}

	go forwardUpstreamStream(upstreamStream.StreamID, streamID)

	return okEnvelope(map[string]any{
		"headers": http.Header{
			"Content-Type": []string{"text/event-stream; charset=utf-8"},
		},
	})
}

func handleExecutorCountTokens(_ []byte) ([]byte, error) {
	return nil, statusError{
		code:       "unsupported",
		message:    "Abliteration.ai executor does not implement count_tokens",
		httpStatus: http.StatusNotImplemented,
	}
}

func handleExecutorHTTPRequest(raw []byte) ([]byte, error) {
	var req rpcExecutorHTTPRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	apiKey, errKey := apiKeyFromStorage(req.StorageJSON)
	if errKey != nil {
		return nil, errKey
	}
	headers := cloneHTTPHeader(req.Headers)
	if headers == nil {
		headers = make(http.Header)
	}
	if headers.Get("Authorization") == "" {
		headers.Set("Authorization", "Bearer "+apiKey)
	}
	resp, errHTTP := doHostHTTP(req.HostCallbackID, req.Method, req.URL, headers, req.Body)
	if errHTTP != nil {
		return nil, errHTTP
	}
	return okEnvelope(pluginapi.ExecutorHTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
	})
}

// prepareUpstreamRequest builds the OpenAI Chat Completions request for every model.
// The only accepted client format is "openai", so no translation is performed.
func prepareUpstreamRequest(req rpcExecutorRequest, stream bool) (preparedUpstreamCall, error) {
	model := strings.TrimSpace(req.Model)
	if model == "" {
		return preparedUpstreamCall{}, fmt.Errorf("executor request has no model")
	}
	if strings.LastIndex(model, "(") >= 0 && strings.HasSuffix(model, ")") {
		return preparedUpstreamCall{}, statusError{
			code:       "unsupported_thinking_suffix",
			message:    fmt.Sprintf("thinking suffix on model %q is not supported: the Abliteration.ai executor forwards no reasoning parameter", model),
			httpStatus: http.StatusBadRequest,
		}
	}

	clientFormat := firstNonEmpty(req.Format, req.SourceFormat)
	if clientFormat == "" {
		return preparedUpstreamCall{}, fmt.Errorf("executor request has neither format nor source_format")
	}
	if clientFormat != "openai" {
		return preparedUpstreamCall{}, statusError{
			code:       "unsupported_format",
			message:    fmt.Sprintf("Abliteration.ai executor accepts only the openai format, got %q", clientFormat),
			httpStatus: http.StatusBadRequest,
		}
	}

	if len(req.Payload) == 0 {
		return preparedUpstreamCall{}, fmt.Errorf("executor request has no payload")
	}

	out, errEdit := sjson.SetBytes(bytes.Clone(req.Payload), "model", model)
	if errEdit != nil {
		return preparedUpstreamCall{}, errEdit
	}
	out, errEdit = sjson.SetBytes(out, "stream", stream)
	if errEdit != nil {
		return preparedUpstreamCall{}, errEdit
	}
	if stream {
		out, errEdit = sjson.SetBytes(out, "stream_options.include_usage", true)
	} else {
		out, errEdit = sjson.DeleteBytes(out, "stream_options")
	}
	if errEdit != nil {
		return preparedUpstreamCall{}, errEdit
	}

	apiKey, errKey := apiKeyFromStorage(req.StorageJSON)
	if errKey != nil {
		return preparedUpstreamCall{}, errKey
	}

	headers := http.Header{
		"Authorization": []string{"Bearer " + apiKey},
		"Content-Type":  []string{"application/json"},
	}
	if stream {
		headers.Set("Accept", "text/event-stream")
	} else {
		headers.Set("Accept", "application/json")
	}

	return preparedUpstreamCall{
		url:     currentConfig().BaseURL + "/v1/chat/completions",
		headers: headers,
		payload: out,
	}, nil
}

func executeNonStream(req rpcExecutorRequest) (pluginapi.ExecutorResponse, error) {
	prepared, errPrep := prepareUpstreamRequest(req, false)
	if errPrep != nil {
		return pluginapi.ExecutorResponse{}, errPrep
	}
	httpResp, errHTTP := doHostHTTP(req.HostCallbackID, http.MethodPost, prepared.url, prepared.headers, prepared.payload)
	if errHTTP != nil {
		return pluginapi.ExecutorResponse{}, errHTTP
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return pluginapi.ExecutorResponse{}, statusError{
			code:       "upstream_error",
			message:    extractUpstreamErrorMessage(httpResp.StatusCode, httpResp.Body),
			httpStatus: httpResp.StatusCode,
		}
	}
	return pluginapi.ExecutorResponse{
		Payload: bytes.Clone(httpResp.Body),
		Headers: httpResp.Headers,
	}, nil
}

func openUpstreamStream(req rpcExecutorRequest) (rpcHostHTTPStreamResponse, error) {
	prepared, errPrep := prepareUpstreamRequest(req, true)
	if errPrep != nil {
		return rpcHostHTTPStreamResponse{}, errPrep
	}
	payload := map[string]any{
		"host_callback_id": req.HostCallbackID,
		"method":           http.MethodPost,
		"url":              prepared.url,
		"headers":          prepared.headers,
		"body":             prepared.payload,
	}
	raw, errCall := callHost(pluginabi.MethodHostHTTPDoStream, payload)
	if errCall != nil {
		return rpcHostHTTPStreamResponse{}, errCall
	}
	var streamResp rpcHostHTTPStreamResponse
	if errUnmarshal := json.Unmarshal(raw, &streamResp); errUnmarshal != nil {
		return rpcHostHTTPStreamResponse{}, errUnmarshal
	}
	if streamResp.StatusCode < 200 || streamResp.StatusCode >= 300 {
		errBody, errRead := readAndCloseErrorStream(streamResp.StreamID)
		if errRead != nil {
			return rpcHostHTTPStreamResponse{}, fmt.Errorf("Abliteration.ai upstream HTTP %d and error body unreadable: %w", streamResp.StatusCode, errRead)
		}
		return rpcHostHTTPStreamResponse{}, statusError{
			code:       "upstream_error",
			message:    extractUpstreamErrorMessage(streamResp.StatusCode, errBody),
			httpStatus: streamResp.StatusCode,
		}
	}
	if strings.TrimSpace(streamResp.StreamID) == "" {
		return rpcHostHTTPStreamResponse{}, fmt.Errorf("upstream stream opened with empty stream_id")
	}
	return streamResp, nil
}

// forwardUpstreamStream relays the upstream SSE body to the host one complete line at a time.
func forwardUpstreamStream(httpStreamID, pluginStreamID string) {
	defer closeHostHTTPStream(httpStreamID)

	var pending []byte
	emitChunk := func(chunk []byte) error {
		_, errEmit := callHost(pluginabi.MethodHostStreamEmit, rpcStreamEmitRequest{
			StreamID: pluginStreamID,
			Payload:  chunk,
		})
		return errEmit
	}

	var streamErr string
	for {
		rawRead, errCall := callHost(pluginabi.MethodHostHTTPStreamRead, map[string]any{
			"stream_id": httpStreamID,
		})
		if errCall != nil {
			streamErr = errCall.Error()
			break
		}
		var readResp rpcHostHTTPStreamReadResponse
		if errUnmarshal := json.Unmarshal(rawRead, &readResp); errUnmarshal != nil {
			streamErr = errUnmarshal.Error()
			break
		}
		pending = append(pending, readResp.Payload...)
		for {
			idx := bytes.IndexByte(pending, '\n')
			if idx < 0 {
				break
			}
			line := append([]byte(nil), pending[:idx+1]...)
			pending = pending[idx+1:]
			if errEmit := emitChunk(line); errEmit != nil {
				streamErr = errEmit.Error()
				break
			}
		}
		if streamErr != "" {
			break
		}
		if readResp.Error != "" {
			streamErr = readResp.Error
			break
		}
		if readResp.Done {
			break
		}
	}

	if streamErr == "" && len(pending) > 0 {
		if errEmit := emitChunk(pending); errEmit != nil {
			streamErr = errEmit.Error()
		}
	}

	_, _ = callHost(pluginabi.MethodHostStreamClose, rpcStreamCloseRequest{
		StreamID: pluginStreamID,
		Error:    streamErr,
	})
}

func readAndCloseErrorStream(httpStreamID string) ([]byte, error) {
	if strings.TrimSpace(httpStreamID) == "" {
		return nil, fmt.Errorf("upstream error stream has empty stream_id")
	}
	defer closeHostHTTPStream(httpStreamID)
	var out []byte
	for i := 0; i < 8; i++ {
		raw, errCall := callHost(pluginabi.MethodHostHTTPStreamRead, map[string]any{
			"stream_id": httpStreamID,
		})
		if errCall != nil {
			return nil, errCall
		}
		var resp rpcHostHTTPStreamReadResponse
		if errUnmarshal := json.Unmarshal(raw, &resp); errUnmarshal != nil {
			return nil, errUnmarshal
		}
		if resp.Error != "" {
			return nil, fmt.Errorf("read upstream error stream: %s", resp.Error)
		}
		out = append(out, resp.Payload...)
		if resp.Done || len(out) > 16384 {
			break
		}
	}
	return out, nil
}

func closeHostHTTPStream(httpStreamID string) {
	if strings.TrimSpace(httpStreamID) == "" {
		return
	}
	_, _ = callHost(pluginabi.MethodHostHTTPStreamClose, map[string]any{
		"stream_id": httpStreamID,
	})
}

func extractUpstreamErrorMessage(status int, body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if msg := gjson.GetBytes(body, "error.message").String(); strings.TrimSpace(msg) != "" {
		return strings.TrimSpace(msg)
	}
	if msg := gjson.GetBytes(body, "message").String(); strings.TrimSpace(msg) != "" {
		return strings.TrimSpace(msg)
	}
	if trimmed != "" {
		return trimmed
	}
	return fmt.Sprintf("Abliteration.ai upstream returned HTTP %d", status)
}

func cloneHTTPHeader(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for k, vals := range h {
		out[k] = append([]string(nil), vals...)
	}
	return out
}
