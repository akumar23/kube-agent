package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// DefaultModel is qwen2.5:32b — best open-source tool-calling reliability at 32B size.
	DefaultModel  = "qwen2.5:32b"
	FallbackModel = "llama3.3:70b"

	defaultTimeout = 180 * time.Second
	MaxRounds      = 10
)

// Message is a single chat turn.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

// ToolCall is a function invocation requested by the model.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

// FunctionCall holds the function name and JSON-encoded arguments.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Tool is the schema sent to the model describing an available function.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction holds the tool name, description, and parameter schema.
type ToolFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// ChatRequest is the payload sent to /v1/chat/completions.
type ChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Tools    []Tool    `json:"tools,omitempty"`
	Stream   bool      `json:"stream"`
}

// ChatResponse is the response from /v1/chat/completions.
type ChatResponse struct {
	Choices []Choice `json:"choices"`
}

// Choice is a single candidate response.
type Choice struct {
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// Client wraps the Ollama OpenAI-compatible REST API.
type Client struct {
	BaseURL    string
	Model      string
	httpClient *http.Client
}

// NewClient creates a Client pointed at baseURL using the given model.
// Pass an empty model to use DefaultModel.
func NewClient(baseURL, model string) *Client {
	if model == "" {
		model = DefaultModel
	}
	return &Client{
		BaseURL:    baseURL,
		Model:      model,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
}

// Chat sends messages (with optional tool definitions) and returns the model's choice.
func (c *Client) Chat(ctx context.Context, messages []Message, tools []Tool) (*Choice, error) {
	req := ChatRequest{
		Model:    c.Model,
		Messages: messages,
		Tools:    tools,
		Stream:   false,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errBody) //nolint:errcheck
		return nil, fmt.Errorf("ollama API error %d: %v", resp.StatusCode, errBody)
	}

	var chatResp ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("empty choices in response")
	}

	return &chatResp.Choices[0], nil
}
