package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServerHealth(t *testing.T) {
	// Create a mock server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "healthy",
				"version":     "1.0.0",
				"agent_count": 0,
				"api_version": "v1",
			})
			return
		}
		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	// Test health endpoint
	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var health map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if health["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", health["status"])
	}
}

func TestAlertManager(t *testing.T) {
	am := NewAlertManager()
	am.Start()
	defer am.Stop()

	// Test adding a rule
	rule := &AlertRule{
		ID:        "test-rule-1",
		Name:      "Test High CPU",
		Type:      AlertHighCPU,
		Severity:  SeverityWarning,
		Threshold: 90.0,
		Cooldown:  time.Second,
		Enabled:   true,
		Channels:  []AlertChannel{ChannelLog},
	}

	am.AddRule(rule)

	// Verify rule was added
	retrievedRule, exists := am.GetRule("test-rule-1")
	if !exists {
		t.Fatal("Rule was not added")
	}

	if retrievedRule.Name != rule.Name {
		t.Errorf("Expected rule name '%s', got '%s'", rule.Name, retrievedRule.Name)
	}

	// Test firing an alert
	am.Fire("test-rule-1", nil, "CPU is at 95%", map[string]any{
		"cpu_usage": 95.0,
	})

	// Check active alerts
	activeAlerts := am.GetActiveAlerts()
	if len(activeAlerts) != 1 {
		t.Errorf("Expected 1 active alert, got %d", len(activeAlerts))
	}

	// Test cooldown - firing again should not create new alert
	am.Fire("test-rule-1", nil, "CPU still high", nil)
	
	activeAlerts = am.GetActiveAlerts()
	if len(activeAlerts) != 1 {
		t.Errorf("Cooldown not working, expected 1 alert, got %d", len(activeAlerts))
	}

	// Test resolving alert
	if len(activeAlerts) > 0 {
		am.Resolve(activeAlerts[0].ID)
	}

	activeAlerts = am.GetActiveAlerts()
	if len(activeAlerts) != 0 {
		t.Errorf("Expected 0 active alerts after resolve, got %d", len(activeAlerts))
	}

	// Test deleting rule
	am.DeleteRule("test-rule-1")
	_, exists = am.GetRule("test-rule-1")
	if exists {
		t.Error("Rule should have been deleted")
	}
}

func TestNotificationManager(t *testing.T) {
	nm := NewNotificationManager(2)
	nm.Start()
	defer nm.Stop()

	// Add log channel
	logChannel := NewLogChannel("test-log")
	nm.AddChannel(logChannel)

	// Test sending notification
	nm.Notify(&Notification{
		Type:     NotifyAlert,
		Title:    "Test Alert",
		Message:  "This is a test alert",
		Severity: "info",
	})

	// Wait for notification to be processed
	time.Sleep(100 * time.Millisecond)

	// Check history
	history := nm.GetHistory(10)
	if len(history) != 1 {
		t.Errorf("Expected 1 notification in history, got %d", len(history))
	}

	if len(history) > 0 && history[0].Title != "Test Alert" {
		t.Errorf("Expected title 'Test Alert', got '%s'", history[0].Title)
	}
}

func TestWebhookChannel(t *testing.T) {
	// Create a test server to receive webhooks
	received := make(chan *Notification, 1)
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var notification Notification
		json.NewDecoder(r.Body).Decode(&notification)
		received <- &notification
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	// Create webhook channel
	webhook := NewWebhookChannel("test-webhook", testServer.URL, map[string]string{
		"X-Custom-Header": "test-value",
	})

	// Send notification
	notification := &Notification{
		Type:      NotifyAlert,
		Title:     "Webhook Test",
		Message:   "Testing webhook",
		Timestamp: time.Now(),
	}

	err := webhook.Send(notification)
	if err != nil {
		t.Fatalf("Failed to send webhook: %v", err)
	}

	// Wait for webhook to be received
	select {
	case recv := <-received:
		if recv.Title != "Webhook Test" {
			t.Errorf("Expected title 'Webhook Test', got '%s'", recv.Title)
		}
	case <-time.After(time.Second):
		t.Error("Webhook was not received")
	}
}

func TestRateLimiting(t *testing.T) {
	// Simple rate limiter test
	type RateLimiter struct {
		tokens     float64
		maxTokens  float64
		rate       float64
		lastUpdate time.Time
	}

	limiter := &RateLimiter{
		tokens:     10,
		maxTokens:  10,
		rate:       1, // 1 token per second
		lastUpdate: time.Now(),
	}

	allow := func() bool {
		now := time.Now()
		elapsed := now.Sub(limiter.lastUpdate).Seconds()
		limiter.tokens += elapsed * limiter.rate
		if limiter.tokens > limiter.maxTokens {
			limiter.tokens = limiter.maxTokens
		}
		limiter.lastUpdate = now

		if limiter.tokens >= 1 {
			limiter.tokens--
			return true
		}
		return false
	}

	// Should allow 10 requests immediately
	for i := 0; i < 10; i++ {
		if !allow() {
			t.Errorf("Request %d should have been allowed", i)
		}
	}

	// 11th request should be denied
	if allow() {
		t.Error("11th request should have been denied")
	}
}

func TestContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	select {
	case <-ctx.Done():
		if ctx.Err() != context.DeadlineExceeded {
			t.Errorf("Expected DeadlineExceeded, got %v", ctx.Err())
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Context should have timed out")
	}
}

func TestJSONParsing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		valid   bool
	}{
		{"valid object", `{"key": "value"}`, true},
		{"valid array", `[1, 2, 3]`, true},
		{"invalid json", `{invalid}`, false},
		{"empty string", ``, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result interface{}
			err := json.Unmarshal([]byte(tt.input), &result)
			isValid := err == nil

			if isValid != tt.valid {
				t.Errorf("Expected valid=%v, got valid=%v", tt.valid, isValid)
			}
		})
	}
}

func TestHTTPMethodRouting(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("GET"))
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("POST"))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tests := []struct {
		method       string
		expectedCode int
		expectedBody string
	}{
		{http.MethodGet, http.StatusOK, "GET"},
		{http.MethodPost, http.StatusCreated, "POST"},
		{http.MethodDelete, http.StatusNoContent, ""},
		{http.MethodPatch, http.StatusMethodNotAllowed, ""},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, server.URL, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, resp.StatusCode)
			}
		})
	}
}

func TestAuthHeaderParsing(t *testing.T) {
	parseBearer := func(header string) (string, bool) {
		if strings.HasPrefix(header, "Bearer ") {
			return strings.TrimPrefix(header, "Bearer "), true
		}
		return "", false
	}

	tests := []struct {
		header   string
		expected string
		valid    bool
	}{
		{"Bearer token123", "token123", true},
		{"Bearer ", "", true},
		{"Basic token123", "", false},
		{"", "", false},
		{"token123", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			token, valid := parseBearer(tt.header)
			if valid != tt.valid {
				t.Errorf("Expected valid=%v, got valid=%v", tt.valid, valid)
			}
			if token != tt.expected {
				t.Errorf("Expected token '%s', got '%s'", tt.expected, token)
			}
		})
	}
}

func BenchmarkJSONMarshal(b *testing.B) {
	data := map[string]interface{}{
		"id":        "test-id",
		"name":      "test-name",
		"timestamp": time.Now(),
		"values":    []int{1, 2, 3, 4, 5},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(data)
	}
}

func BenchmarkAlertFiring(b *testing.B) {
	am := NewAlertManager()
	am.Start()
	defer am.Stop()

	rule := &AlertRule{
		ID:        "bench-rule",
		Name:      "Benchmark Rule",
		Type:      AlertHighCPU,
		Severity:  SeverityWarning,
		Threshold: 90.0,
		Cooldown:  0, // No cooldown for benchmark
		Enabled:   true,
		Channels:  []AlertChannel{},
	}
	am.AddRule(rule)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		am.Fire("bench-rule", nil, "test", nil)
	}
}
