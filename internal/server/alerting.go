package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/argus/argus/pkg/models"
)

// AlertType represents the type of alert
type AlertType string

const (
	AlertAgentOffline    AlertType = "agent_offline"
	AlertAgentOnline     AlertType = "agent_online"
	AlertHighCPU         AlertType = "high_cpu"
	AlertHighMemory      AlertType = "high_memory"
	AlertDiskFull        AlertType = "disk_full"
	AlertCommandFailed   AlertType = "command_failed"
	AlertSecurityEvent   AlertType = "security_event"
	AlertCustom          AlertType = "custom"
)

// AlertSeverity represents the severity level
type AlertSeverity string

const (
	SeverityCritical AlertSeverity = "critical"
	SeverityWarning  AlertSeverity = "warning"
	SeverityInfo     AlertSeverity = "info"
)

// AlertChannel represents a notification channel type
type AlertChannel string

const (
	ChannelWebhook AlertChannel = "webhook"
	ChannelEmail   AlertChannel = "email"
	ChannelSlack   AlertChannel = "slack"
	ChannelLog     AlertChannel = "log"
)

// AlertRule defines when an alert should be triggered
type AlertRule struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Type         AlertType         `json:"type"`
	Severity     AlertSeverity     `json:"severity"`
	Threshold    float64           `json:"threshold"`
	Duration     time.Duration     `json:"duration"`
	Labels       map[string]string `json:"labels"`
	AgentFilter  []string          `json:"agent_filter"`
	Channels     []AlertChannel    `json:"channels"`
	Cooldown     time.Duration     `json:"cooldown"`
	Enabled      bool              `json:"enabled"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// Alert represents a triggered alert
type Alert struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id"`
	RuleName    string            `json:"rule_name"`
	Type        AlertType         `json:"type"`
	Severity    AlertSeverity     `json:"severity"`
	AgentID     string            `json:"agent_id,omitempty"`
	AgentName   string            `json:"agent_name,omitempty"`
	Message     string            `json:"message"`
	Details     map[string]any    `json:"details,omitempty"`
	FiredAt     time.Time         `json:"fired_at"`
	ResolvedAt  *time.Time        `json:"resolved_at,omitempty"`
	Acknowledged bool             `json:"acknowledged"`
	AckedBy     string            `json:"acked_by,omitempty"`
	AckedAt     *time.Time        `json:"acked_at,omitempty"`
}

// ChannelConfig holds channel configuration
type ChannelConfig struct {
	Type       AlertChannel      `json:"type"`
	Name       string            `json:"name"`
	Enabled    bool              `json:"enabled"`
	Config     map[string]string `json:"config"`
}

// WebhookConfig holds webhook configuration
type WebhookConfig struct {
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	Headers      map[string]string `json:"headers"`
	Secret       string            `json:"secret,omitempty"`
	Timeout      time.Duration     `json:"timeout"`
}

// SlackConfig holds Slack configuration
type SlackConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username"`
	IconEmoji  string `json:"icon_emoji"`
}

// EmailConfig holds email configuration
type EmailConfig struct {
	SMTPHost     string   `json:"smtp_host"`
	SMTPPort     int      `json:"smtp_port"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	FromAddress  string   `json:"from_address"`
	ToAddresses  []string `json:"to_addresses"`
	UseTLS       bool     `json:"use_tls"`
}

// AlertManager manages alerting
type AlertManager struct {
	mu            sync.RWMutex
	rules         map[string]*AlertRule
	activeAlerts  map[string]*Alert
	alertHistory  []*Alert
	channels      map[string]*ChannelConfig
	lastFired     map[string]time.Time // ruleID -> last fired time
	ctx           context.Context
	cancel        context.CancelFunc
	httpClient    *http.Client
	maxHistory    int
}

// NewAlertManager creates a new alert manager
func NewAlertManager() *AlertManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &AlertManager{
		rules:        make(map[string]*AlertRule),
		activeAlerts: make(map[string]*Alert),
		alertHistory: make([]*Alert, 0),
		channels:     make(map[string]*ChannelConfig),
		lastFired:    make(map[string]time.Time),
		ctx:          ctx,
		cancel:       cancel,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		maxHistory:   1000,
	}
}

// Start starts the alert manager
func (am *AlertManager) Start() {
	log.Println("Alert manager started")
}

// Stop stops the alert manager
func (am *AlertManager) Stop() {
	am.cancel()
	log.Println("Alert manager stopped")
}

// AddRule adds an alert rule
func (am *AlertManager) AddRule(rule *AlertRule) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	am.rules[rule.ID] = rule
	log.Printf("Alert rule added: %s (%s)", rule.Name, rule.ID)
}

// UpdateRule updates an alert rule
func (am *AlertManager) UpdateRule(rule *AlertRule) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if _, exists := am.rules[rule.ID]; !exists {
		return false
	}
	
	rule.UpdatedAt = time.Now()
	am.rules[rule.ID] = rule
	return true
}

// DeleteRule deletes an alert rule
func (am *AlertManager) DeleteRule(ruleID string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if _, exists := am.rules[ruleID]; !exists {
		return false
	}
	
	delete(am.rules, ruleID)
	delete(am.lastFired, ruleID)
	return true
}

// GetRule returns an alert rule
func (am *AlertManager) GetRule(ruleID string) (*AlertRule, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	rule, ok := am.rules[ruleID]
	return rule, ok
}

// ListRules returns all alert rules
func (am *AlertManager) ListRules() []*AlertRule {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	rules := make([]*AlertRule, 0, len(am.rules))
	for _, rule := range am.rules {
		rules = append(rules, rule)
	}
	return rules
}

// ConfigureChannel configures a notification channel
func (am *AlertManager) ConfigureChannel(config *ChannelConfig) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.channels[config.Name] = config
}

// Fire triggers an alert
func (am *AlertManager) Fire(ruleID string, agent *models.Agent, message string, details map[string]any) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	rule, exists := am.rules[ruleID]
	if !exists || !rule.Enabled {
		return
	}
	
	// Check cooldown
	if lastFired, ok := am.lastFired[ruleID]; ok {
		if time.Since(lastFired) < rule.Cooldown {
			return
		}
	}
	
	// Create alert
	alertID := generateAlertID()
	alert := &Alert{
		ID:       alertID,
		RuleID:   ruleID,
		RuleName: rule.Name,
		Type:     rule.Type,
		Severity: rule.Severity,
		Message:  message,
		Details:  details,
		FiredAt:  time.Now(),
	}
	
	if agent != nil {
		alert.AgentID = agent.ID
		alert.AgentName = agent.Hostname
	}
	
	am.activeAlerts[alertID] = alert
	am.alertHistory = append(am.alertHistory, alert)
	am.lastFired[ruleID] = time.Now()
	
	// Trim history
	if len(am.alertHistory) > am.maxHistory {
		am.alertHistory = am.alertHistory[1:]
	}
	
	log.Printf("Alert fired: %s - %s", rule.Name, message)
	
	// Send notifications (async)
	go am.sendNotifications(alert, rule.Channels)
}

// Resolve resolves an active alert
func (am *AlertManager) Resolve(alertID string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	alert, exists := am.activeAlerts[alertID]
	if !exists {
		return false
	}
	
	now := time.Now()
	alert.ResolvedAt = &now
	delete(am.activeAlerts, alertID)
	
	log.Printf("Alert resolved: %s", alertID)
	return true
}

// Acknowledge acknowledges an alert
func (am *AlertManager) Acknowledge(alertID, userID string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	alert, exists := am.activeAlerts[alertID]
	if !exists {
		return false
	}
	
	now := time.Now()
	alert.Acknowledged = true
	alert.AckedBy = userID
	alert.AckedAt = &now
	
	log.Printf("Alert acknowledged: %s by %s", alertID, userID)
	return true
}

// GetActiveAlerts returns all active alerts
func (am *AlertManager) GetActiveAlerts() []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	alerts := make([]*Alert, 0, len(am.activeAlerts))
	for _, alert := range am.activeAlerts {
		alerts = append(alerts, alert)
	}
	return alerts
}

// GetAlertHistory returns alert history
func (am *AlertManager) GetAlertHistory(limit int) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	if limit <= 0 || limit > len(am.alertHistory) {
		limit = len(am.alertHistory)
	}
	
	// Return most recent first
	start := len(am.alertHistory) - limit
	result := make([]*Alert, limit)
	for i := 0; i < limit; i++ {
		result[i] = am.alertHistory[start+limit-1-i]
	}
	return result
}

// CheckAgentStatus checks agent status for alerting
func (am *AlertManager) CheckAgentStatus(agent *models.Agent, wasOnline bool) {
	if agent.Status == models.StatusOffline && wasOnline {
		// Agent went offline
		am.fireForType(AlertAgentOffline, agent, 
			fmt.Sprintf("Agent %s went offline", agent.Hostname),
			map[string]any{
				"last_seen": agent.LastSeen,
			})
	} else if agent.Status == models.StatusOnline && !wasOnline {
		// Agent came back online
		am.fireForType(AlertAgentOnline, agent,
			fmt.Sprintf("Agent %s is back online", agent.Hostname),
			nil)
	}
}

// CheckMetrics checks metrics against alert rules
func (am *AlertManager) CheckMetrics(agent *models.Agent, cpuUsage, memUsage, diskUsage float64) {
	am.mu.RLock()
	rules := make([]*AlertRule, 0)
	for _, rule := range am.rules {
		if rule.Enabled {
			rules = append(rules, rule)
		}
	}
	am.mu.RUnlock()
	
	for _, rule := range rules {
		switch rule.Type {
		case AlertHighCPU:
			if cpuUsage >= rule.Threshold {
				am.Fire(rule.ID, agent,
					fmt.Sprintf("High CPU usage: %.1f%% on %s", cpuUsage, agent.Hostname),
					map[string]any{"cpu_usage": cpuUsage})
			}
		case AlertHighMemory:
			if memUsage >= rule.Threshold {
				am.Fire(rule.ID, agent,
					fmt.Sprintf("High memory usage: %.1f%% on %s", memUsage, agent.Hostname),
					map[string]any{"memory_usage": memUsage})
			}
		case AlertDiskFull:
			if diskUsage >= rule.Threshold {
				am.Fire(rule.ID, agent,
					fmt.Sprintf("Disk usage critical: %.1f%% on %s", diskUsage, agent.Hostname),
					map[string]any{"disk_usage": diskUsage})
			}
		}
	}
}

func (am *AlertManager) fireForType(alertType AlertType, agent *models.Agent, message string, details map[string]any) {
	am.mu.RLock()
	var matchingRules []*AlertRule
	for _, rule := range am.rules {
		if rule.Type == alertType && rule.Enabled {
			matchingRules = append(matchingRules, rule)
		}
	}
	am.mu.RUnlock()
	
	for _, rule := range matchingRules {
		am.Fire(rule.ID, agent, message, details)
	}
}

func (am *AlertManager) sendNotifications(alert *Alert, channels []AlertChannel) {
	for _, channelType := range channels {
		am.mu.RLock()
		var config *ChannelConfig
		for _, c := range am.channels {
			if c.Type == channelType && c.Enabled {
				config = c
				break
			}
		}
		am.mu.RUnlock()
		
		if config == nil {
			continue
		}
		
		switch channelType {
		case ChannelWebhook:
			am.sendWebhook(alert, config)
		case ChannelSlack:
			am.sendSlack(alert, config)
		case ChannelLog:
			am.sendLog(alert)
		case ChannelEmail:
			// Email requires more complex setup
			log.Printf("Email notification would be sent for alert: %s", alert.ID)
		}
	}
}

func (am *AlertManager) sendWebhook(alert *Alert, config *ChannelConfig) {
	url := config.Config["url"]
	if url == "" {
		return
	}
	
	payload, _ := json.Marshal(alert)
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("Failed to create webhook request: %v", err)
		return
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	// Add custom headers
	for key, value := range config.Config {
		if key != "url" && key != "method" {
			req.Header.Set(key, value)
		}
	}
	
	resp, err := am.httpClient.Do(req)
	if err != nil {
		log.Printf("Failed to send webhook: %v", err)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		log.Printf("Webhook returned error status: %d", resp.StatusCode)
	}
}

func (am *AlertManager) sendSlack(alert *Alert, config *ChannelConfig) {
	webhookURL := config.Config["webhook_url"]
	if webhookURL == "" {
		return
	}
	
	color := "#36a64f" // green
	switch alert.Severity {
	case SeverityCritical:
		color = "#ff0000"
	case SeverityWarning:
		color = "#ffcc00"
	}
	
	payload := map[string]any{
		"attachments": []map[string]any{
			{
				"color":    color,
				"title":    fmt.Sprintf("[%s] %s", alert.Severity, alert.RuleName),
				"text":     alert.Message,
				"fields": []map[string]string{
					{"title": "Type", "value": string(alert.Type), "short": "true"},
					{"title": "Agent", "value": alert.AgentName, "short": "true"},
				},
				"ts": alert.FiredAt.Unix(),
			},
		},
	}
	
	data, _ := json.Marshal(payload)
	
	resp, err := am.httpClient.Post(webhookURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Failed to send Slack notification: %v", err)
		return
	}
	defer resp.Body.Close()
}

func (am *AlertManager) sendLog(alert *Alert) {
	log.Printf("[ALERT] [%s] %s: %s (Agent: %s)", 
		alert.Severity, alert.RuleName, alert.Message, alert.AgentName)
}

// Helper to generate unique alert ID
func generateAlertID() string {
	return fmt.Sprintf("alert-%d", time.Now().UnixNano())
}
