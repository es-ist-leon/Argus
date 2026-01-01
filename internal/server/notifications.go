package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"text/template"
	"time"
)

// NotificationType represents the type of notification
type NotificationType string

const (
	NotifyAlert         NotificationType = "alert"
	NotifyAgentStatus   NotificationType = "agent_status"
	NotifyCommandResult NotificationType = "command_result"
	NotifySystemEvent   NotificationType = "system_event"
	NotifySecurityEvent NotificationType = "security_event"
)

// Notification represents a notification to be sent
type Notification struct {
	ID        string                 `json:"id"`
	Type      NotificationType       `json:"type"`
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	Severity  string                 `json:"severity"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Delivered bool                   `json:"delivered"`
}

// NotificationChannel interface for different notification channels
type NotificationChannel interface {
	Send(notification *Notification) error
	Name() string
	IsEnabled() bool
}

// NotificationManager manages notification sending
type NotificationManager struct {
	mu           sync.RWMutex
	channels     map[string]NotificationChannel
	queue        chan *Notification
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	history      []*Notification
	maxHistory   int
	workers      int
}

// NewNotificationManager creates a new notification manager
func NewNotificationManager(workers int) *NotificationManager {
	if workers <= 0 {
		workers = 3
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	return &NotificationManager{
		channels:   make(map[string]NotificationChannel),
		queue:      make(chan *Notification, 1000),
		ctx:        ctx,
		cancel:     cancel,
		history:    make([]*Notification, 0),
		maxHistory: 500,
		workers:    workers,
	}
}

// Start starts the notification manager
func (nm *NotificationManager) Start() {
	for i := 0; i < nm.workers; i++ {
		nm.wg.Add(1)
		go nm.worker(i)
	}
	log.Printf("Notification manager started with %d workers", nm.workers)
}

// Stop stops the notification manager
func (nm *NotificationManager) Stop() {
	nm.cancel()
	nm.wg.Wait()
	log.Println("Notification manager stopped")
}

func (nm *NotificationManager) worker(id int) {
	defer nm.wg.Done()
	
	for {
		select {
		case <-nm.ctx.Done():
			return
		case notification := <-nm.queue:
			nm.send(notification)
		}
	}
}

// AddChannel adds a notification channel
func (nm *NotificationManager) AddChannel(channel NotificationChannel) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.channels[channel.Name()] = channel
	log.Printf("Notification channel added: %s", channel.Name())
}

// RemoveChannel removes a notification channel
func (nm *NotificationManager) RemoveChannel(name string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	delete(nm.channels, name)
}

// Notify queues a notification for sending
func (nm *NotificationManager) Notify(notification *Notification) {
	notification.ID = generateNotificationID()
	notification.Timestamp = time.Now()
	
	select {
	case nm.queue <- notification:
	default:
		log.Printf("Notification queue full, dropping notification: %s", notification.ID)
	}
}

// NotifyAlert sends an alert notification
func (nm *NotificationManager) NotifyAlert(title, message string, severity string, data map[string]interface{}) {
	nm.Notify(&Notification{
		Type:     NotifyAlert,
		Title:    title,
		Message:  message,
		Severity: severity,
		Data:     data,
	})
}

// NotifyAgentStatus sends an agent status notification
func (nm *NotificationManager) NotifyAgentStatus(agentID, hostname, status string) {
	nm.Notify(&Notification{
		Type:    NotifyAgentStatus,
		Title:   fmt.Sprintf("Agent %s Status Change", hostname),
		Message: fmt.Sprintf("Agent %s (%s) is now %s", hostname, agentID, status),
		Data: map[string]interface{}{
			"agent_id": agentID,
			"hostname": hostname,
			"status":   status,
		},
	})
}

// NotifyCommandResult sends a command result notification
func (nm *NotificationManager) NotifyCommandResult(commandID, agentID string, success bool, output string) {
	status := "succeeded"
	severity := "info"
	if !success {
		status = "failed"
		severity = "warning"
	}
	
	nm.Notify(&Notification{
		Type:     NotifyCommandResult,
		Title:    fmt.Sprintf("Command %s", status),
		Message:  fmt.Sprintf("Command %s on agent %s %s", commandID, agentID, status),
		Severity: severity,
		Data: map[string]interface{}{
			"command_id": commandID,
			"agent_id":   agentID,
			"success":    success,
			"output":     output,
		},
	})
}

func (nm *NotificationManager) send(notification *Notification) {
	nm.mu.RLock()
	channels := make([]NotificationChannel, 0, len(nm.channels))
	for _, ch := range nm.channels {
		if ch.IsEnabled() {
			channels = append(channels, ch)
		}
	}
	nm.mu.RUnlock()
	
	for _, channel := range channels {
		if err := channel.Send(notification); err != nil {
			log.Printf("Failed to send notification via %s: %v", channel.Name(), err)
		}
	}
	
	notification.Delivered = true
	nm.addToHistory(notification)
}

func (nm *NotificationManager) addToHistory(notification *Notification) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	nm.history = append(nm.history, notification)
	if len(nm.history) > nm.maxHistory {
		nm.history = nm.history[1:]
	}
}

// GetHistory returns notification history
func (nm *NotificationManager) GetHistory(limit int) []*Notification {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	if limit <= 0 || limit > len(nm.history) {
		limit = len(nm.history)
	}
	
	result := make([]*Notification, limit)
	start := len(nm.history) - limit
	for i := 0; i < limit; i++ {
		result[i] = nm.history[start+limit-1-i]
	}
	return result
}

// =============================================================================
// Webhook Channel
// =============================================================================

// WebhookChannel sends notifications via HTTP webhook
type WebhookChannel struct {
	name       string
	url        string
	method     string
	headers    map[string]string
	timeout    time.Duration
	enabled    bool
	template   *template.Template
	httpClient *http.Client
}

// NewWebhookChannel creates a new webhook channel
func NewWebhookChannel(name, url string, headers map[string]string) *WebhookChannel {
	return &WebhookChannel{
		name:    name,
		url:     url,
		method:  "POST",
		headers: headers,
		timeout: 30 * time.Second,
		enabled: true,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (w *WebhookChannel) Name() string {
	return w.name
}

func (w *WebhookChannel) IsEnabled() bool {
	return w.enabled
}

func (w *WebhookChannel) Send(notification *Notification) error {
	payload, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to marshal notification: %w", err)
	}
	
	req, err := http.NewRequest(w.method, w.url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	for key, value := range w.headers {
		req.Header.Set(key, value)
	}
	
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	
	return nil
}

// =============================================================================
// Slack Channel
// =============================================================================

// SlackChannel sends notifications to Slack
type SlackChannel struct {
	name       string
	webhookURL string
	channel    string
	username   string
	iconEmoji  string
	enabled    bool
	httpClient *http.Client
}

// NewSlackChannel creates a new Slack channel
func NewSlackChannel(name, webhookURL, channel string) *SlackChannel {
	return &SlackChannel{
		name:       name,
		webhookURL: webhookURL,
		channel:    channel,
		username:   "Argus RMT",
		iconEmoji:  ":robot_face:",
		enabled:    true,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (s *SlackChannel) Name() string {
	return s.name
}

func (s *SlackChannel) IsEnabled() bool {
	return s.enabled
}

func (s *SlackChannel) Send(notification *Notification) error {
	color := "#36a64f" // green
	switch notification.Severity {
	case "critical":
		color = "#ff0000"
	case "warning":
		color = "#ffcc00"
	case "info":
		color = "#0000ff"
	}
	
	payload := map[string]interface{}{
		"channel":    s.channel,
		"username":   s.username,
		"icon_emoji": s.iconEmoji,
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  notification.Title,
				"text":   notification.Message,
				"footer": "Argus RMT",
				"ts":     notification.Timestamp.Unix(),
			},
		},
	}
	
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	
	resp, err := s.httpClient.Post(s.webhookURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to send to Slack: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack returned status %d", resp.StatusCode)
	}
	
	return nil
}

// =============================================================================
// Email Channel
// =============================================================================

// EmailChannel sends notifications via email
type EmailChannel struct {
	name        string
	smtpHost    string
	smtpPort    int
	username    string
	password    string
	fromAddress string
	toAddresses []string
	useTLS      bool
	enabled     bool
	template    *template.Template
}

// NewEmailChannel creates a new email channel
func NewEmailChannel(name, smtpHost string, smtpPort int, username, password, fromAddress string, toAddresses []string) *EmailChannel {
	tmpl := template.Must(template.New("email").Parse(defaultEmailTemplate))
	
	return &EmailChannel{
		name:        name,
		smtpHost:    smtpHost,
		smtpPort:    smtpPort,
		username:    username,
		password:    password,
		fromAddress: fromAddress,
		toAddresses: toAddresses,
		useTLS:      true,
		enabled:     true,
		template:    tmpl,
	}
}

func (e *EmailChannel) Name() string {
	return e.name
}

func (e *EmailChannel) IsEnabled() bool {
	return e.enabled
}

func (e *EmailChannel) Send(notification *Notification) error {
	var body bytes.Buffer
	if err := e.template.Execute(&body, notification); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	
	// Build message
	headers := make(map[string]string)
	headers["From"] = e.fromAddress
	headers["To"] = strings.Join(e.toAddresses, ", ")
	headers["Subject"] = fmt.Sprintf("[Argus] %s", notification.Title)
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"
	
	var message bytes.Buffer
	for key, value := range headers {
		message.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}
	message.WriteString("\r\n")
	message.Write(body.Bytes())
	
	// Send email
	addr := fmt.Sprintf("%s:%d", e.smtpHost, e.smtpPort)
	auth := smtp.PlainAuth("", e.username, e.password, e.smtpHost)
	
	err := smtp.SendMail(addr, auth, e.fromAddress, e.toAddresses, message.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	
	return nil
}

const defaultEmailTemplate = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: #3b82f6; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { background: #f8f9fa; padding: 20px; border-radius: 0 0 8px 8px; }
        .severity-critical { border-left: 4px solid #ff0000; }
        .severity-warning { border-left: 4px solid #ffcc00; }
        .severity-info { border-left: 4px solid #0000ff; }
        .footer { margin-top: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
        </div>
        <div class="content severity-{{.Severity}}">
            <p>{{.Message}}</p>
            <p><strong>Type:</strong> {{.Type}}</p>
            <p><strong>Time:</strong> {{.Timestamp}}</p>
        </div>
        <div class="footer">
            <p>This notification was sent by Argus Remote Management Tool</p>
        </div>
    </div>
</body>
</html>
`

// =============================================================================
// Log Channel
// =============================================================================

// LogChannel logs notifications to standard output
type LogChannel struct {
	name    string
	enabled bool
}

// NewLogChannel creates a new log channel
func NewLogChannel(name string) *LogChannel {
	return &LogChannel{
		name:    name,
		enabled: true,
	}
}

func (l *LogChannel) Name() string {
	return l.name
}

func (l *LogChannel) IsEnabled() bool {
	return l.enabled
}

func (l *LogChannel) Send(notification *Notification) error {
	log.Printf("[NOTIFICATION] [%s] [%s] %s: %s",
		notification.Type,
		notification.Severity,
		notification.Title,
		notification.Message)
	return nil
}

// Helper to generate unique notification ID
func generateNotificationID() string {
	return fmt.Sprintf("notif-%d", time.Now().UnixNano())
}
