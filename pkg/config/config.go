package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// ServerConfig holds complete server configuration
type ServerConfig struct {
	Server   ServerSettings   `yaml:"server"`
	Database DatabaseSettings `yaml:"database"`
	Logging  LoggingSettings  `yaml:"logging"`
	Metrics  MetricsSettings  `yaml:"metrics"`
	RateLimit RateLimitSettings `yaml:"rate_limit"`
	CORS     CORSSettings     `yaml:"cors"`
}

type ServerSettings struct {
	ListenAddr string        `yaml:"listen_addr"`
	APIAddr    string        `yaml:"api_addr"`
	TLS        TLSSettings   `yaml:"tls"`
	Auth       AuthSettings  `yaml:"auth"`
	Session    SessionSettings `yaml:"session"`
	Agents     AgentSettings `yaml:"agents"`
	Audit      AuditSettings `yaml:"audit"`
}

type TLSSettings struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	ClientAuth bool   `yaml:"client_auth"`
}

type AuthSettings struct {
	JWTSecret      string        `yaml:"jwt_secret"`
	TokenExpiry    time.Duration `yaml:"token_expiry"`
	RefreshEnabled bool          `yaml:"refresh_enabled"`
}

type SessionSettings struct {
	Timeout           time.Duration `yaml:"timeout"`
	MaxSessionsPerUser int          `yaml:"max_sessions_per_user"`
}

type AgentSettings struct {
	MaxConnections    int           `yaml:"max_connections"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	HeartbeatTimeout  time.Duration `yaml:"heartbeat_timeout"`
}

type AuditSettings struct {
	Enabled       bool   `yaml:"enabled"`
	LogFile       string `yaml:"log_file"`
	RetentionDays int    `yaml:"retention_days"`
}

type DatabaseSettings struct {
	Type       string `yaml:"type"`
	Connection string `yaml:"connection"`
}

type LoggingSettings struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	File       string `yaml:"file"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
}

type MetricsSettings struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Path    string `yaml:"path"`
}

type RateLimitSettings struct {
	Enabled           bool    `yaml:"enabled"`
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

type CORSSettings struct {
	Enabled        bool     `yaml:"enabled"`
	AllowedOrigins []string `yaml:"allowed_origins"`
	AllowedMethods []string `yaml:"allowed_methods"`
	AllowedHeaders []string `yaml:"allowed_headers"`
}

// AgentConfig holds complete agent configuration
type AgentConfig struct {
	Agent   AgentClientSettings `yaml:"agent"`
	Native  NativeSettings      `yaml:"native"`
	Logging LoggingSettings     `yaml:"logging"`
	Resources ResourceSettings  `yaml:"resources"`
}

type AgentClientSettings struct {
	ID           string                   `yaml:"id"`
	Server       AgentServerSettings      `yaml:"server"`
	Connection   AgentConnectionSettings  `yaml:"connection"`
	Labels       map[string]string        `yaml:"labels"`
	Capabilities []string                 `yaml:"capabilities"`
	Security     AgentSecuritySettings    `yaml:"security"`
}

type AgentServerSettings struct {
	Addr string      `yaml:"addr"`
	TLS  TLSSettings `yaml:"tls"`
}

type AgentConnectionSettings struct {
	HeartbeatInterval  time.Duration `yaml:"heartbeat_interval"`
	ReconnectInterval  time.Duration `yaml:"reconnect_interval"`
	ReconnectMaxAttempts int         `yaml:"reconnect_max_attempts"`
	ConnectTimeout     time.Duration `yaml:"connect_timeout"`
}

type AgentSecuritySettings struct {
	AllowedCommands []string `yaml:"allowed_commands"`
	BlockedCommands []string `yaml:"blocked_commands"`
	FileTransfer    FileTransferSettings `yaml:"file_transfer"`
}

type FileTransferSettings struct {
	AllowedPaths []string `yaml:"allowed_paths"`
	BlockedPaths []string `yaml:"blocked_paths"`
	MaxFileSize  string   `yaml:"max_file_size"`
}

type NativeSettings struct {
	Enabled     bool   `yaml:"enabled"`
	LibraryPath string `yaml:"library_path"`
}

type ResourceSettings struct {
	MaxCPUPercent        int `yaml:"max_cpu_percent"`
	MaxMemoryMB          int `yaml:"max_memory_mb"`
	MaxConcurrentCommands int `yaml:"max_concurrent_commands"`
}

// LoadServerConfig loads server configuration from a file
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	data = []byte(os.ExpandEnv(string(data)))

	config := &ServerConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	setServerDefaults(config)

	return config, nil
}

// LoadAgentConfig loads agent configuration from a file
func LoadAgentConfig(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	data = []byte(os.ExpandEnv(string(data)))

	config := &AgentConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	setAgentDefaults(config)

	return config, nil
}

func setServerDefaults(c *ServerConfig) {
	if c.Server.ListenAddr == "" {
		c.Server.ListenAddr = ":8443"
	}
	if c.Server.APIAddr == "" {
		c.Server.APIAddr = ":8080"
	}
	if c.Server.Auth.TokenExpiry == 0 {
		c.Server.Auth.TokenExpiry = 24 * time.Hour
	}
	if c.Server.Session.Timeout == 0 {
		c.Server.Session.Timeout = 24 * time.Hour
	}
	if c.Server.Session.MaxSessionsPerUser == 0 {
		c.Server.Session.MaxSessionsPerUser = 5
	}
	if c.Server.Agents.MaxConnections == 0 {
		c.Server.Agents.MaxConnections = 10000
	}
	if c.Server.Agents.HeartbeatInterval == 0 {
		c.Server.Agents.HeartbeatInterval = 30 * time.Second
	}
	if c.Server.Agents.HeartbeatTimeout == 0 {
		c.Server.Agents.HeartbeatTimeout = 90 * time.Second
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Logging.Output == "" {
		c.Logging.Output = "stdout"
	}
	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
	if c.RateLimit.RequestsPerSecond == 0 {
		c.RateLimit.RequestsPerSecond = 100
	}
	if c.RateLimit.Burst == 0 {
		c.RateLimit.Burst = 200
	}
}

func setAgentDefaults(c *AgentConfig) {
	if c.Agent.Connection.HeartbeatInterval == 0 {
		c.Agent.Connection.HeartbeatInterval = 30 * time.Second
	}
	if c.Agent.Connection.ReconnectInterval == 0 {
		c.Agent.Connection.ReconnectInterval = 10 * time.Second
	}
	if c.Agent.Connection.ConnectTimeout == 0 {
		c.Agent.Connection.ConnectTimeout = 30 * time.Second
	}
	if len(c.Agent.Capabilities) == 0 {
		c.Agent.Capabilities = []string{
			"execute", "file_transfer", "system_info",
			"process_list", "process_kill", "service_manage",
			"shell_session",
		}
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Resources.MaxCPUPercent == 0 {
		c.Resources.MaxCPUPercent = 10
	}
	if c.Resources.MaxMemoryMB == 0 {
		c.Resources.MaxMemoryMB = 256
	}
	if c.Resources.MaxConcurrentCommands == 0 {
		c.Resources.MaxConcurrentCommands = 5
	}
}

// SaveConfig saves a configuration to a file
func SaveConfig(path string, config interface{}) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// DefaultServerConfig returns a default server configuration
func DefaultServerConfig() *ServerConfig {
	config := &ServerConfig{}
	setServerDefaults(config)
	return config
}

// DefaultAgentConfig returns a default agent configuration
func DefaultAgentConfig() *AgentConfig {
	config := &AgentConfig{}
	setAgentDefaults(config)
	return config
}
