package models

import (
	"time"
)

// Agent represents a remote managed endpoint
type Agent struct {
	ID          string            `json:"id"`
	Hostname    string            `json:"hostname"`
	IPAddress   string            `json:"ip_address"`
	OS          string            `json:"os"`
	Arch        string            `json:"arch"`
	Version     string            `json:"version"`
	Status      AgentStatus       `json:"status"`
	Labels      map[string]string `json:"labels"`
	LastSeen    time.Time         `json:"last_seen"`
	RegisteredAt time.Time        `json:"registered_at"`
	Capabilities []string         `json:"capabilities"`
}

type AgentStatus string

const (
	StatusOnline      AgentStatus = "online"
	StatusOffline     AgentStatus = "offline"
	StatusMaintenance AgentStatus = "maintenance"
	StatusError       AgentStatus = "error"
)

// Command represents a task to be executed on agents
type Command struct {
	ID          string            `json:"id"`
	Type        CommandType       `json:"type"`
	Payload     map[string]any    `json:"payload"`
	TargetAgent string            `json:"target_agent"`
	TargetGroup string            `json:"target_group"`
	Priority    int               `json:"priority"`
	Timeout     time.Duration     `json:"timeout"`
	CreatedAt   time.Time         `json:"created_at"`
	CreatedBy   string            `json:"created_by"`
}

type CommandType string

const (
	CmdExecute       CommandType = "execute"
	CmdFileTransfer  CommandType = "file_transfer"
	CmdSystemInfo    CommandType = "system_info"
	CmdProcessList   CommandType = "process_list"
	CmdProcessKill   CommandType = "process_kill"
	CmdServiceManage CommandType = "service_manage"
	CmdRegistryRead  CommandType = "registry_read"
	CmdRegistryWrite CommandType = "registry_write"
	CmdNetworkInfo   CommandType = "network_info"
	CmdShellSession  CommandType = "shell_session"
	CmdUpdate        CommandType = "update"
	CmdRestart       CommandType = "restart"
	CmdShutdown      CommandType = "shutdown"
)

// CommandResult represents the result of an executed command
type CommandResult struct {
	CommandID   string        `json:"command_id"`
	AgentID     string        `json:"agent_id"`
	Success     bool          `json:"success"`
	ExitCode    int           `json:"exit_code"`
	Output      string        `json:"output"`
	Error       string        `json:"error,omitempty"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Duration    time.Duration `json:"duration"`
}

// SystemInfo represents detailed system information
type SystemInfo struct {
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	OSVersion    string     `json:"os_version"`
	Arch         string     `json:"arch"`
	CPUModel     string     `json:"cpu_model"`
	CPUCores     int        `json:"cpu_cores"`
	CPUUsage     float64    `json:"cpu_usage"`
	MemoryTotal  uint64     `json:"memory_total"`
	MemoryUsed   uint64     `json:"memory_used"`
	MemoryFree   uint64     `json:"memory_free"`
	DiskInfo     []DiskInfo `json:"disk_info"`
	NetworkInfo  []NetInfo  `json:"network_info"`
	Uptime       int64      `json:"uptime"`
	BootTime     time.Time  `json:"boot_time"`
}

type DiskInfo struct {
	Device     string  `json:"device"`
	MountPoint string  `json:"mount_point"`
	FSType     string  `json:"fs_type"`
	Total      uint64  `json:"total"`
	Used       uint64  `json:"used"`
	Free       uint64  `json:"free"`
	UsedPct    float64 `json:"used_pct"`
}

type NetInfo struct {
	Name       string   `json:"name"`
	MAC        string   `json:"mac"`
	IPs        []string `json:"ips"`
	BytesSent  uint64   `json:"bytes_sent"`
	BytesRecv  uint64   `json:"bytes_recv"`
}

// ProcessInfo represents a running process
type ProcessInfo struct {
	PID        int32     `json:"pid"`
	PPID       int32     `json:"ppid"`
	Name       string    `json:"name"`
	Exe        string    `json:"exe"`
	Cmdline    string    `json:"cmdline"`
	User       string    `json:"user"`
	Status     string    `json:"status"`
	CPUPercent float64   `json:"cpu_percent"`
	MemPercent float32   `json:"mem_percent"`
	MemRSS     uint64    `json:"mem_rss"`
	CreateTime time.Time `json:"create_time"`
}

// User represents an admin user
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         UserRole  `json:"role"`
	Permissions  []string  `json:"permissions"`
	APIKey       string    `json:"-"`
	MFAEnabled   bool      `json:"mfa_enabled"`
	MFASecret    string    `json:"-"`
	LastLogin    time.Time `json:"last_login"`
	CreatedAt    time.Time `json:"created_at"`
	Active       bool      `json:"active"`
}

type UserRole string

const (
	RoleAdmin    UserRole = "admin"
	RoleOperator UserRole = "operator"
	RoleViewer   UserRole = "viewer"
	RoleAuditor  UserRole = "auditor"
)

// AuditLog represents an audit trail entry
type AuditLog struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	UserID    string         `json:"user_id"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Details   map[string]any `json:"details"`
	IPAddress string         `json:"ip_address"`
	UserAgent string         `json:"user_agent"`
	Success   bool           `json:"success"`
}

// AgentGroup represents a logical grouping of agents
type AgentGroup struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Selector    map[string]string `json:"selector"`
	Policies    []Policy          `json:"policies"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// Policy defines rules for agent behavior
type Policy struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Type        PolicyType     `json:"type"`
	Rules       map[string]any `json:"rules"`
	Priority    int            `json:"priority"`
	Enabled     bool           `json:"enabled"`
}

type PolicyType string

const (
	PolicySecurity   PolicyType = "security"
	PolicyCompliance PolicyType = "compliance"
	PolicyResource   PolicyType = "resource"
	PolicySchedule   PolicyType = "schedule"
)
