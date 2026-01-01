package api

import "time"

// ==================== Authentication ====================

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" validate:"required,min=3,max=64"`
	Password string `json:"password" validate:"required,min=8"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         UserInfo  `json:"user"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// UserInfo represents basic user information
type UserInfo struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// ==================== User Management ====================

// CreateUserRequest represents a user creation request
type CreateUserRequest struct {
	Username string `json:"username" validate:"required,min=3,max=64,alphanum"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Role     string `json:"role" validate:"required,oneof=admin operator viewer auditor"`
}

// UpdateUserRequest represents a user update request
type UpdateUserRequest struct {
	Email    string `json:"email,omitempty" validate:"omitempty,email"`
	Password string `json:"password,omitempty" validate:"omitempty,min=8"`
	Role     string `json:"role,omitempty" validate:"omitempty,oneof=admin operator viewer auditor"`
	Active   *bool  `json:"active,omitempty"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

// ==================== Agents ====================

// AgentResponse represents agent information
type AgentResponse struct {
	ID           string            `json:"id"`
	Hostname     string            `json:"hostname"`
	IPAddress    string            `json:"ip_address"`
	OS           string            `json:"os"`
	Arch         string            `json:"arch"`
	Version      string            `json:"version"`
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Capabilities []string          `json:"capabilities"`
	LastSeen     time.Time         `json:"last_seen"`
	RegisteredAt time.Time         `json:"registered_at"`
}

// AgentListResponse represents a list of agents
type AgentListResponse struct {
	Agents     []AgentResponse `json:"agents"`
	TotalCount int             `json:"total_count"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
}

// AgentFilterRequest represents agent filtering options
type AgentFilterRequest struct {
	Status    string            `json:"status,omitempty"`
	OS        string            `json:"os,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Search    string            `json:"search,omitempty"`
	Page      int               `json:"page,omitempty"`
	PageSize  int               `json:"page_size,omitempty"`
	SortBy    string            `json:"sort_by,omitempty"`
	SortOrder string            `json:"sort_order,omitempty"`
}

// ==================== Commands ====================

// CommandRequest represents a command execution request
type CommandRequest struct {
	Type    string         `json:"type" validate:"required"`
	Payload map[string]any `json:"payload"`
	Timeout int            `json:"timeout" validate:"min=1,max=86400"`
}

// CommandResponse represents a command response
type CommandResponse struct {
	CommandID string `json:"command_id"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
}

// CommandResultResponse represents a command result
type CommandResultResponse struct {
	CommandID   string        `json:"command_id"`
	AgentID     string        `json:"agent_id"`
	Type        string        `json:"type"`
	Status      string        `json:"status"`
	Success     bool          `json:"success"`
	ExitCode    int           `json:"exit_code"`
	Output      string        `json:"output"`
	Error       string        `json:"error,omitempty"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Duration    time.Duration `json:"duration"`
}

// BatchCommandRequest represents a batch command request
type BatchCommandRequest struct {
	AgentIDs []string       `json:"agent_ids" validate:"required,min=1"`
	Type     string         `json:"type" validate:"required"`
	Payload  map[string]any `json:"payload"`
	Timeout  int            `json:"timeout" validate:"min=1,max=86400"`
}

// BatchCommandResponse represents a batch command response
type BatchCommandResponse struct {
	Commands   []CommandResponse `json:"commands"`
	TotalCount int               `json:"total_count"`
	Errors     []string          `json:"errors,omitempty"`
}

// ==================== Agent Groups ====================

// CreateGroupRequest represents a group creation request
type CreateGroupRequest struct {
	Name        string            `json:"name" validate:"required,min=1,max=128"`
	Description string            `json:"description,omitempty" validate:"max=512"`
	Selector    map[string]string `json:"selector" validate:"required"`
}

// UpdateGroupRequest represents a group update request
type UpdateGroupRequest struct {
	Name        string            `json:"name,omitempty" validate:"omitempty,min=1,max=128"`
	Description string            `json:"description,omitempty" validate:"max=512"`
	Selector    map[string]string `json:"selector,omitempty"`
}

// GroupResponse represents group information
type GroupResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Selector    map[string]string `json:"selector"`
	AgentCount  int               `json:"agent_count"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ==================== Scheduled Tasks ====================

// CreateTaskRequest represents a task creation request
type CreateTaskRequest struct {
	Name        string         `json:"name" validate:"required,min=1,max=128"`
	Description string         `json:"description,omitempty" validate:"max=512"`
	Schedule    ScheduleConfig `json:"schedule" validate:"required"`
	Command     CommandRequest `json:"command" validate:"required"`
	TargetAgent string         `json:"target_agent,omitempty"`
	TargetGroup string         `json:"target_group,omitempty"`
	Enabled     bool           `json:"enabled"`
}

// ScheduleConfig represents task scheduling configuration
type ScheduleConfig struct {
	Type     string   `json:"type" validate:"required,oneof=once interval daily weekly cron"`
	Interval string   `json:"interval,omitempty"`
	Cron     string   `json:"cron,omitempty"`
	Once     string   `json:"once,omitempty"`
	Times    []string `json:"times,omitempty"`
	Days     []int    `json:"days,omitempty"`
}

// TaskResponse represents task information
type TaskResponse struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Schedule    ScheduleConfig `json:"schedule"`
	Command     CommandRequest `json:"command"`
	TargetAgent string         `json:"target_agent,omitempty"`
	TargetGroup string         `json:"target_group,omitempty"`
	Enabled     bool           `json:"enabled"`
	LastRun     time.Time      `json:"last_run"`
	NextRun     time.Time      `json:"next_run"`
	RunCount    int            `json:"run_count"`
	CreatedAt   time.Time      `json:"created_at"`
	CreatedBy   string         `json:"created_by"`
}

// ==================== File Transfer ====================

// FileListRequest represents a file listing request
type FileListRequest struct {
	Path string `json:"path" validate:"required"`
}

// FileListResponse represents file listing response
type FileListResponse struct {
	Path  string     `json:"path"`
	Files []FileInfo `json:"files"`
}

// FileInfo represents file information
type FileInfo struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	IsDir      bool      `json:"is_dir"`
	Mode       string    `json:"mode"`
	ModifiedAt time.Time `json:"modified_at"`
}

// FileUploadRequest represents a file upload request
type FileUploadRequest struct {
	RemotePath string `json:"remote_path" validate:"required"`
	Content    string `json:"content" validate:"required"` // Base64 encoded
	Checksum   string `json:"checksum,omitempty"`
}

// FileDownloadRequest represents a file download request
type FileDownloadRequest struct {
	RemotePath string `json:"remote_path" validate:"required"`
}

// FileTransferResponse represents a file transfer response
type FileTransferResponse struct {
	TransferID  string `json:"transfer_id"`
	CommandID   string `json:"command_id"`
	Status      string `json:"status"`
	TotalSize   int64  `json:"total_size,omitempty"`
	TotalChunks int    `json:"total_chunks,omitempty"`
}

// ==================== Dashboard & Statistics ====================

// DashboardStatsResponse represents dashboard statistics
type DashboardStatsResponse struct {
	TotalAgents     int               `json:"total_agents"`
	OnlineAgents    int               `json:"online_agents"`
	OfflineAgents   int               `json:"offline_agents"`
	PendingCommands int               `json:"pending_commands"`
	TotalCommands   int64             `json:"total_commands"`
	SuccessRate     float64           `json:"success_rate"`
	AgentsByOS      map[string]int    `json:"agents_by_os"`
	AgentsByStatus  map[string]int    `json:"agents_by_status"`
	RecentActivity  []ActivityEntry   `json:"recent_activity"`
}

// ActivityEntry represents a recent activity entry
type ActivityEntry struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	AgentID   string    `json:"agent_id,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
}

// ==================== Audit Log ====================

// AuditLogResponse represents an audit log entry
type AuditLogResponse struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	UserID    string         `json:"user_id"`
	Username  string         `json:"username"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Details   map[string]any `json:"details,omitempty"`
	IPAddress string         `json:"ip_address"`
	UserAgent string         `json:"user_agent"`
	Success   bool           `json:"success"`
}

// AuditLogListResponse represents a list of audit logs
type AuditLogListResponse struct {
	Logs       []AuditLogResponse `json:"logs"`
	TotalCount int                `json:"total_count"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
}

// ==================== Metrics ====================

// MetricsResponse represents server metrics
type MetricsResponse struct {
	TotalRequests      uint64  `json:"total_requests"`
	TotalAgentConns    uint64  `json:"total_agent_conns"`
	TotalCommands      uint64  `json:"total_commands"`
	TotalCommandsOK    uint64  `json:"total_commands_ok"`
	TotalCommandsFail  uint64  `json:"total_commands_fail"`
	ActiveAgents       int64   `json:"active_agents"`
	ActiveWebSockets   int64   `json:"active_websockets"`
	PendingCommands    int64   `json:"pending_commands"`
	AvgRequestLatency  float64 `json:"avg_request_latency_ms"`
	AvgCommandLatency  float64 `json:"avg_command_latency_ms"`
	Goroutines         int     `json:"goroutines"`
	HeapAllocBytes     uint64  `json:"heap_alloc_bytes"`
	UptimeSeconds      float64 `json:"uptime_seconds"`
}

// ==================== Alerts ====================

// AlertConfig represents alert configuration
type AlertConfig struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"` // agent_offline, high_cpu, disk_full, etc.
	Threshold   float64           `json:"threshold,omitempty"`
	Duration    string            `json:"duration,omitempty"`
	Targets     []string          `json:"targets,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Enabled     bool              `json:"enabled"`
	Channels    []string          `json:"channels"` // email, webhook, slack
	CreatedAt   time.Time         `json:"created_at"`
}

// AlertEvent represents an alert event
type AlertEvent struct {
	ID        string         `json:"id"`
	AlertID   string         `json:"alert_id"`
	AlertName string         `json:"alert_name"`
	AgentID   string         `json:"agent_id,omitempty"`
	Severity  string         `json:"severity"` // critical, warning, info
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	FiredAt   time.Time      `json:"fired_at"`
	ResolvedAt *time.Time    `json:"resolved_at,omitempty"`
}

// ==================== Health ====================

// HealthResponse represents server health status
type HealthResponse struct {
	Status     string    `json:"status"`
	Version    string    `json:"version"`
	AgentCount int       `json:"agent_count"`
	APIVersion string    `json:"api_version"`
	ServerTime time.Time `json:"server_time"`
	Uptime     string    `json:"uptime"`
}

// ==================== Pagination ====================

// PaginationRequest represents pagination parameters
type PaginationRequest struct {
	Page     int    `json:"page" validate:"min=1"`
	PageSize int    `json:"page_size" validate:"min=1,max=100"`
	SortBy   string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty" validate:"omitempty,oneof=asc desc"`
}

// PaginationResponse represents pagination metadata
type PaginationResponse struct {
	Page       int  `json:"page"`
	PageSize   int  `json:"page_size"`
	TotalCount int  `json:"total_count"`
	TotalPages int  `json:"total_pages"`
	HasNext    bool `json:"has_next"`
	HasPrev    bool `json:"has_prev"`
}
