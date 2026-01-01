package api

import (
	"net"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
)

// Validator provides input validation functions
type Validator struct {
	errors []FieldError
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{
		errors: make([]FieldError, 0),
	}
}

// HasErrors returns true if there are validation errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// Errors returns all validation errors
func (v *Validator) Errors() []FieldError {
	return v.errors
}

// AddError adds a validation error
func (v *Validator) AddError(field, message, tag string) {
	v.errors = append(v.errors, FieldError{
		Field:   field,
		Message: message,
		Tag:     tag,
	})
}

// Reset clears all errors
func (v *Validator) Reset() {
	v.errors = v.errors[:0]
}

// Required validates that a field is not empty
func (v *Validator) Required(field, value string) bool {
	if strings.TrimSpace(value) == "" {
		v.AddError(field, field+" is required", "required")
		return false
	}
	return true
}

// MinLength validates minimum string length
func (v *Validator) MinLength(field, value string, min int) bool {
	if len(value) < min {
		v.AddError(field, field+" must be at least "+itoa(min)+" characters", "min")
		return false
	}
	return true
}

// MaxLength validates maximum string length
func (v *Validator) MaxLength(field, value string, max int) bool {
	if len(value) > max {
		v.AddError(field, field+" must be at most "+itoa(max)+" characters", "max")
		return false
	}
	return true
}

// Length validates exact string length
func (v *Validator) Length(field, value string, length int) bool {
	if len(value) != length {
		v.AddError(field, field+" must be exactly "+itoa(length)+" characters", "len")
		return false
	}
	return true
}

// Email validates email format
func (v *Validator) Email(field, value string) bool {
	if value == "" {
		return true // Use Required for mandatory check
	}
	_, err := mail.ParseAddress(value)
	if err != nil {
		v.AddError(field, "Invalid email format", "email")
		return false
	}
	return true
}

// Alphanumeric validates that a string contains only alphanumeric characters
func (v *Validator) Alphanumeric(field, value string) bool {
	if value == "" {
		return true
	}
	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			v.AddError(field, field+" must contain only alphanumeric characters", "alphanum")
			return false
		}
	}
	return true
}

// AlphanumericDash validates alphanumeric with dashes and underscores
func (v *Validator) AlphanumericDash(field, value string) bool {
	if value == "" {
		return true
	}
	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			v.AddError(field, field+" must contain only alphanumeric characters, dashes, and underscores", "alphanumDash")
			return false
		}
	}
	return true
}

// IP validates IP address format
func (v *Validator) IP(field, value string) bool {
	if value == "" {
		return true
	}
	if net.ParseIP(value) == nil {
		v.AddError(field, "Invalid IP address", "ip")
		return false
	}
	return true
}

// Port validates port number
func (v *Validator) Port(field string, value int) bool {
	if value < 1 || value > 65535 {
		v.AddError(field, "Port must be between 1 and 65535", "port")
		return false
	}
	return true
}

// InRange validates integer is within range
func (v *Validator) InRange(field string, value, min, max int) bool {
	if value < min || value > max {
		v.AddError(field, field+" must be between "+itoa(min)+" and "+itoa(max), "range")
		return false
	}
	return true
}

// OneOf validates that value is one of allowed values
func (v *Validator) OneOf(field, value string, allowed []string) bool {
	if value == "" {
		return true
	}
	for _, a := range allowed {
		if value == a {
			return true
		}
	}
	v.AddError(field, field+" must be one of: "+strings.Join(allowed, ", "), "oneof")
	return false
}

// Regex validates against a regular expression
func (v *Validator) Regex(field, value, pattern, message string) bool {
	if value == "" {
		return true
	}
	matched, err := regexp.MatchString(pattern, value)
	if err != nil || !matched {
		if message == "" {
			message = field + " has invalid format"
		}
		v.AddError(field, message, "regex")
		return false
	}
	return true
}

// UUID validates UUID format
func (v *Validator) UUID(field, value string) bool {
	if value == "" {
		return true
	}
	pattern := `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	matched, _ := regexp.MatchString(pattern, strings.ToLower(value))
	if !matched {
		v.AddError(field, "Invalid UUID format", "uuid")
		return false
	}
	return true
}

// Password validates password complexity
func (v *Validator) Password(field, value string) bool {
	if value == "" {
		return true
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, r := range value {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasNumber = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if len(value) < 8 {
		v.AddError(field, "Password must be at least 8 characters", "password_length")
		return false
	}

	if !hasUpper {
		v.AddError(field, "Password must contain at least one uppercase letter", "password_upper")
		return false
	}

	if !hasLower {
		v.AddError(field, "Password must contain at least one lowercase letter", "password_lower")
		return false
	}

	if !hasNumber {
		v.AddError(field, "Password must contain at least one number", "password_number")
		return false
	}

	if !hasSpecial {
		v.AddError(field, "Password must contain at least one special character", "password_special")
		return false
	}

	return true
}

// URL validates URL format
func (v *Validator) URL(field, value string) bool {
	if value == "" {
		return true
	}
	pattern := `^https?://[^\s/$.?#].[^\s]*$`
	matched, _ := regexp.MatchString(pattern, value)
	if !matched {
		v.AddError(field, "Invalid URL format", "url")
		return false
	}
	return true
}

// Path validates file path (basic check)
func (v *Validator) Path(field, value string) bool {
	if value == "" {
		return true
	}
	// Reject obvious path traversal
	if strings.Contains(value, "..") {
		v.AddError(field, "Path cannot contain '..'", "path")
		return false
	}
	// Reject null bytes
	if strings.Contains(value, "\x00") {
		v.AddError(field, "Invalid path", "path")
		return false
	}
	return true
}

// Duration validates duration string format
func (v *Validator) Duration(field, value string) bool {
	if value == "" {
		return true
	}
	pattern := `^(\d+)(s|m|h|d)$`
	matched, _ := regexp.MatchString(pattern, value)
	if !matched {
		v.AddError(field, "Invalid duration format (use format like 30s, 5m, 1h, 7d)", "duration")
		return false
	}
	return true
}

// Cron validates cron expression (basic validation)
func (v *Validator) Cron(field, value string) bool {
	if value == "" {
		return true
	}
	parts := strings.Fields(value)
	if len(parts) != 5 && len(parts) != 6 {
		v.AddError(field, "Invalid cron expression", "cron")
		return false
	}
	return true
}

// Labels validates label key-value pairs
func (v *Validator) Labels(field string, labels map[string]string) bool {
	labelKeyPattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)
	
	for key, value := range labels {
		if len(key) > 63 {
			v.AddError(field, "Label key '"+key+"' exceeds maximum length of 63 characters", "label_key")
			return false
		}
		if !labelKeyPattern.MatchString(key) {
			v.AddError(field, "Label key '"+key+"' has invalid format", "label_key")
			return false
		}
		if len(value) > 255 {
			v.AddError(field, "Label value for '"+key+"' exceeds maximum length of 255 characters", "label_value")
			return false
		}
	}
	return true
}

// Validate runs all validation and returns API error if validation fails
func (v *Validator) Validate() *APIError {
	if v.HasErrors() {
		return ErrValidation(v.Errors())
	}
	return nil
}

// Helper function to convert int to string
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	
	negative := n < 0
	if negative {
		n = -n
	}
	
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	
	if negative {
		digits = append([]byte{'-'}, digits...)
	}
	
	return string(digits)
}

// ValidateLoginRequest validates a login request
func ValidateLoginRequest(req *LoginRequest) *APIError {
	v := NewValidator()
	v.Required("username", req.Username)
	v.MinLength("username", req.Username, 3)
	v.MaxLength("username", req.Username, 64)
	v.Required("password", req.Password)
	v.MinLength("password", req.Password, 8)
	return v.Validate()
}

// ValidateCreateUserRequest validates a user creation request
func ValidateCreateUserRequest(req *CreateUserRequest) *APIError {
	v := NewValidator()
	v.Required("username", req.Username)
	v.MinLength("username", req.Username, 3)
	v.MaxLength("username", req.Username, 64)
	v.Alphanumeric("username", req.Username)
	v.Required("email", req.Email)
	v.Email("email", req.Email)
	v.Required("password", req.Password)
	v.MinLength("password", req.Password, 8)
	v.Required("role", req.Role)
	v.OneOf("role", req.Role, []string{"admin", "operator", "viewer", "auditor"})
	return v.Validate()
}

// ValidateCommandRequest validates a command request
func ValidateCommandRequest(req *CommandRequest) *APIError {
	v := NewValidator()
	v.Required("type", req.Type)
	v.OneOf("type", req.Type, []string{
		"execute", "file_transfer", "system_info", "process_list",
		"process_kill", "service_manage", "registry_read", "registry_write",
		"network_info", "shell_session", "update", "restart", "shutdown",
	})
	v.InRange("timeout", req.Timeout, 1, 86400)
	return v.Validate()
}

// ValidateCreateGroupRequest validates a group creation request
func ValidateCreateGroupRequest(req *CreateGroupRequest) *APIError {
	v := NewValidator()
	v.Required("name", req.Name)
	v.MinLength("name", req.Name, 1)
	v.MaxLength("name", req.Name, 128)
	v.MaxLength("description", req.Description, 512)
	if len(req.Selector) == 0 {
		v.AddError("selector", "At least one selector is required", "required")
	}
	v.Labels("selector", req.Selector)
	return v.Validate()
}

// ValidateCreateTaskRequest validates a task creation request
func ValidateCreateTaskRequest(req *CreateTaskRequest) *APIError {
	v := NewValidator()
	v.Required("name", req.Name)
	v.MinLength("name", req.Name, 1)
	v.MaxLength("name", req.Name, 128)
	v.MaxLength("description", req.Description, 512)
	v.Required("schedule.type", req.Schedule.Type)
	v.OneOf("schedule.type", req.Schedule.Type, []string{"once", "interval", "daily", "weekly", "cron"})
	
	if req.Schedule.Type == "cron" {
		v.Required("schedule.cron", req.Schedule.Cron)
		v.Cron("schedule.cron", req.Schedule.Cron)
	}
	if req.Schedule.Type == "interval" {
		v.Required("schedule.interval", req.Schedule.Interval)
		v.Duration("schedule.interval", req.Schedule.Interval)
	}
	
	if req.TargetAgent == "" && req.TargetGroup == "" {
		v.AddError("target", "Either target_agent or target_group is required", "required")
	}
	
	if err := ValidateCommandRequest(&req.Command); err != nil {
		return err
	}
	
	return v.Validate()
}

// ValidateFileUploadRequest validates a file upload request
func ValidateFileUploadRequest(req *FileUploadRequest) *APIError {
	v := NewValidator()
	v.Required("remote_path", req.RemotePath)
	v.Path("remote_path", req.RemotePath)
	v.Required("content", req.Content)
	return v.Validate()
}

// ValidateFileDownloadRequest validates a file download request
func ValidateFileDownloadRequest(req *FileDownloadRequest) *APIError {
	v := NewValidator()
	v.Required("remote_path", req.RemotePath)
	v.Path("remote_path", req.RemotePath)
	return v.Validate()
}
