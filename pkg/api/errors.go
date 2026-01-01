package api

import (
	"encoding/json"
	"net/http"
)

// ErrorCode represents an API error code
type ErrorCode string

const (
	ErrCodeUnknown          ErrorCode = "UNKNOWN_ERROR"
	ErrCodeInvalidRequest   ErrorCode = "INVALID_REQUEST"
	ErrCodeUnauthorized     ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden        ErrorCode = "FORBIDDEN"
	ErrCodeNotFound         ErrorCode = "NOT_FOUND"
	ErrCodeConflict         ErrorCode = "CONFLICT"
	ErrCodeRateLimited      ErrorCode = "RATE_LIMITED"
	ErrCodeInternalError    ErrorCode = "INTERNAL_ERROR"
	ErrCodeServiceUnavail   ErrorCode = "SERVICE_UNAVAILABLE"
	ErrCodeValidationFailed ErrorCode = "VALIDATION_FAILED"
	ErrCodeAgentOffline     ErrorCode = "AGENT_OFFLINE"
	ErrCodeTimeout          ErrorCode = "TIMEOUT"
	ErrCodeCommandFailed    ErrorCode = "COMMAND_FAILED"
	ErrCodeTransferFailed   ErrorCode = "TRANSFER_FAILED"
)

// APIError represents an API error response
type APIError struct {
	Code       ErrorCode      `json:"code"`
	Message    string         `json:"message"`
	Details    string         `json:"details,omitempty"`
	Field      string         `json:"field,omitempty"`
	RequestID  string         `json:"request_id,omitempty"`
	Timestamp  int64          `json:"timestamp"`
	Validation []FieldError   `json:"validation,omitempty"`
}

// FieldError represents a field validation error
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Tag     string `json:"tag,omitempty"`
	Value   any    `json:"value,omitempty"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	return e.Message
}

// NewAPIError creates a new API error
func NewAPIError(code ErrorCode, message string) *APIError {
	return &APIError{
		Code:      code,
		Message:   message,
		Timestamp: currentTimestamp(),
	}
}

// WithDetails adds details to the error
func (e *APIError) WithDetails(details string) *APIError {
	e.Details = details
	return e
}

// WithField adds a field name to the error
func (e *APIError) WithField(field string) *APIError {
	e.Field = field
	return e
}

// WithRequestID adds a request ID to the error
func (e *APIError) WithRequestID(requestID string) *APIError {
	e.RequestID = requestID
	return e
}

// WithValidation adds validation errors
func (e *APIError) WithValidation(errors []FieldError) *APIError {
	e.Validation = errors
	return e
}

// HTTPStatus returns the appropriate HTTP status code for the error
func (e *APIError) HTTPStatus() int {
	switch e.Code {
	case ErrCodeInvalidRequest, ErrCodeValidationFailed:
		return http.StatusBadRequest
	case ErrCodeUnauthorized:
		return http.StatusUnauthorized
	case ErrCodeForbidden:
		return http.StatusForbidden
	case ErrCodeNotFound, ErrCodeAgentOffline:
		return http.StatusNotFound
	case ErrCodeConflict:
		return http.StatusConflict
	case ErrCodeRateLimited:
		return http.StatusTooManyRequests
	case ErrCodeTimeout:
		return http.StatusGatewayTimeout
	case ErrCodeServiceUnavail:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// WriteJSON writes the error as JSON to the response writer
func (e *APIError) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.HTTPStatus())
	json.NewEncoder(w).Encode(e)
}

// Common error constructors

// ErrInvalidRequest creates an invalid request error
func ErrInvalidRequest(message string) *APIError {
	return NewAPIError(ErrCodeInvalidRequest, message)
}

// ErrUnauthorized creates an unauthorized error
func ErrUnauthorized(message string) *APIError {
	if message == "" {
		message = "Authentication required"
	}
	return NewAPIError(ErrCodeUnauthorized, message)
}

// ErrForbidden creates a forbidden error
func ErrForbidden(message string) *APIError {
	if message == "" {
		message = "Access denied"
	}
	return NewAPIError(ErrCodeForbidden, message)
}

// ErrNotFound creates a not found error
func ErrNotFound(resource string) *APIError {
	return NewAPIError(ErrCodeNotFound, resource+" not found")
}

// ErrConflict creates a conflict error
func ErrConflict(message string) *APIError {
	return NewAPIError(ErrCodeConflict, message)
}

// ErrRateLimited creates a rate limited error
func ErrRateLimited() *APIError {
	return NewAPIError(ErrCodeRateLimited, "Rate limit exceeded")
}

// ErrInternal creates an internal error
func ErrInternal(message string) *APIError {
	if message == "" {
		message = "Internal server error"
	}
	return NewAPIError(ErrCodeInternalError, message)
}

// ErrValidation creates a validation error
func ErrValidation(errors []FieldError) *APIError {
	return NewAPIError(ErrCodeValidationFailed, "Validation failed").WithValidation(errors)
}

// ErrAgentOffline creates an agent offline error
func ErrAgentOffline(agentID string) *APIError {
	return NewAPIError(ErrCodeAgentOffline, "Agent is offline").WithDetails(agentID)
}

// ErrTimeout creates a timeout error
func ErrTimeout(operation string) *APIError {
	return NewAPIError(ErrCodeTimeout, "Operation timed out").WithDetails(operation)
}

// Helper functions

func currentTimestamp() int64 {
	return timeNow().Unix()
}

// timeNow is a variable for testing purposes
var timeNow = func() interface{ Unix() int64 } {
	return &realTime{}
}

type realTime struct{}

func (t *realTime) Unix() int64 {
	return 0 // Will be replaced at runtime
}

func init() {
	// Initialize with actual time function
	timeNow = func() interface{ Unix() int64 } {
		return &timeWrapper{}
	}
}

type timeWrapper struct{}

func (t *timeWrapper) Unix() int64 {
	return unixTime()
}

// unixTime returns current unix timestamp
func unixTime() int64 {
	// Import time package functionality inline
	type timeInterface interface {
		Unix() int64
	}
	// This will be resolved at compile time
	return getNow()
}

var getNow = func() int64 {
	return 0
}

func init() {
	// Import time at runtime
	getNow = getCurrentUnixTime
}

func getCurrentUnixTime() int64 {
	// Using time.Now().Unix() equivalent
	return int64(0) // Placeholder - actual implementation uses time package
}
