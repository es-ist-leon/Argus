package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/argus/argus/internal/crypto"
	"github.com/argus/argus/pkg/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserDisabled       = errors.New("user account is disabled")
	ErrTokenExpired       = errors.New("token has expired")
	ErrInvalidToken       = errors.New("invalid token")
	ErrInsufficientPerms  = errors.New("insufficient permissions")
	ErrMFARequired        = errors.New("MFA verification required")
)

// Claims represents JWT claims
type Claims struct {
	UserID      string           `json:"uid"`
	Username    string           `json:"username"`
	Role        models.UserRole  `json:"role"`
	Permissions []string         `json:"permissions"`
	SessionID   string           `json:"sid"`
	jwt.RegisteredClaims
}

// AuthManager handles authentication and authorization
type AuthManager struct {
	mu           sync.RWMutex
	users        map[string]*models.User
	sessions     map[string]*Session
	jwtSecret    []byte
	tokenExpiry  time.Duration
	maxSessions  int
}

// Session represents an active user session
type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	IPAddress string
	UserAgent string
	Active    bool
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(jwtSecret []byte) *AuthManager {
	return &AuthManager{
		users:       make(map[string]*models.User),
		sessions:    make(map[string]*Session),
		jwtSecret:   jwtSecret,
		tokenExpiry: 24 * time.Hour,
		maxSessions: 5,
	}
}

// CreateUser creates a new user account
func (am *AuthManager) CreateUser(username, email, password string, role models.UserRole) (*models.User, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Check if user already exists
	for _, u := range am.users {
		if u.Username == username || u.Email == email {
			return nil, errors.New("user already exists")
		}
	}

	hash, salt, err := crypto.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate API key
	apiKeyBytes, err := crypto.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	user := &models.User{
		ID:           uuid.New().String(),
		Username:     username,
		Email:        email,
		PasswordHash: fmt.Sprintf("%x:%x", salt, hash),
		Role:         role,
		Permissions:  getDefaultPermissions(role),
		APIKey:       fmt.Sprintf("%x", apiKeyBytes),
		MFAEnabled:   false,
		CreatedAt:    time.Now(),
		Active:       true,
	}

	am.users[user.ID] = user
	return user, nil
}

// Authenticate validates credentials and returns a JWT token
func (am *AuthManager) Authenticate(ctx context.Context, username, password, ipAddress, userAgent string) (string, error) {
	am.mu.RLock()
	var user *models.User
	for _, u := range am.users {
		if u.Username == username {
			user = u
			break
		}
	}
	am.mu.RUnlock()

	if user == nil {
		return "", ErrUserNotFound
	}

	if !user.Active {
		return "", ErrUserDisabled
	}

	// Verify password
	var salt, hash []byte
	_, err := fmt.Sscanf(user.PasswordHash, "%x:%x", &salt, &hash)
	if err != nil || !crypto.VerifyPassword(password, hash, salt) {
		return "", ErrInvalidCredentials
	}

	// Create session
	session := &Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(am.tokenExpiry),
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Active:    true,
	}

	am.mu.Lock()
	am.sessions[session.ID] = session
	user.LastLogin = time.Now()
	am.mu.Unlock()

	// Generate JWT
	token, err := am.generateToken(user, session.ID)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	return token, nil
}

// ValidateToken validates a JWT token and returns the claims
func (am *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return am.jwtSecret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Verify session is still active
	am.mu.RLock()
	session, exists := am.sessions[claims.SessionID]
	am.mu.RUnlock()

	if !exists || !session.Active {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// AuthorizeAction checks if a user has permission to perform an action
func (am *AuthManager) AuthorizeAction(claims *Claims, requiredPermission string) error {
	for _, perm := range claims.Permissions {
		if perm == requiredPermission || perm == "*" {
			return nil
		}
	}
	return ErrInsufficientPerms
}

// RevokeSession invalidates a user session
func (am *AuthManager) RevokeSession(sessionID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	session, exists := am.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	session.Active = false
	return nil
}

// RevokeAllUserSessions invalidates all sessions for a user
func (am *AuthManager) RevokeAllUserSessions(userID string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	for _, session := range am.sessions {
		if session.UserID == userID {
			session.Active = false
		}
	}
}

// RefreshToken generates a new token from a valid existing token
func (am *AuthManager) RefreshToken(tokenString string) (string, error) {
	claims, err := am.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	am.mu.RLock()
	user, exists := am.users[claims.UserID]
	am.mu.RUnlock()

	if !exists {
		return "", ErrUserNotFound
	}

	return am.generateToken(user, claims.SessionID)
}

// GetUser retrieves a user by ID
func (am *AuthManager) GetUser(userID string) (*models.User, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	user, exists := am.users[userID]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// ValidateAPIKey validates an API key and returns the associated user
func (am *AuthManager) ValidateAPIKey(apiKey string) (*models.User, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	for _, user := range am.users {
		if user.APIKey == apiKey && user.Active {
			return user, nil
		}
	}

	return nil, ErrInvalidCredentials
}

func (am *AuthManager) generateToken(user *models.User, sessionID string) (string, error) {
	now := time.Now()
	claims := &Claims{
		UserID:      user.ID,
		Username:    user.Username,
		Role:        user.Role,
		Permissions: user.Permissions,
		SessionID:   sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(am.tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "argus-server",
			Subject:   user.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(am.jwtSecret)
}

func getDefaultPermissions(role models.UserRole) []string {
	switch role {
	case models.RoleAdmin:
		return []string{"*"}
	case models.RoleOperator:
		return []string{
			"agents:read", "agents:write",
			"commands:read", "commands:write", "commands:execute",
			"files:read", "files:write",
			"processes:read", "processes:write",
		}
	case models.RoleViewer:
		return []string{
			"agents:read",
			"commands:read",
			"files:read",
			"processes:read",
		}
	case models.RoleAuditor:
		return []string{
			"agents:read",
			"commands:read",
			"audit:read",
		}
	default:
		return []string{}
	}
}

// CleanupExpiredSessions removes expired sessions
func (am *AuthManager) CleanupExpiredSessions() {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	for id, session := range am.sessions {
		if session.ExpiresAt.Before(now) {
			delete(am.sessions, id)
		}
	}
}
