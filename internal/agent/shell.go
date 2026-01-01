package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/argus/argus/internal/protocol"
	"github.com/argus/argus/pkg/models"
)

// ShellSession represents an interactive shell session
type ShellSession struct {
	ID        string
	Cmd       *exec.Cmd
	Stdin     io.WriteCloser
	Stdout    io.ReadCloser
	Stderr    io.ReadCloser
	Started   time.Time
	LastUsed  time.Time
	Cancel    context.CancelFunc
	Output    chan []byte
	mu        sync.Mutex
	active    bool
}

// ShellManager manages interactive shell sessions
type ShellManager struct {
	mu       sync.RWMutex
	sessions map[string]*ShellSession
	maxSessions int
	timeout  time.Duration
}

// NewShellManager creates a new shell manager
func NewShellManager(maxSessions int, timeout time.Duration) *ShellManager {
	if maxSessions <= 0 {
		maxSessions = 5
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}

	sm := &ShellManager{
		sessions:    make(map[string]*ShellSession),
		maxSessions: maxSessions,
		timeout:     timeout,
	}

	// Start cleanup routine
	go sm.cleanupLoop()

	return sm
}

// CreateSession creates a new shell session
func (sm *ShellManager) CreateSession(sessionID string) (*ShellSession, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check max sessions
	if len(sm.sessions) >= sm.maxSessions {
		return nil, fmt.Errorf("maximum sessions (%d) reached", sm.maxSessions)
	}

	// Check if session already exists
	if _, exists := sm.sessions[sessionID]; exists {
		return nil, fmt.Errorf("session %s already exists", sessionID)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe")
	} else {
		// Try to use user's shell, fall back to sh
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		cmd = exec.CommandContext(ctx, shell)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get stdin: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		stdin.Close()
		return nil, fmt.Errorf("failed to get stdout: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("failed to get stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return nil, fmt.Errorf("failed to start shell: %w", err)
	}

	session := &ShellSession{
		ID:       sessionID,
		Cmd:      cmd,
		Stdin:    stdin,
		Stdout:   stdout,
		Stderr:   stderr,
		Started:  time.Now(),
		LastUsed: time.Now(),
		Cancel:   cancel,
		Output:   make(chan []byte, 100),
		active:   true,
	}

	sm.sessions[sessionID] = session

	// Start output reader
	go session.readOutput()

	return session, nil
}

// GetSession retrieves an existing session
func (sm *ShellManager) GetSession(sessionID string) (*ShellSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	session, ok := sm.sessions[sessionID]
	if ok {
		session.LastUsed = time.Now()
	}
	return session, ok
}

// CloseSession closes a shell session
func (sm *ShellManager) CloseSession(sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	session.Close()
	delete(sm.sessions, sessionID)
	return nil
}

// ListSessions returns all active sessions
func (sm *ShellManager) ListSessions() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	ids := make([]string, 0, len(sm.sessions))
	for id := range sm.sessions {
		ids = append(ids, id)
	}
	return ids
}

func (sm *ShellManager) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for id, session := range sm.sessions {
			if now.Sub(session.LastUsed) > sm.timeout {
				session.Close()
				delete(sm.sessions, id)
			}
		}
		sm.mu.Unlock()
	}
}

// Write sends input to the shell
func (s *ShellSession) Write(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return fmt.Errorf("session is closed")
	}

	s.LastUsed = time.Now()
	_, err := s.Stdin.Write(data)
	return err
}

// Read reads available output from the shell
func (s *ShellSession) Read() ([]byte, error) {
	select {
	case data := <-s.Output:
		return data, nil
	case <-time.After(100 * time.Millisecond):
		return nil, nil
	}
}

// Close terminates the shell session
func (s *ShellSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return
	}

	s.active = false
	s.Cancel()
	s.Stdin.Close()
	s.Stdout.Close()
	s.Stderr.Close()
	s.Cmd.Wait()
	close(s.Output)
}

// IsActive returns whether the session is active
func (s *ShellSession) IsActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

func (s *ShellSession) readOutput() {
	buf := make([]byte, 4096)

	// Read stdout
	go func() {
		for {
			n, err := s.Stdout.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case s.Output <- data:
				default:
					// Drop if channel full
				}
			}
		}
	}()

	// Read stderr
	go func() {
		for {
			n, err := s.Stderr.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case s.Output <- data:
				default:
				}
			}
		}
	}()
}

// HandleShellSession processes shell session commands
func (a *Agent) HandleShellSession(cmd *protocol.CommandPayload, result *models.CommandResult) {
	operation, _ := cmd.Payload["operation"].(string)
	sessionID, _ := cmd.Payload["session_id"].(string)

	if a.shellManager == nil {
		a.shellManager = NewShellManager(5, 30*time.Minute)
	}

	switch operation {
	case "create":
		session, err := a.shellManager.CreateSession(sessionID)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true
		result.Output = fmt.Sprintf("Shell session created: %s", session.ID)

	case "write":
		session, ok := a.shellManager.GetSession(sessionID)
		if !ok {
			result.Success = false
			result.Error = "session not found"
			return
		}

		input, _ := cmd.Payload["input"].(string)
		if err := session.Write([]byte(input)); err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true

	case "read":
		session, ok := a.shellManager.GetSession(sessionID)
		if !ok {
			result.Success = false
			result.Error = "session not found"
			return
		}

		// Collect output
		var output []byte
		timeout := time.After(time.Second)
	readLoop:
		for {
			select {
			case data := <-session.Output:
				output = append(output, data...)
			case <-timeout:
				break readLoop
			}
		}

		result.Success = true
		result.Output = string(output)

	case "close":
		if err := a.shellManager.CloseSession(sessionID); err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true
		result.Output = "Session closed"

	case "list":
		sessions := a.shellManager.ListSessions()
		result.Success = true
		result.Output = fmt.Sprintf("Active sessions: %v", sessions)

	case "resize":
		// PTY resize (would need actual PTY implementation)
		result.Success = true
		result.Output = "Resize acknowledged"

	default:
		result.Success = false
		result.Error = "unknown operation: " + operation
	}
}
