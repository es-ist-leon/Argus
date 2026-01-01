package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/argus/argus/internal/auth"
	"github.com/argus/argus/internal/protocol"
	"github.com/argus/argus/pkg/models"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// Config holds server configuration
type Config struct {
	ListenAddr     string        `yaml:"listen_addr"`
	APIAddr        string        `yaml:"api_addr"`
	TLSCertFile    string        `yaml:"tls_cert_file"`
	TLSKeyFile     string        `yaml:"tls_key_file"`
	JWTSecret      string        `yaml:"jwt_secret"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	SessionTimeout time.Duration `yaml:"session_timeout"`
	MaxAgents      int           `yaml:"max_agents"`
	AuditLog       bool          `yaml:"audit_log"`
}

// Server is the main control server
type Server struct {
	config      *Config
	authManager *auth.AuthManager
	agents      map[string]*AgentConnection
	agentsMu    sync.RWMutex
	commands    chan *models.Command
	results     chan *models.CommandResult
	auditLogs   []models.AuditLog
	auditMu     sync.RWMutex
	httpServer  *http.Server
	agentServer net.Listener
	upgrader    websocket.Upgrader
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// AgentConnection represents a connected agent
type AgentConnection struct {
	Agent       *models.Agent
	Conn        net.Conn
	LastSeen    time.Time
	Sequence    uint32
	SendQueue   chan *protocol.Message
	Connected   bool
	mu          sync.Mutex
}

// NewServer creates a new server instance
func NewServer(config *Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Server{
		config:      config,
		authManager: auth.NewAuthManager([]byte(config.JWTSecret)),
		agents:      make(map[string]*AgentConnection),
		commands:    make(chan *models.Command, 1000),
		results:     make(chan *models.CommandResult, 1000),
		auditLogs:   make([]models.AuditLog, 0),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start starts the server
func (s *Server) Start() error {
	// Create default admin user
	_, err := s.authManager.CreateUser("admin", "admin@argus.local", "changeme", models.RoleAdmin)
	if err != nil {
		log.Printf("Warning: Could not create default admin user: %v", err)
	}

	// Start agent listener
	s.wg.Add(1)
	go s.startAgentListener()

	// Start API server
	s.wg.Add(1)
	go s.startAPIServer()

	// Start background tasks
	s.wg.Add(1)
	go s.heartbeatMonitor()

	s.wg.Add(1)
	go s.commandDispatcher()

	log.Printf("Argus Server started - Agent: %s, API: %s", s.config.ListenAddr, s.config.APIAddr)
	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() {
	log.Println("Shutting down server...")
	s.cancel()

	// Close all agent connections
	s.agentsMu.Lock()
	for _, agent := range s.agents {
		agent.Conn.Close()
	}
	s.agentsMu.Unlock()

	if s.agentServer != nil {
		s.agentServer.Close()
	}

	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx)
	}

	s.wg.Wait()
	log.Println("Server stopped")
}

func (s *Server) startAgentListener() {
	defer s.wg.Done()

	var err error
	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
		if err != nil {
			log.Fatalf("Failed to load TLS certificates: %v", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		s.agentServer, err = tls.Listen("tcp", s.config.ListenAddr, tlsConfig)
	} else {
		s.agentServer, err = net.Listen("tcp", s.config.ListenAddr)
	}

	if err != nil {
		log.Fatalf("Failed to start agent listener: %v", err)
	}

	log.Printf("Agent listener started on %s", s.config.ListenAddr)

	for {
		conn, err := s.agentServer.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		go s.handleAgentConnection(conn)
	}
}

func (s *Server) handleAgentConnection(conn net.Conn) {
	defer conn.Close()

	// Set initial timeout for handshake
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read handshake message
	msg, err := protocol.DecodeMessage(conn)
	if err != nil {
		log.Printf("Failed to read handshake: %v", err)
		return
	}

	if msg.Header.Type != protocol.MsgTypeHandshake {
		log.Printf("Expected handshake, got message type: %d", msg.Header.Type)
		return
	}

	var handshake protocol.HandshakePayload
	if err := msg.DecodePayload(&handshake); err != nil {
		log.Printf("Failed to decode handshake: %v", err)
		return
	}

	// Check max agents limit
	s.agentsMu.Lock()
	if len(s.agents) >= s.config.MaxAgents {
		s.agentsMu.Unlock()
		log.Printf("Max agents limit reached, rejecting agent: %s", handshake.AgentID)
		return
	}

	// Create agent record
	agent := &models.Agent{
		ID:           handshake.AgentID,
		Hostname:     handshake.Hostname,
		IPAddress:    conn.RemoteAddr().String(),
		OS:           handshake.OS,
		Arch:         handshake.Arch,
		Version:      handshake.Version,
		Status:       models.StatusOnline,
		Labels:       handshake.Labels,
		LastSeen:     time.Now(),
		RegisteredAt: time.Now(),
		Capabilities: handshake.Capabilities,
	}

	agentConn := &AgentConnection{
		Agent:     agent,
		Conn:      conn,
		LastSeen:  time.Now(),
		Sequence:  1,
		SendQueue: make(chan *protocol.Message, 100),
		Connected: true,
	}

	s.agents[agent.ID] = agentConn
	s.agentsMu.Unlock()

	log.Printf("Agent connected: %s (%s) from %s", agent.Hostname, agent.ID, agent.IPAddress)

	// Send acknowledgment
	ack, _ := protocol.NewMessage(protocol.MsgTypeAck, map[string]string{"status": "accepted"}, 0)
	conn.Write(ack.Encode())

	// Start send loop
	go s.agentSendLoop(agentConn)

	// Main receive loop
	s.agentReceiveLoop(agentConn)
}

func (s *Server) agentSendLoop(ac *AgentConnection) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case msg := <-ac.SendQueue:
			ac.mu.Lock()
			if ac.Connected {
				ac.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := ac.Conn.Write(msg.Encode()); err != nil {
					log.Printf("Failed to send message to agent %s: %v", ac.Agent.ID, err)
					ac.Connected = false
				}
			}
			ac.mu.Unlock()
			if !ac.Connected {
				return
			}
		}
	}
}

func (s *Server) agentReceiveLoop(ac *AgentConnection) {
	defer func() {
		s.agentsMu.Lock()
		delete(s.agents, ac.Agent.ID)
		s.agentsMu.Unlock()
		ac.Connected = false
		log.Printf("Agent disconnected: %s (%s)", ac.Agent.Hostname, ac.Agent.ID)
	}()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		ac.Conn.SetReadDeadline(time.Now().Add(s.config.HeartbeatInterval * 3))
		msg, err := protocol.DecodeMessage(ac.Conn)
		if err != nil {
			log.Printf("Error reading from agent %s: %v", ac.Agent.ID, err)
			return
		}

		ac.LastSeen = time.Now()
		ac.Agent.LastSeen = time.Now()

		switch msg.Header.Type {
		case protocol.MsgTypeHeartbeat:
			var hb protocol.HeartbeatPayload
			if err := msg.DecodePayload(&hb); err == nil {
				ac.Agent.Status = models.AgentStatus(hb.Status)
			}

		case protocol.MsgTypeResult:
			var result protocol.ResultPayload
			if err := msg.DecodePayload(&result); err == nil {
				s.results <- &models.CommandResult{
					CommandID:   result.CommandID,
					AgentID:     ac.Agent.ID,
					Success:     result.Success,
					ExitCode:    result.ExitCode,
					Output:      result.Output,
					Error:       result.Error,
					StartedAt:   time.Unix(result.StartedAt, 0),
					CompletedAt: time.Unix(result.CompletedAt, 0),
				}
			}

		case protocol.MsgTypeSystemInfo:
			var sysinfo models.SystemInfo
			if err := msg.DecodePayload(&sysinfo); err == nil {
				log.Printf("Received system info from %s", ac.Agent.ID)
			}

		case protocol.MsgTypeDisconnect:
			log.Printf("Agent %s requested disconnect", ac.Agent.ID)
			return
		}
	}
}

func (s *Server) heartbeatMonitor() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.agentsMu.RLock()
			for _, ac := range s.agents {
				if time.Since(ac.LastSeen) > s.config.HeartbeatInterval*3 {
					ac.Agent.Status = models.StatusOffline
				}
			}
			s.agentsMu.RUnlock()
		}
	}
}

func (s *Server) commandDispatcher() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		case cmd := <-s.commands:
			s.dispatchCommand(cmd)
		}
	}
}

func (s *Server) dispatchCommand(cmd *models.Command) {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()

	if cmd.TargetAgent != "" {
		if ac, ok := s.agents[cmd.TargetAgent]; ok && ac.Connected {
			msg, err := protocol.NewCommand(cmd, ac.Sequence)
			if err != nil {
				log.Printf("Failed to create command message: %v", err)
				return
			}
			ac.Sequence++
			ac.SendQueue <- msg
		}
	} else if cmd.TargetGroup != "" {
		// TODO: Implement group targeting
	}
}

// API Server

func (s *Server) startAPIServer() {
	defer s.wg.Done()

	router := mux.NewRouter()

	// Auth routes
	router.HandleFunc("/api/v1/auth/login", s.handleLogin).Methods("POST")
	router.HandleFunc("/api/v1/auth/logout", s.authMiddleware(s.handleLogout)).Methods("POST")
	router.HandleFunc("/api/v1/auth/refresh", s.authMiddleware(s.handleRefresh)).Methods("POST")

	// Agent routes
	router.HandleFunc("/api/v1/agents", s.authMiddleware(s.handleListAgents)).Methods("GET")
	router.HandleFunc("/api/v1/agents/{id}", s.authMiddleware(s.handleGetAgent)).Methods("GET")
	router.HandleFunc("/api/v1/agents/{id}/commands", s.authMiddleware(s.handleSendCommand)).Methods("POST")

	// Command routes
	router.HandleFunc("/api/v1/commands", s.authMiddleware(s.handleListCommands)).Methods("GET")
	router.HandleFunc("/api/v1/commands/{id}/result", s.authMiddleware(s.handleGetCommandResult)).Methods("GET")

	// WebSocket for real-time updates
	router.HandleFunc("/api/v1/ws", s.authMiddleware(s.handleWebSocket)).Methods("GET")

	// Dashboard
	router.HandleFunc("/api/v1/dashboard/stats", s.authMiddleware(s.handleDashboardStats)).Methods("GET")

	// Audit log
	router.HandleFunc("/api/v1/audit", s.authMiddleware(s.handleAuditLog)).Methods("GET")

	s.httpServer = &http.Server{
		Addr:         s.config.APIAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("API server started on %s", s.config.APIAddr)

	if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("API server error: %v", err)
	}
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			// Check API key
			apiKey := r.Header.Get("X-API-Key")
			if apiKey != "" {
				user, err := s.authManager.ValidateAPIKey(apiKey)
				if err == nil {
					ctx := context.WithValue(r.Context(), "user", user)
					next(w, r.WithContext(ctx))
					return
				}
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		claims, err := s.authManager.ValidateToken(token)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token, err := s.authManager.Authenticate(r.Context(), req.Username, req.Password, r.RemoteAddr, r.UserAgent())
	if err != nil {
		s.logAudit("login_failed", req.Username, r, false)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	s.logAudit("login_success", req.Username, r, true)

	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	s.authManager.RevokeSession(claims.SessionID)
	s.logAudit("logout", claims.Username, r, true)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if len(token) > 7 {
		token = token[7:]
	}

	newToken, err := s.authManager.RefreshToken(token)
	if err != nil {
		http.Error(w, "Failed to refresh token", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": newToken})
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	s.agentsMu.RLock()
	agents := make([]*models.Agent, 0, len(s.agents))
	for _, ac := range s.agents {
		agents = append(agents, ac.Agent)
	}
	s.agentsMu.RUnlock()

	json.NewEncoder(w).Encode(agents)
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["id"]

	s.agentsMu.RLock()
	ac, ok := s.agents[agentID]
	s.agentsMu.RUnlock()

	if !ok {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(ac.Agent)
}

func (s *Server) handleSendCommand(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["id"]

	var cmdReq struct {
		Type    models.CommandType `json:"type"`
		Payload map[string]any     `json:"payload"`
		Timeout int                `json:"timeout"`
	}

	if err := json.NewDecoder(r.Body).Decode(&cmdReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	claims := r.Context().Value("claims").(*auth.Claims)

	cmd := &models.Command{
		ID:          uuid.New().String(),
		Type:        cmdReq.Type,
		Payload:     cmdReq.Payload,
		TargetAgent: agentID,
		Priority:    1,
		Timeout:     time.Duration(cmdReq.Timeout) * time.Second,
		CreatedAt:   time.Now(),
		CreatedBy:   claims.UserID,
	}

	s.commands <- cmd
	s.logAudit("command_sent", claims.Username, r, true)

	json.NewEncoder(w).Encode(map[string]string{"command_id": cmd.ID})
}

func (s *Server) handleListCommands(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement command history
	json.NewEncoder(w).Encode([]models.Command{})
}

func (s *Server) handleGetCommandResult(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement result retrieval
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// Stream agent updates and command results
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.agentsMu.RLock()
			agents := make([]*models.Agent, 0, len(s.agents))
			for _, ac := range s.agents {
				agents = append(agents, ac.Agent)
			}
			s.agentsMu.RUnlock()

			if err := conn.WriteJSON(map[string]any{"type": "agents", "data": agents}); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	s.agentsMu.RLock()
	totalAgents := len(s.agents)
	onlineAgents := 0
	for _, ac := range s.agents {
		if ac.Agent.Status == models.StatusOnline {
			onlineAgents++
		}
	}
	s.agentsMu.RUnlock()

	stats := map[string]any{
		"total_agents":   totalAgents,
		"online_agents":  onlineAgents,
		"offline_agents": totalAgents - onlineAgents,
		"pending_commands": len(s.commands),
	}

	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "audit:read"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	s.auditMu.RLock()
	logs := make([]models.AuditLog, len(s.auditLogs))
	copy(logs, s.auditLogs)
	s.auditMu.RUnlock()

	json.NewEncoder(w).Encode(logs)
}

func (s *Server) logAudit(action, resource string, r *http.Request, success bool) {
	if !s.config.AuditLog {
		return
	}

	entry := models.AuditLog{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Action:    action,
		Resource:  resource,
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Success:   success,
	}

	if claims, ok := r.Context().Value("claims").(*auth.Claims); ok {
		entry.UserID = claims.UserID
	}

	s.auditMu.Lock()
	s.auditLogs = append(s.auditLogs, entry)
	// Keep only last 10000 entries
	if len(s.auditLogs) > 10000 {
		s.auditLogs = s.auditLogs[1:]
	}
	s.auditMu.Unlock()
}

// SendCommand sends a command to an agent
func (s *Server) SendCommand(cmd *models.Command) {
	s.commands <- cmd
}

// GetAgents returns all connected agents
func (s *Server) GetAgents() []*models.Agent {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()

	agents := make([]*models.Agent, 0, len(s.agents))
	for _, ac := range s.agents {
		agents = append(agents, ac.Agent)
	}
	return agents
}
