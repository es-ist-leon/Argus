package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/argus/argus/internal/auth"
	"github.com/argus/argus/pkg/models"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// ==================== User Management ====================

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "users:read"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Return list of users (without sensitive data)
	users := s.authManager.ListUsers()
	json.NewEncoder(w).Encode(users)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "users:write"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req struct {
		Username string          `json:"username"`
		Email    string          `json:"email"`
		Password string          `json:"password"`
		Role     models.UserRole `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := s.authManager.CreateUser(req.Username, req.Email, req.Password, req.Role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.logAudit("user_created", req.Username, r, true)
	json.NewEncoder(w).Encode(user)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "users:read"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	userID := vars["id"]

	user, err := s.authManager.GetUser(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "users:write"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	userID := vars["id"]

	var req struct {
		Email    string          `json:"email,omitempty"`
		Role     models.UserRole `json:"role,omitempty"`
		Password string          `json:"password,omitempty"`
		Active   *bool           `json:"active,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := s.authManager.UpdateUser(userID, req.Email, req.Role, req.Password, req.Active); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.logAudit("user_updated", userID, r, true)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "users:write"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	userID := vars["id"]

	if err := s.authManager.DeleteUser(userID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.logAudit("user_deleted", userID, r, true)
	w.WriteHeader(http.StatusNoContent)
}

// ==================== Agent Groups ====================

var agentGroups = make(map[string]*models.AgentGroup)

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups := make([]*models.AgentGroup, 0, len(agentGroups))
	for _, g := range agentGroups {
		groups = append(groups, g)
	}
	json.NewEncoder(w).Encode(groups)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "groups:write"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var group models.AgentGroup
	if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	group.ID = uuid.New().String()
	group.CreatedAt = time.Now()
	group.UpdatedAt = time.Now()

	agentGroups[group.ID] = &group

	s.logAudit("group_created", group.Name, r, true)
	json.NewEncoder(w).Encode(group)
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupID := vars["id"]

	group, ok := agentGroups[groupID]
	if !ok {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}

	// Include matching agents
	matchingAgents := s.getAgentsForGroup(group)
	response := map[string]interface{}{
		"group":  group,
		"agents": matchingAgents,
	}

	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "groups:write"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	groupID := vars["id"]

	if _, ok := agentGroups[groupID]; !ok {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}

	delete(agentGroups, groupID)
	s.logAudit("group_deleted", groupID, r, true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSendGroupCommand(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupID := vars["id"]

	group, ok := agentGroups[groupID]
	if !ok {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}

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

	// Send command to all agents in group
	agents := s.getAgentsForGroup(group)
	commandIDs := make([]string, 0, len(agents))

	for _, agent := range agents {
		cmd := &models.Command{
			ID:          uuid.New().String(),
			Type:        cmdReq.Type,
			Payload:     cmdReq.Payload,
			TargetAgent: agent.ID,
			TargetGroup: groupID,
			Priority:    1,
			Timeout:     time.Duration(cmdReq.Timeout) * time.Second,
			CreatedAt:   time.Now(),
			CreatedBy:   claims.UserID,
		}
		s.commands <- cmd
		commandIDs = append(commandIDs, cmd.ID)
	}

	s.logAudit("group_command_sent", groupID, r, true)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"command_ids": commandIDs,
		"agent_count": len(agents),
	})
}

func (s *Server) getAgentsForGroup(group *models.AgentGroup) []*models.Agent {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()

	matching := make([]*models.Agent, 0)
	for _, ac := range s.agents {
		if matchesSelector(ac.Agent.Labels, group.Selector) {
			matching = append(matching, ac.Agent)
		}
	}
	return matching
}

func matchesSelector(labels, selector map[string]string) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

// ==================== Agent Extended ====================

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "agents:write"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	agentID := vars["id"]

	s.agentsMu.Lock()
	ac, ok := s.agents[agentID]
	if ok {
		ac.Conn.Close()
		delete(s.agents, agentID)
	}
	s.agentsMu.Unlock()

	if !ok {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	s.logAudit("agent_disconnected", agentID, r, true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetAgentSysInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["id"]

	// Send system_info command and wait for result
	cmd := &models.Command{
		ID:          uuid.New().String(),
		Type:        models.CmdSystemInfo,
		TargetAgent: agentID,
		Timeout:     30 * time.Second,
		CreatedAt:   time.Now(),
	}

	s.commands <- cmd

	// Return command ID - client should poll for result
	json.NewEncoder(w).Encode(map[string]string{
		"command_id": cmd.ID,
		"status":     "pending",
	})
}

func (s *Server) handleGetAgentProcesses(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["id"]

	cmd := &models.Command{
		ID:          uuid.New().String(),
		Type:        models.CmdProcessList,
		TargetAgent: agentID,
		Timeout:     30 * time.Second,
		CreatedAt:   time.Now(),
	}

	s.commands <- cmd

	json.NewEncoder(w).Encode(map[string]string{
		"command_id": cmd.ID,
		"status":     "pending",
	})
}

// ==================== Commands Extended ====================

func (s *Server) handleGetCommand(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	commandID := vars["id"]

	if s.store != nil {
		cmd, ok := s.store.GetCommand(commandID)
		if ok {
			json.NewEncoder(w).Encode(cmd)
			return
		}
	}

	http.Error(w, "Command not found", http.StatusNotFound)
}

// ==================== Scheduled Tasks ====================

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	if s.scheduler == nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	tasks := s.scheduler.ListTasks()
	json.NewEncoder(w).Encode(tasks)
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "tasks:write"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var task ScheduledTask
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	task.CreatedBy = claims.UserID

	if s.scheduler == nil {
		s.scheduler = NewScheduler(s.commands, "data")
		s.scheduler.Start()
	}

	if err := s.scheduler.AddTask(&task); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.logAudit("task_created", task.Name, r, true)
	json.NewEncoder(w).Encode(task)
}

func (s *Server) handleGetTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["id"]

	if s.scheduler == nil {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	task, ok := s.scheduler.GetTask(taskID)
	if !ok {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(task)
}

func (s *Server) handleUpdateTask(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "tasks:write"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	taskID := vars["id"]

	var task ScheduledTask
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	task.ID = taskID

	if s.scheduler == nil || !s.scheduler.UpdateTask(&task) {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	s.logAudit("task_updated", taskID, r, true)
	json.NewEncoder(w).Encode(task)
}

func (s *Server) handleDeleteTask(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "tasks:write"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	taskID := vars["id"]

	if s.scheduler == nil || !s.scheduler.RemoveTask(taskID) {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	s.logAudit("task_deleted", taskID, r, true)
	w.WriteHeader(http.StatusNoContent)
}

// ==================== File Transfer ====================

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["id"]
	path := r.URL.Query().Get("path")

	if path == "" {
		path = "/"
	}

	cmd := &models.Command{
		ID:          uuid.New().String(),
		Type:        models.CmdFileTransfer,
		TargetAgent: agentID,
		Payload: map[string]any{
			"operation":   "list",
			"remote_path": path,
		},
		Timeout:   30 * time.Second,
		CreatedAt: time.Now(),
	}

	s.commands <- cmd

	json.NewEncoder(w).Encode(map[string]string{
		"command_id": cmd.ID,
		"status":     "pending",
	})
}

func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["id"]

	var req struct {
		RemotePath string `json:"remote_path"`
		Content    string `json:"content"` // base64 encoded
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	transferID := uuid.New().String()
	// Calculate chunks based on content size
	contentSize := len(req.Content)
	chunkSize := 64 * 1024
	totalChunks := (contentSize + chunkSize - 1) / chunkSize

	// Init upload
	cmd := &models.Command{
		ID:          uuid.New().String(),
		Type:        models.CmdFileTransfer,
		TargetAgent: agentID,
		Payload: map[string]any{
			"operation":    "init_upload",
			"transfer_id":  transferID,
			"remote_path":  req.RemotePath,
			"total_size":   float64(contentSize),
			"total_chunks": float64(totalChunks),
		},
		Timeout:   5 * time.Minute,
		CreatedAt: time.Now(),
	}

	s.commands <- cmd

	claims := r.Context().Value("claims").(*auth.Claims)
	s.logAudit("file_upload", req.RemotePath, r, true)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"transfer_id":  transferID,
		"command_id":   cmd.ID,
		"total_chunks": totalChunks,
		"status":       "initiated",
		"user":         claims.Username,
	})
}

func (s *Server) handleDownloadFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["id"]

	var req struct {
		RemotePath string `json:"remote_path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	transferID := uuid.New().String()

	cmd := &models.Command{
		ID:          uuid.New().String(),
		Type:        models.CmdFileTransfer,
		TargetAgent: agentID,
		Payload: map[string]any{
			"operation":   "init_download",
			"transfer_id": transferID,
			"local_path":  req.RemotePath,
		},
		Timeout:   5 * time.Minute,
		CreatedAt: time.Now(),
	}

	s.commands <- cmd

	claims := r.Context().Value("claims").(*auth.Claims)
	s.logAudit("file_download", req.RemotePath, r, true)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"transfer_id": transferID,
		"command_id":  cmd.ID,
		"status":      "initiated",
		"user":        claims.Username,
	})
}

// ==================== Metrics & Health ====================

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	if err := s.authManager.AuthorizeAction(claims, "metrics:read"); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if s.metrics != nil {
		stats := s.metrics.GetStats()
		json.NewEncoder(w).Encode(stats)
	} else {
		json.NewEncoder(w).Encode(map[string]string{"status": "metrics not enabled"})
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.agentsMu.RLock()
	agentCount := len(s.agents)
	s.agentsMu.RUnlock()

	health := map[string]interface{}{
		"status":       "healthy",
		"agent_count":  agentCount,
		"api_version":  "v1",
		"server_time":  time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// handleIndex serves the main HTML page
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Don't serve index for API routes
	if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
		http.NotFound(w, r)
		return
	}

	http.ServeFile(w, r, "web/templates/index.html")
}
