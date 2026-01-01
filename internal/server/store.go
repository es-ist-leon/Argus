package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/argus/argus/pkg/models"
)

// Store provides persistent storage for commands and results
type Store struct {
	mu           sync.RWMutex
	commands     map[string]*models.Command
	results      map[string]*models.CommandResult
	commandQueue []*models.Command
	dataDir      string
	maxHistory   int
}

// NewStore creates a new store instance
func NewStore(dataDir string) *Store {
	if dataDir == "" {
		dataDir = "data"
	}
	os.MkdirAll(dataDir, 0755)

	s := &Store{
		commands:     make(map[string]*models.Command),
		results:      make(map[string]*models.CommandResult),
		commandQueue: make([]*models.Command, 0),
		dataDir:      dataDir,
		maxHistory:   10000,
	}

	s.loadFromDisk()
	return s
}

// SaveCommand stores a command
func (s *Store) SaveCommand(cmd *models.Command) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.commands[cmd.ID] = cmd
	s.commandQueue = append(s.commandQueue, cmd)

	// Trim history
	if len(s.commandQueue) > s.maxHistory {
		old := s.commandQueue[0]
		delete(s.commands, old.ID)
		delete(s.results, old.ID)
		s.commandQueue = s.commandQueue[1:]
	}
}

// GetCommand retrieves a command by ID
func (s *Store) GetCommand(id string) (*models.Command, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cmd, ok := s.commands[id]
	return cmd, ok
}

// SaveResult stores a command result
func (s *Store) SaveResult(result *models.CommandResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[result.CommandID] = result
}

// GetResult retrieves a result by command ID
func (s *Store) GetResult(commandID string) (*models.CommandResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result, ok := s.results[commandID]
	return result, ok
}

// GetCommandHistory returns recent commands with optional filters
func (s *Store) GetCommandHistory(agentID string, cmdType models.CommandType, limit int) []*models.Command {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.commandQueue) {
		limit = len(s.commandQueue)
	}

	result := make([]*models.Command, 0, limit)
	count := 0

	// Iterate from newest to oldest
	for i := len(s.commandQueue) - 1; i >= 0 && count < limit; i-- {
		cmd := s.commandQueue[i]
		if agentID != "" && cmd.TargetAgent != agentID {
			continue
		}
		if cmdType != "" && cmd.Type != cmdType {
			continue
		}
		result = append(result, cmd)
		count++
	}

	return result
}

// GetPendingResults returns commands without results
func (s *Store) GetPendingResults(agentID string) []*models.Command {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pending := make([]*models.Command, 0)
	for _, cmd := range s.commandQueue {
		if agentID != "" && cmd.TargetAgent != agentID {
			continue
		}
		if _, hasResult := s.results[cmd.ID]; !hasResult {
			pending = append(pending, cmd)
		}
	}
	return pending
}

// GetResultsForAgent returns all results for an agent
func (s *Store) GetResultsForAgent(agentID string, limit int) []*models.CommandResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*models.CommandResult, 0)
	for _, result := range s.results {
		if result.AgentID == agentID {
			results = append(results, result)
			if limit > 0 && len(results) >= limit {
				break
			}
		}
	}
	return results
}

// Stats returns store statistics
func (s *Store) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pending := 0
	successful := 0
	failed := 0

	for _, cmd := range s.commands {
		if result, ok := s.results[cmd.ID]; ok {
			if result.Success {
				successful++
			} else {
				failed++
			}
		} else {
			pending++
		}
	}

	return map[string]int{
		"total_commands":      len(s.commands),
		"total_results":       len(s.results),
		"pending_commands":    pending,
		"successful_commands": successful,
		"failed_commands":     failed,
	}
}

// Persist saves data to disk
func (s *Store) Persist() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Save commands
	cmdFile := filepath.Join(s.dataDir, "commands.json")
	cmdData, err := json.MarshalIndent(s.commandQueue, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(cmdFile, cmdData, 0644); err != nil {
		return err
	}

	// Save results
	resultFile := filepath.Join(s.dataDir, "results.json")
	resultData, err := json.MarshalIndent(s.results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(resultFile, resultData, 0644)
}

func (s *Store) loadFromDisk() {
	// Load commands
	cmdFile := filepath.Join(s.dataDir, "commands.json")
	if data, err := os.ReadFile(cmdFile); err == nil {
		var commands []*models.Command
		if json.Unmarshal(data, &commands) == nil {
			for _, cmd := range commands {
				s.commands[cmd.ID] = cmd
			}
			s.commandQueue = commands
		}
	}

	// Load results
	resultFile := filepath.Join(s.dataDir, "results.json")
	if data, err := os.ReadFile(resultFile); err == nil {
		json.Unmarshal(data, &s.results)
	}
}

// FileTransfer represents an in-progress file transfer
type FileTransfer struct {
	ID          string
	AgentID     string
	Operation   string // "upload" or "download"
	LocalPath   string
	RemotePath  string
	TotalSize   int64
	Transferred int64
	ChunkSize   int
	Checksum    string
	StartedAt   time.Time
	Status      string
	Error       string
	Chunks      map[int][]byte
	TotalChunks int
}

// FileTransferStore manages file transfers
type FileTransferStore struct {
	mu        sync.RWMutex
	transfers map[string]*FileTransfer
}

// NewFileTransferStore creates a new file transfer store
func NewFileTransferStore() *FileTransferStore {
	return &FileTransferStore{
		transfers: make(map[string]*FileTransfer),
	}
}

// Create creates a new file transfer
func (fts *FileTransferStore) Create(ft *FileTransfer) {
	fts.mu.Lock()
	defer fts.mu.Unlock()
	ft.Chunks = make(map[int][]byte)
	fts.transfers[ft.ID] = ft
}

// Get retrieves a file transfer
func (fts *FileTransferStore) Get(id string) (*FileTransfer, bool) {
	fts.mu.RLock()
	defer fts.mu.RUnlock()
	ft, ok := fts.transfers[id]
	return ft, ok
}

// AddChunk adds a chunk to a transfer
func (fts *FileTransferStore) AddChunk(id string, index int, data []byte) bool {
	fts.mu.Lock()
	defer fts.mu.Unlock()

	ft, ok := fts.transfers[id]
	if !ok {
		return false
	}

	ft.Chunks[index] = data
	ft.Transferred += int64(len(data))

	// Check if complete
	if len(ft.Chunks) == ft.TotalChunks {
		ft.Status = "complete"
	}

	return true
}

// GetChunks returns all chunks for assembly
func (fts *FileTransferStore) GetChunks(id string) ([][]byte, bool) {
	fts.mu.RLock()
	defer fts.mu.RUnlock()

	ft, ok := fts.transfers[id]
	if !ok {
		return nil, false
	}

	chunks := make([][]byte, ft.TotalChunks)
	for i := 0; i < ft.TotalChunks; i++ {
		chunk, ok := ft.Chunks[i]
		if !ok {
			return nil, false
		}
		chunks[i] = chunk
	}
	return chunks, true
}

// Delete removes a file transfer
func (fts *FileTransferStore) Delete(id string) {
	fts.mu.Lock()
	defer fts.mu.Unlock()
	delete(fts.transfers, id)
}

// ListForAgent returns all transfers for an agent
func (fts *FileTransferStore) ListForAgent(agentID string) []*FileTransfer {
	fts.mu.RLock()
	defer fts.mu.RUnlock()

	transfers := make([]*FileTransfer, 0)
	for _, ft := range fts.transfers {
		if ft.AgentID == agentID {
			transfers = append(transfers, ft)
		}
	}
	return transfers
}
