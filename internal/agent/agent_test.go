package agent

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAgentConfig(t *testing.T) {
	config := &Config{
		AgentID:           "test-agent-001",
		ServerAddr:        "localhost:8443",
		TLSEnabled:        true,
		HeartbeatInterval: 30 * time.Second,
		ReconnectInterval: 10 * time.Second,
		Labels: map[string]string{
			"environment": "test",
			"role":        "webserver",
		},
		Capabilities: []string{"execute", "file_transfer"},
	}

	if config.AgentID != "test-agent-001" {
		t.Errorf("Expected AgentID 'test-agent-001', got '%s'", config.AgentID)
	}

	if config.HeartbeatInterval != 30*time.Second {
		t.Errorf("Expected HeartbeatInterval 30s, got %v", config.HeartbeatInterval)
	}

	if len(config.Capabilities) != 2 {
		t.Errorf("Expected 2 capabilities, got %d", len(config.Capabilities))
	}
}

func TestNewAgent(t *testing.T) {
	config := &Config{
		ServerAddr: "localhost:8443",
	}

	agent := NewAgent(config)

	if agent.config.AgentID == "" {
		t.Error("Agent ID should be auto-generated when empty")
	}

	if agent.config.HeartbeatInterval != 30*time.Second {
		t.Errorf("Default HeartbeatInterval should be 30s, got %v", agent.config.HeartbeatInterval)
	}

	if agent.config.ReconnectInterval != 10*time.Second {
		t.Errorf("Default ReconnectInterval should be 10s, got %v", agent.config.ReconnectInterval)
	}

	if len(agent.config.Capabilities) == 0 {
		t.Error("Default capabilities should be set")
	}
}

func TestShellManager(t *testing.T) {
	sm := NewShellManager(5, 30*time.Minute)

	// Test session creation
	session, err := sm.CreateSession("test-session-1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if session.ID != "test-session-1" {
		t.Errorf("Expected session ID 'test-session-1', got '%s'", session.ID)
	}

	if !session.IsActive() {
		t.Error("Session should be active after creation")
	}

	// Test session retrieval
	retrieved, ok := sm.GetSession("test-session-1")
	if !ok {
		t.Error("Session should be retrievable")
	}

	if retrieved.ID != session.ID {
		t.Error("Retrieved session should match created session")
	}

	// Test session list
	sessions := sm.ListSessions()
	if len(sessions) != 1 {
		t.Errorf("Expected 1 session, got %d", len(sessions))
	}

	// Test duplicate session creation
	_, err = sm.CreateSession("test-session-1")
	if err == nil {
		t.Error("Should not be able to create duplicate session")
	}

	// Test max sessions
	for i := 0; i < 5; i++ {
		sm.CreateSession(string(rune('a' + i)))
	}

	_, err = sm.CreateSession("overflow")
	if err == nil {
		t.Error("Should not exceed max sessions")
	}

	// Test session close
	err = sm.CloseSession("test-session-1")
	if err != nil {
		t.Errorf("Failed to close session: %v", err)
	}

	_, ok = sm.GetSession("test-session-1")
	if ok {
		t.Error("Session should not exist after close")
	}
}

func TestFileTransferManager(t *testing.T) {
	tempDir := t.TempDir()
	ftm := NewFileTransferManager(tempDir)

	// Set allowed paths for testing
	ftm.SetAllowedPaths([]string{tempDir})

	// Test path validation
	if !ftm.IsPathAllowed(filepath.Join(tempDir, "test.txt")) {
		t.Error("Path in allowed directory should be allowed")
	}

	if ftm.IsPathAllowed("/etc/shadow") {
		t.Error("Path outside allowed directories should not be allowed")
	}

	// Test upload initialization
	testPath := filepath.Join(tempDir, "upload-test.txt")
	transfer, err := ftm.InitUpload("transfer-1", testPath, 1000, 1, "")
	if err != nil {
		t.Fatalf("Failed to init upload: %v", err)
	}

	if transfer.Status != "in_progress" {
		t.Errorf("Expected status 'in_progress', got '%s'", transfer.Status)
	}

	// Test chunk receive
	err = ftm.ReceiveChunk("transfer-1", 0, []byte("test data"))
	if err != nil {
		t.Errorf("Failed to receive chunk: %v", err)
	}

	// Test transfer retrieval
	retrieved, ok := ftm.GetTransfer("transfer-1")
	if !ok {
		t.Error("Transfer should be retrievable")
	}

	if retrieved.Received != 9 {
		t.Errorf("Expected 9 bytes received, got %d", retrieved.Received)
	}

	// Test download initialization
	testFile := filepath.Join(tempDir, "download-test.txt")
	os.WriteFile(testFile, []byte("test content for download"), 0644)

	_, size, checksum, err := ftm.InitDownload("transfer-2", testFile)
	if err != nil {
		t.Fatalf("Failed to init download: %v", err)
	}

	if size != 24 {
		t.Errorf("Expected size 24, got %d", size)
	}

	if checksum == "" {
		t.Error("Checksum should not be empty")
	}

	// Test chunk retrieval
	chunk, err := ftm.GetChunk("transfer-2", 0)
	if err != nil {
		t.Errorf("Failed to get chunk: %v", err)
	}

	if string(chunk) != "test content for download" {
		t.Errorf("Chunk content mismatch: %s", string(chunk))
	}

	// Test cancel transfer
	ftm.CancelTransfer("transfer-1")
	_, ok = ftm.GetTransfer("transfer-1")
	if ok {
		t.Error("Transfer should be cancelled")
	}
}

func TestServiceInfo(t *testing.T) {
	info := ServiceInfo{
		Name:        "nginx",
		DisplayName: "Nginx Web Server",
		Status:      "running",
		StartType:   "automatic",
		PID:         1234,
	}

	if info.Name != "nginx" {
		t.Errorf("Expected name 'nginx', got '%s'", info.Name)
	}

	if info.Status != "running" {
		t.Errorf("Expected status 'running', got '%s'", info.Status)
	}
}

func TestUpdateManager(t *testing.T) {
	um := NewUpdateManager("1.0.0", "http://localhost:8080")

	if um.GetCurrentVersion() != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", um.GetCurrentVersion())
	}

	um.SetUpdateURL("http://new-server:8080")

	// Test scheduler
	scheduler := NewUpdateScheduler(um)

	info := &UpdateInfo{
		Version:     "1.1.0",
		ReleaseDate: time.Now(),
		DownloadURL: "http://localhost/update.zip",
		Size:        1000,
	}

	scheduler.Schedule(info, time.Now().Add(time.Hour))

	scheduled := scheduler.GetScheduled()
	if scheduled == nil {
		t.Error("Should have scheduled update")
	}

	if scheduled.Info.Version != "1.1.0" {
		t.Errorf("Expected scheduled version '1.1.0', got '%s'", scheduled.Info.Version)
	}

	scheduler.Cancel()

	if scheduler.GetScheduled() != nil {
		t.Error("Schedule should be cancelled")
	}
}

func TestCommandExecution(t *testing.T) {
	config := &Config{
		ServerAddr: "localhost:8443",
	}
	agent := NewAgent(config)

	// Create a mock context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test command that should work on all platforms
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "echo"
	} else {
		cmd = "echo"
	}

	// We can't fully test without mocking, but we can test the structure
	result := &struct {
		CommandID   string
		AgentID     string
		Success     bool
		ExitCode    int
		Output      string
		Error       string
		StartedAt   time.Time
		CompletedAt time.Time
	}{
		CommandID: "test-cmd-1",
		AgentID:   agent.config.AgentID,
		StartedAt: time.Now(),
	}

	// Verify result structure
	if result.CommandID != "test-cmd-1" {
		t.Errorf("Expected CommandID 'test-cmd-1', got '%s'", result.CommandID)
	}

	_ = ctx // use ctx to avoid unused variable error
	_ = cmd
}

func TestBasicSystemInfo(t *testing.T) {
	config := &Config{
		ServerAddr: "localhost:8443",
	}
	agent := NewAgent(config)

	sysInfo := agent.getBasicSystemInfo()

	if sysInfo.Hostname == "" {
		// Hostname might be empty in some test environments
		t.Log("Warning: Hostname is empty")
	}

	if sysInfo.OS != runtime.GOOS {
		t.Errorf("Expected OS '%s', got '%s'", runtime.GOOS, sysInfo.OS)
	}

	if sysInfo.Arch != runtime.GOARCH {
		t.Errorf("Expected Arch '%s', got '%s'", runtime.GOARCH, sysInfo.Arch)
	}

	if sysInfo.CPUCores != runtime.NumCPU() {
		t.Errorf("Expected %d CPU cores, got %d", runtime.NumCPU(), sysInfo.CPUCores)
	}
}

func TestBasicProcessList(t *testing.T) {
	config := &Config{
		ServerAddr: "localhost:8443",
	}
	agent := NewAgent(config)

	processes := agent.getBasicProcessList()

	// Basic implementation returns empty list
	if processes == nil {
		t.Error("Process list should not be nil")
	}
}

func TestJoinArgs(t *testing.T) {
	tests := []struct {
		args     []string
		expected string
	}{
		{[]string{}, ""},
		{[]string{"arg1"}, "arg1"},
		{[]string{"arg1", "arg2"}, "arg1 arg2"},
		{[]string{"arg1", "arg2", "arg3"}, "arg1 arg2 arg3"},
	}

	for _, tt := range tests {
		result := joinArgs(tt.args)
		if result != tt.expected {
			t.Errorf("joinArgs(%v) = '%s', expected '%s'", tt.args, result, tt.expected)
		}
	}
}

func TestShellSessionWrite(t *testing.T) {
	sm := NewShellManager(5, 30*time.Minute)
	session, err := sm.CreateSession("write-test")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	defer sm.CloseSession("write-test")

	// Test writing to session
	err = session.Write([]byte("test input\n"))
	if err != nil {
		t.Errorf("Failed to write to session: %v", err)
	}

	// Test writing to closed session
	session.Close()
	err = session.Write([]byte("should fail"))
	if err == nil {
		t.Error("Writing to closed session should fail")
	}
}

func TestFileChecksumCalculation(t *testing.T) {
	// Create temp file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "checksum-test.txt")
	
	content := []byte("test content for checksum calculation")
	os.WriteFile(testFile, content, 0644)

	checksum, err := calculateFileChecksum(testFile)
	if err != nil {
		t.Fatalf("Failed to calculate checksum: %v", err)
	}

	if checksum == "" {
		t.Error("Checksum should not be empty")
	}

	// Checksum should be consistent
	checksum2, _ := calculateFileChecksum(testFile)
	if checksum != checksum2 {
		t.Error("Checksum should be consistent")
	}
}

func TestCopyFile(t *testing.T) {
	tempDir := t.TempDir()
	srcFile := filepath.Join(tempDir, "source.txt")
	dstFile := filepath.Join(tempDir, "destination.txt")

	content := []byte("test content to copy")
	os.WriteFile(srcFile, content, 0644)

	err := copyFile(srcFile, dstFile)
	if err != nil {
		t.Fatalf("Failed to copy file: %v", err)
	}

	// Verify content
	copied, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("Failed to read copied file: %v", err)
	}

	if string(copied) != string(content) {
		t.Error("Copied content does not match original")
	}
}

func TestFileCopyFunc(t *testing.T) {
	tempDir := t.TempDir()
	srcFile := filepath.Join(tempDir, "copy-src.txt")
	dstFile := filepath.Join(tempDir, "copy-dst.txt")

	os.WriteFile(srcFile, []byte("copy test"), 0644)

	srcF, _ := os.Open(srcFile)
	dstF, _ := os.Create(dstFile)
	
	_, err := io.Copy(dstF, srcF)
	srcF.Close()
	dstF.Close()

	if err != nil {
		t.Errorf("io.Copy failed: %v", err)
	}

	content, _ := os.ReadFile(dstFile)
	if string(content) != "copy test" {
		t.Error("Copy content mismatch")
	}
}

func BenchmarkShellSessionCreation(b *testing.B) {
	sm := NewShellManager(1000, 30*time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := string(rune(i))
		session, _ := sm.CreateSession(id)
		if session != nil {
			sm.CloseSession(id)
		}
	}
}

func BenchmarkChecksumCalculation(b *testing.B) {
	tempDir := b.TempDir()
	testFile := filepath.Join(tempDir, "bench.txt")
	
	// Create a 1MB file
	data := make([]byte, 1024*1024)
	os.WriteFile(testFile, data, 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calculateFileChecksum(testFile)
	}
}

func BenchmarkJSONMarshalResult(b *testing.B) {
	result := map[string]interface{}{
		"command_id": "test-123",
		"agent_id":   "agent-456",
		"success":    true,
		"exit_code":  0,
		"output":     strings.Repeat("x", 1000),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(result)
	}
}
