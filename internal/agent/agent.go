package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/argus/argus/internal/protocol"
	"github.com/argus/argus/pkg/models"
	"github.com/google/uuid"
)

// Config holds agent configuration
type Config struct {
	AgentID           string            `yaml:"agent_id"`
	ServerAddr        string            `yaml:"server_addr"`
	TLSEnabled        bool              `yaml:"tls_enabled"`
	TLSCACert         string            `yaml:"tls_ca_cert"`
	TLSCert           string            `yaml:"tls_cert"`
	TLSKey            string            `yaml:"tls_key"`
	TLSInsecure       bool              `yaml:"tls_insecure"`
	HeartbeatInterval time.Duration     `yaml:"heartbeat_interval"`
	ReconnectInterval time.Duration     `yaml:"reconnect_interval"`
	Labels            map[string]string `yaml:"labels"`
	Capabilities      []string          `yaml:"capabilities"`
}

// Agent represents the remote agent
type Agent struct {
	config    *Config
	conn      net.Conn
	connected bool
	sequence  uint32
	sendQueue chan *protocol.Message
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.Mutex

	// System info cache
	sysInfo     *models.SystemInfo
	sysInfoTime time.Time

	// Native module interface
	nativeModule NativeModule
}

// NativeModule interface for C++ native components
type NativeModule interface {
	GetSystemInfo() (*models.SystemInfo, error)
	GetProcessList() ([]models.ProcessInfo, error)
	KillProcess(pid int32) error
	ExecuteCommand(cmd string, args []string, timeout time.Duration) (string, int, error)
}

// NewAgent creates a new agent instance
func NewAgent(config *Config) *Agent {
	if config.AgentID == "" {
		config.AgentID = uuid.New().String()
	}

	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 30 * time.Second
	}

	if config.ReconnectInterval == 0 {
		config.ReconnectInterval = 10 * time.Second
	}

	if config.Capabilities == nil {
		config.Capabilities = []string{
			"execute", "file_transfer", "system_info",
			"process_list", "process_kill", "shell_session",
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Agent{
		config:    config,
		sendQueue: make(chan *protocol.Message, 100),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// SetNativeModule sets the native C++ module
func (a *Agent) SetNativeModule(nm NativeModule) {
	a.nativeModule = nm
}

// Start starts the agent
func (a *Agent) Start() error {
	log.Printf("Argus Agent starting (ID: %s)", a.config.AgentID)

	a.wg.Add(1)
	go a.connectionLoop()

	return nil
}

// Stop stops the agent
func (a *Agent) Stop() {
	log.Println("Stopping agent...")
	a.cancel()

	a.mu.Lock()
	if a.conn != nil {
		// Send disconnect message
		msg, _ := protocol.NewMessage(protocol.MsgTypeDisconnect, nil, a.sequence)
		a.conn.Write(msg.Encode())
		a.conn.Close()
	}
	a.mu.Unlock()

	a.wg.Wait()
	log.Println("Agent stopped")
}

func (a *Agent) connectionLoop() {
	defer a.wg.Done()

	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}

		if err := a.connect(); err != nil {
			log.Printf("Connection failed: %v, retrying in %v", err, a.config.ReconnectInterval)
			time.Sleep(a.config.ReconnectInterval)
			continue
		}

		a.run()

		// Connection lost, reconnect
		log.Println("Connection lost, reconnecting...")
		time.Sleep(a.config.ReconnectInterval)
	}
}

func (a *Agent) connect() error {
	var conn net.Conn
	var err error

	if a.config.TLSEnabled {
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: a.config.TLSInsecure,
		}

		if a.config.TLSCACert != "" {
			caCert, err := os.ReadFile(a.config.TLSCACert)
			if err != nil {
				return fmt.Errorf("failed to read CA cert: %w", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		}

		if a.config.TLSCert != "" && a.config.TLSKey != "" {
			cert, err := tls.LoadX509KeyPair(a.config.TLSCert, a.config.TLSKey)
			if err != nil {
				return fmt.Errorf("failed to load client cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		conn, err = tls.Dial("tcp", a.config.ServerAddr, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", a.config.ServerAddr, 30*time.Second)
	}

	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	a.mu.Lock()
	a.conn = conn
	a.connected = true
	a.sequence = 1
	a.mu.Unlock()

	// Send handshake
	hostname, _ := os.Hostname()
	msg, err := protocol.NewHandshake(
		a.config.AgentID,
		hostname,
		runtime.GOOS,
		runtime.GOARCH,
		"1.0.0",
		a.config.Capabilities,
		a.config.Labels,
		nil,
		a.sequence,
	)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create handshake: %w", err)
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(msg.Encode()); err != nil {
		conn.Close()
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	// Wait for acknowledgment
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	ackMsg, err := protocol.DecodeMessage(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to receive ack: %w", err)
	}

	if ackMsg.Header.Type != protocol.MsgTypeAck {
		conn.Close()
		return fmt.Errorf("unexpected response type: %d", ackMsg.Header.Type)
	}

	a.sequence++
	log.Printf("Connected to server: %s", a.config.ServerAddr)
	return nil
}

func (a *Agent) run() {
	// Start send loop
	a.wg.Add(1)
	go a.sendLoop()

	// Start heartbeat
	a.wg.Add(1)
	go a.heartbeatLoop()

	// Main receive loop
	a.receiveLoop()

	// Signal disconnection
	a.mu.Lock()
	a.connected = false
	a.mu.Unlock()
}

func (a *Agent) sendLoop() {
	defer a.wg.Done()

	for {
		select {
		case <-a.ctx.Done():
			return
		case msg := <-a.sendQueue:
			a.mu.Lock()
			if a.connected && a.conn != nil {
				a.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := a.conn.Write(msg.Encode()); err != nil {
					log.Printf("Send error: %v", err)
					a.connected = false
				}
			}
			a.mu.Unlock()
			if !a.connected {
				return
			}
		}
	}
}

func (a *Agent) heartbeatLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.mu.Lock()
			connected := a.connected
			a.mu.Unlock()

			if !connected {
				return
			}

			cpuUsage, memUsage, diskUsage := a.getResourceUsage()

			msg, err := protocol.NewHeartbeat(
				a.config.AgentID,
				cpuUsage,
				memUsage,
				diskUsage,
				string(models.StatusOnline),
				a.sequence,
			)
			if err != nil {
				continue
			}

			a.mu.Lock()
			a.sequence++
			a.mu.Unlock()

			a.sendQueue <- msg
		}
	}
}

func (a *Agent) receiveLoop() {
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}

		a.mu.Lock()
		conn := a.conn
		connected := a.connected
		a.mu.Unlock()

		if !connected || conn == nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(a.config.HeartbeatInterval * 3))
		msg, err := protocol.DecodeMessage(conn)
		if err != nil {
			log.Printf("Receive error: %v", err)
			return
		}

		a.handleMessage(msg)
	}
}

func (a *Agent) handleMessage(msg *protocol.Message) {
	switch msg.Header.Type {
	case protocol.MsgTypeCommand:
		var cmd protocol.CommandPayload
		if err := msg.DecodePayload(&cmd); err != nil {
			log.Printf("Failed to decode command: %v", err)
			return
		}
		go a.executeCommand(&cmd)

	case protocol.MsgTypeDisconnect:
		log.Println("Server requested disconnect")
		a.mu.Lock()
		a.connected = false
		a.mu.Unlock()
	}
}

func (a *Agent) executeCommand(cmd *protocol.CommandPayload) {
	log.Printf("Executing command: %s (%s)", cmd.CommandID, cmd.Type)

	result := &models.CommandResult{
		CommandID: cmd.CommandID,
		AgentID:   a.config.AgentID,
		StartedAt: time.Now(),
	}

	timeout := time.Duration(cmd.Timeout) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	ctx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()

	switch cmd.Type {
	case models.CmdExecute:
		a.handleExecute(ctx, cmd, result)

	case models.CmdSystemInfo:
		a.handleSystemInfo(result)

	case models.CmdProcessList:
		a.handleProcessList(result)

	case models.CmdProcessKill:
		a.handleProcessKill(cmd, result)

	default:
		result.Success = false
		result.Error = fmt.Sprintf("unsupported command type: %s", cmd.Type)
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)

	// Send result
	msg, err := protocol.NewResult(result, a.sequence)
	if err != nil {
		log.Printf("Failed to create result message: %v", err)
		return
	}

	a.mu.Lock()
	a.sequence++
	a.mu.Unlock()

	a.sendQueue <- msg
}

func (a *Agent) handleExecute(ctx context.Context, cmd *protocol.CommandPayload, result *models.CommandResult) {
	command, ok := cmd.Payload["command"].(string)
	if !ok {
		result.Success = false
		result.Error = "missing command parameter"
		return
	}

	var args []string
	if argsRaw, ok := cmd.Payload["args"].([]interface{}); ok {
		for _, arg := range argsRaw {
			if s, ok := arg.(string); ok {
				args = append(args, s)
			}
		}
	}

	// Use native module if available
	if a.nativeModule != nil {
		output, exitCode, err := a.nativeModule.ExecuteCommand(command, args, time.Duration(cmd.Timeout)*time.Second)
		result.Output = output
		result.ExitCode = exitCode
		if err != nil {
			result.Error = err.Error()
			result.Success = false
		} else {
			result.Success = exitCode == 0
		}
		return
	}

	// Fallback to Go implementation
	var execCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		fullCmd := command
		if len(args) > 0 {
			fullCmd = command + " " + joinArgs(args)
		}
		execCmd = exec.CommandContext(ctx, "cmd", "/C", fullCmd)
	} else {
		execCmd = exec.CommandContext(ctx, command, args...)
	}

	output, err := execCmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.Error = err.Error()
		result.Success = false
	} else {
		result.ExitCode = 0
		result.Success = true
	}
}

func (a *Agent) handleSystemInfo(result *models.CommandResult) {
	var sysInfo *models.SystemInfo
	var err error

	if a.nativeModule != nil {
		sysInfo, err = a.nativeModule.GetSystemInfo()
	} else {
		sysInfo = a.getBasicSystemInfo()
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return
	}

	data, _ := json.Marshal(sysInfo)
	result.Output = string(data)
	result.Success = true
	result.ExitCode = 0
}

func (a *Agent) handleProcessList(result *models.CommandResult) {
	var processes []models.ProcessInfo
	var err error

	if a.nativeModule != nil {
		processes, err = a.nativeModule.GetProcessList()
	} else {
		processes = a.getBasicProcessList()
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return
	}

	data, _ := json.Marshal(processes)
	result.Output = string(data)
	result.Success = true
	result.ExitCode = 0
}

func (a *Agent) handleProcessKill(cmd *protocol.CommandPayload, result *models.CommandResult) {
	pidFloat, ok := cmd.Payload["pid"].(float64)
	if !ok {
		result.Success = false
		result.Error = "missing pid parameter"
		return
	}
	pid := int32(pidFloat)

	var err error
	if a.nativeModule != nil {
		err = a.nativeModule.KillProcess(pid)
	} else {
		proc, findErr := os.FindProcess(int(pid))
		if findErr != nil {
			err = findErr
		} else {
			err = proc.Kill()
		}
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return
	}

	result.Success = true
	result.ExitCode = 0
	result.Output = fmt.Sprintf("Process %d killed", pid)
}

func (a *Agent) getResourceUsage() (cpu, mem, disk float64) {
	// Basic implementation - native module provides better accuracy
	if a.nativeModule != nil {
		sysInfo, err := a.nativeModule.GetSystemInfo()
		if err == nil {
			cpu = sysInfo.CPUUsage
			if sysInfo.MemoryTotal > 0 {
				mem = float64(sysInfo.MemoryUsed) / float64(sysInfo.MemoryTotal) * 100
			}
			if len(sysInfo.DiskInfo) > 0 {
				disk = sysInfo.DiskInfo[0].UsedPct
			}
		}
	}
	return
}

func (a *Agent) getBasicSystemInfo() *models.SystemInfo {
	hostname, _ := os.Hostname()
	return &models.SystemInfo{
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		CPUCores:  runtime.NumCPU(),
		BootTime:  time.Now().Add(-time.Duration(runtime.NumCPU()) * time.Hour), // Placeholder
	}
}

func (a *Agent) getBasicProcessList() []models.ProcessInfo {
	// Basic implementation - native module provides full details
	return []models.ProcessInfo{}
}

func joinArgs(args []string) string {
	result := ""
	for i, arg := range args {
		if i > 0 {
			result += " "
		}
		result += arg
	}
	return result
}
