package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/argus/argus/pkg/models"
)

func TestMessageCreation(t *testing.T) {
	payload := map[string]string{"key": "value"}

	msg, err := NewMessage(MsgTypeCommand, payload, 1)
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	if msg.Header.Type != MsgTypeCommand {
		t.Errorf("Expected type %d, got %d", MsgTypeCommand, msg.Header.Type)
	}

	if msg.Header.Sequence != 1 {
		t.Errorf("Expected sequence 1, got %d", msg.Header.Sequence)
	}

	if msg.Header.Version != ProtocolVersion {
		t.Errorf("Expected version %d, got %d", ProtocolVersion, msg.Header.Version)
	}
}

func TestMessageEncodeDecode(t *testing.T) {
	payload := HandshakePayload{
		AgentID:      "test-agent",
		Hostname:     "test-host",
		OS:           "linux",
		Arch:         "amd64",
		Version:      "1.0.0",
		Capabilities: []string{"execute", "file_transfer"},
		Labels:       map[string]string{"env": "test"},
		Timestamp:    time.Now().Unix(),
	}

	msg, err := NewMessage(MsgTypeHandshake, payload, 42)
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Encode
	encoded := msg.Encode()

	if len(encoded) != HeaderSize+int(msg.Header.Length) {
		t.Errorf("Encoded length mismatch: expected %d, got %d",
			HeaderSize+int(msg.Header.Length), len(encoded))
	}

	// Decode
	reader := bytes.NewReader(encoded)
	decoded, err := DecodeMessage(reader)
	if err != nil {
		t.Fatalf("Failed to decode message: %v", err)
	}

	if decoded.Header.Type != MsgTypeHandshake {
		t.Errorf("Type mismatch: expected %d, got %d", MsgTypeHandshake, decoded.Header.Type)
	}

	if decoded.Header.Sequence != 42 {
		t.Errorf("Sequence mismatch: expected 42, got %d", decoded.Header.Sequence)
	}

	// Decode payload
	var decodedPayload HandshakePayload
	err = decoded.DecodePayload(&decodedPayload)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	if decodedPayload.AgentID != "test-agent" {
		t.Errorf("AgentID mismatch: expected 'test-agent', got '%s'", decodedPayload.AgentID)
	}

	if decodedPayload.Hostname != "test-host" {
		t.Errorf("Hostname mismatch: expected 'test-host', got '%s'", decodedPayload.Hostname)
	}
}

func TestNewHandshake(t *testing.T) {
	msg, err := NewHandshake(
		"agent-001",
		"server-01",
		"linux",
		"amd64",
		"1.0.0",
		[]string{"execute"},
		map[string]string{"env": "prod"},
		nil,
		1,
	)

	if err != nil {
		t.Fatalf("Failed to create handshake: %v", err)
	}

	if msg.Header.Type != MsgTypeHandshake {
		t.Errorf("Expected handshake type, got %d", msg.Header.Type)
	}

	var payload HandshakePayload
	msg.DecodePayload(&payload)

	if payload.AgentID != "agent-001" {
		t.Errorf("AgentID mismatch")
	}
}

func TestNewHeartbeat(t *testing.T) {
	msg, err := NewHeartbeat("agent-001", 25.5, 60.0, 45.0, "online", 10)
	if err != nil {
		t.Fatalf("Failed to create heartbeat: %v", err)
	}

	if msg.Header.Type != MsgTypeHeartbeat {
		t.Errorf("Expected heartbeat type, got %d", msg.Header.Type)
	}

	var payload HeartbeatPayload
	msg.DecodePayload(&payload)

	if payload.CPUUsage != 25.5 {
		t.Errorf("CPU usage mismatch: expected 25.5, got %f", payload.CPUUsage)
	}

	if payload.MemUsage != 60.0 {
		t.Errorf("Memory usage mismatch: expected 60.0, got %f", payload.MemUsage)
	}

	if payload.Status != "online" {
		t.Errorf("Status mismatch: expected 'online', got '%s'", payload.Status)
	}
}

func TestNewCommand(t *testing.T) {
	cmd := &models.Command{
		ID:       "cmd-001",
		Type:     models.CmdExecute,
		Payload:  map[string]any{"command": "ls", "args": []string{"-la"}},
		Timeout:  30 * time.Second,
		Priority: 1,
	}

	msg, err := NewCommand(cmd, 5)
	if err != nil {
		t.Fatalf("Failed to create command message: %v", err)
	}

	if msg.Header.Type != MsgTypeCommand {
		t.Errorf("Expected command type, got %d", msg.Header.Type)
	}

	var payload CommandPayload
	msg.DecodePayload(&payload)

	if payload.CommandID != "cmd-001" {
		t.Errorf("CommandID mismatch")
	}

	if payload.Type != models.CmdExecute {
		t.Errorf("Command type mismatch")
	}

	if payload.Timeout != 30 {
		t.Errorf("Timeout mismatch: expected 30, got %d", payload.Timeout)
	}
}

func TestNewResult(t *testing.T) {
	result := &models.CommandResult{
		CommandID:   "cmd-001",
		AgentID:     "agent-001",
		Success:     true,
		ExitCode:    0,
		Output:      "command output",
		StartedAt:   time.Now().Add(-time.Second),
		CompletedAt: time.Now(),
	}

	msg, err := NewResult(result, 6)
	if err != nil {
		t.Fatalf("Failed to create result message: %v", err)
	}

	if msg.Header.Type != MsgTypeResult {
		t.Errorf("Expected result type, got %d", msg.Header.Type)
	}

	var payload ResultPayload
	msg.DecodePayload(&payload)

	if !payload.Success {
		t.Error("Success should be true")
	}

	if payload.ExitCode != 0 {
		t.Errorf("ExitCode mismatch: expected 0, got %d", payload.ExitCode)
	}

	if payload.Output != "command output" {
		t.Errorf("Output mismatch")
	}
}

func TestNewError(t *testing.T) {
	msg, err := NewError(404, "Not Found", "Agent not found", 7)
	if err != nil {
		t.Fatalf("Failed to create error message: %v", err)
	}

	if msg.Header.Type != MsgTypeError {
		t.Errorf("Expected error type, got %d", msg.Header.Type)
	}

	var payload ErrorPayload
	msg.DecodePayload(&payload)

	if payload.Code != 404 {
		t.Errorf("Error code mismatch: expected 404, got %d", payload.Code)
	}

	if payload.Message != "Not Found" {
		t.Errorf("Error message mismatch")
	}
}

func TestCRC32(t *testing.T) {
	data := []byte("test data for crc32")
	
	checksum1 := crc32(data)
	checksum2 := crc32(data)

	if checksum1 != checksum2 {
		t.Error("CRC32 should be consistent")
	}

	// Different data should have different checksum
	differentData := []byte("different data")
	checksum3 := crc32(differentData)

	if checksum1 == checksum3 {
		t.Error("Different data should have different checksum")
	}

	// Empty data
	emptyChecksum := crc32([]byte{})
	if emptyChecksum == 0 {
		t.Error("CRC32 of empty data should not be 0")
	}
}

func TestMessageTooLarge(t *testing.T) {
	// Create a payload that exceeds max size
	largePayload := make([]byte, MaxMessageSize+1)

	_, err := NewMessage(MsgTypeCommand, largePayload, 1)
	if err != ErrMessageTooLarge {
		t.Errorf("Expected ErrMessageTooLarge, got %v", err)
	}
}

func TestVersionMismatch(t *testing.T) {
	// Create a message with wrong version
	buf := make([]byte, HeaderSize)
	buf[0] = ProtocolVersion + 1 // Wrong version
	binary.BigEndian.PutUint16(buf[1:3], MsgTypeCommand)
	buf[3] = 0
	binary.BigEndian.PutUint32(buf[4:8], 1)
	binary.BigEndian.PutUint32(buf[8:12], 0) // Zero length
	binary.BigEndian.PutUint32(buf[12:16], crc32([]byte{}))

	reader := bytes.NewReader(buf)
	_, err := DecodeMessage(reader)

	if err != ErrVersionMismatch {
		t.Errorf("Expected ErrVersionMismatch, got %v", err)
	}
}

func TestChecksumMismatch(t *testing.T) {
	payload := []byte(`{"test": "data"}`)
	
	buf := make([]byte, HeaderSize+len(payload))
	buf[0] = ProtocolVersion
	binary.BigEndian.PutUint16(buf[1:3], MsgTypeCommand)
	buf[3] = 0
	binary.BigEndian.PutUint32(buf[4:8], 1)
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(payload)))
	binary.BigEndian.PutUint32(buf[12:16], 0xDEADBEEF) // Wrong checksum
	copy(buf[HeaderSize:], payload)

	reader := bytes.NewReader(buf)
	_, err := DecodeMessage(reader)

	if err != ErrChecksumMismatch {
		t.Errorf("Expected ErrChecksumMismatch, got %v", err)
	}
}

func TestFileTransferPayload(t *testing.T) {
	payload := FileTransferPayload{
		TransferID:  "transfer-001",
		Operation:   "upload",
		RemotePath:  "/tmp/test.txt",
		ChunkIndex:  0,
		TotalChunks: 5,
		ChunkSize:   65536,
		TotalSize:   320000,
		Checksum:    "abc123",
		Data:        []byte("chunk data"),
	}

	msg, err := NewMessage(MsgTypeFileTransfer, payload, 1)
	if err != nil {
		t.Fatalf("Failed to create file transfer message: %v", err)
	}

	var decoded FileTransferPayload
	msg.DecodePayload(&decoded)

	if decoded.TransferID != "transfer-001" {
		t.Errorf("TransferID mismatch")
	}

	if decoded.TotalChunks != 5 {
		t.Errorf("TotalChunks mismatch: expected 5, got %d", decoded.TotalChunks)
	}
}

func TestShellDataPayload(t *testing.T) {
	payload := ShellDataPayload{
		SessionID: "session-001",
		Data:      []byte("ls -la\n"),
		Cols:      80,
		Rows:      24,
		Resize:    false,
	}

	msg, err := NewMessage(MsgTypeShellData, payload, 1)
	if err != nil {
		t.Fatalf("Failed to create shell data message: %v", err)
	}

	var decoded ShellDataPayload
	msg.DecodePayload(&decoded)

	if decoded.SessionID != "session-001" {
		t.Errorf("SessionID mismatch")
	}

	if decoded.Cols != 80 || decoded.Rows != 24 {
		t.Errorf("Terminal size mismatch")
	}
}

func TestMessageTypes(t *testing.T) {
	types := []uint16{
		MsgTypeHandshake,
		MsgTypeHeartbeat,
		MsgTypeCommand,
		MsgTypeResult,
		MsgTypeSystemInfo,
		MsgTypeProcessList,
		MsgTypeFileTransfer,
		MsgTypeShellData,
		MsgTypeError,
		MsgTypeAck,
		MsgTypeDisconnect,
	}

	for _, msgType := range types {
		msg, err := NewMessage(msgType, map[string]string{}, 1)
		if err != nil {
			t.Errorf("Failed to create message type %d: %v", msgType, err)
		}

		if msg.Header.Type != msgType {
			t.Errorf("Type mismatch for %d", msgType)
		}
	}
}

func BenchmarkMessageEncode(b *testing.B) {
	payload := HandshakePayload{
		AgentID:      "agent-001",
		Hostname:     "test-host",
		OS:           "linux",
		Arch:         "amd64",
		Version:      "1.0.0",
		Capabilities: []string{"execute", "file_transfer", "shell_session"},
		Timestamp:    time.Now().Unix(),
	}

	msg, _ := NewMessage(MsgTypeHandshake, payload, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg.Encode()
	}
}

func BenchmarkMessageDecode(b *testing.B) {
	payload := HandshakePayload{
		AgentID:      "agent-001",
		Hostname:     "test-host",
		OS:           "linux",
		Arch:         "amd64",
		Version:      "1.0.0",
		Capabilities: []string{"execute", "file_transfer", "shell_session"},
		Timestamp:    time.Now().Unix(),
	}

	msg, _ := NewMessage(MsgTypeHandshake, payload, 1)
	encoded := msg.Encode()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(encoded)
		DecodeMessage(reader)
	}
}

func BenchmarkCRC32(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crc32(data)
	}
}
