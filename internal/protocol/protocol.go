package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/argus/argus/pkg/models"
)

const (
	ProtocolVersion = 1
	MaxMessageSize  = 64 * 1024 * 1024 // 64MB
	HeaderSize      = 16
)

// Message types
const (
	MsgTypeHandshake    uint16 = 0x0001
	MsgTypeHeartbeat    uint16 = 0x0002
	MsgTypeCommand      uint16 = 0x0003
	MsgTypeResult       uint16 = 0x0004
	MsgTypeSystemInfo   uint16 = 0x0005
	MsgTypeProcessList  uint16 = 0x0006
	MsgTypeFileTransfer uint16 = 0x0007
	MsgTypeShellData    uint16 = 0x0008
	MsgTypeError        uint16 = 0x0009
	MsgTypeAck          uint16 = 0x000A
	MsgTypeDisconnect   uint16 = 0x00FF
)

var (
	ErrInvalidMessage   = errors.New("invalid message format")
	ErrMessageTooLarge  = errors.New("message exceeds maximum size")
	ErrVersionMismatch  = errors.New("protocol version mismatch")
	ErrChecksumMismatch = errors.New("message checksum mismatch")
)

// Header represents the message header
type Header struct {
	Version   uint8
	Type      uint16
	Flags     uint8
	Sequence  uint32
	Length    uint32
	Checksum  uint32
}

// Message represents a protocol message
type Message struct {
	Header  Header
	Payload []byte
}

// HandshakePayload is sent during connection establishment
type HandshakePayload struct {
	AgentID      string            `json:"agent_id"`
	Hostname     string            `json:"hostname"`
	OS           string            `json:"os"`
	Arch         string            `json:"arch"`
	Version      string            `json:"version"`
	Capabilities []string          `json:"capabilities"`
	Labels       map[string]string `json:"labels"`
	PublicKey    []byte            `json:"public_key"`
	Timestamp    int64             `json:"timestamp"`
}

// HeartbeatPayload is sent periodically to maintain connection
type HeartbeatPayload struct {
	AgentID   string  `json:"agent_id"`
	Timestamp int64   `json:"timestamp"`
	CPUUsage  float64 `json:"cpu_usage"`
	MemUsage  float64 `json:"mem_usage"`
	DiskUsage float64 `json:"disk_usage"`
	Status    string  `json:"status"`
}

// CommandPayload represents a command to be executed
type CommandPayload struct {
	CommandID   string            `json:"command_id"`
	Type        models.CommandType `json:"type"`
	Payload     map[string]any    `json:"payload"`
	Timeout     int64             `json:"timeout"`
	Priority    int               `json:"priority"`
}

// ResultPayload represents command execution result
type ResultPayload struct {
	CommandID   string `json:"command_id"`
	Success     bool   `json:"success"`
	ExitCode    int    `json:"exit_code"`
	Output      string `json:"output"`
	Error       string `json:"error,omitempty"`
	StartedAt   int64  `json:"started_at"`
	CompletedAt int64  `json:"completed_at"`
}

// FileTransferPayload for file operations
type FileTransferPayload struct {
	TransferID  string `json:"transfer_id"`
	Operation   string `json:"operation"` // upload, download, delete
	RemotePath  string `json:"remote_path"`
	ChunkIndex  int    `json:"chunk_index"`
	TotalChunks int    `json:"total_chunks"`
	ChunkSize   int    `json:"chunk_size"`
	TotalSize   int64  `json:"total_size"`
	Checksum    string `json:"checksum"`
	Data        []byte `json:"data,omitempty"`
}

// ShellDataPayload for interactive shell sessions
type ShellDataPayload struct {
	SessionID string `json:"session_id"`
	Data      []byte `json:"data"`
	Cols      int    `json:"cols,omitempty"`
	Rows      int    `json:"rows,omitempty"`
	Resize    bool   `json:"resize,omitempty"`
}

// ErrorPayload for error responses
type ErrorPayload struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// NewMessage creates a new message with the given type and payload
func NewMessage(msgType uint16, payload any, sequence uint32) (*Message, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	if len(data) > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}

	msg := &Message{
		Header: Header{
			Version:  ProtocolVersion,
			Type:     msgType,
			Flags:    0,
			Sequence: sequence,
			Length:   uint32(len(data)),
			Checksum: crc32(data),
		},
		Payload: data,
	}

	return msg, nil
}

// Encode serializes a message to bytes
func (m *Message) Encode() []byte {
	buf := make([]byte, HeaderSize+len(m.Payload))
	
	buf[0] = m.Header.Version
	binary.BigEndian.PutUint16(buf[1:3], m.Header.Type)
	buf[3] = m.Header.Flags
	binary.BigEndian.PutUint32(buf[4:8], m.Header.Sequence)
	binary.BigEndian.PutUint32(buf[8:12], m.Header.Length)
	binary.BigEndian.PutUint32(buf[12:16], m.Header.Checksum)
	
	copy(buf[HeaderSize:], m.Payload)
	return buf
}

// DecodeMessage deserializes bytes to a message
func DecodeMessage(r io.Reader) (*Message, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	msg := &Message{
		Header: Header{
			Version:  header[0],
			Type:     binary.BigEndian.Uint16(header[1:3]),
			Flags:    header[3],
			Sequence: binary.BigEndian.Uint32(header[4:8]),
			Length:   binary.BigEndian.Uint32(header[8:12]),
			Checksum: binary.BigEndian.Uint32(header[12:16]),
		},
	}

	if msg.Header.Version != ProtocolVersion {
		return nil, ErrVersionMismatch
	}

	if msg.Header.Length > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}

	msg.Payload = make([]byte, msg.Header.Length)
	if _, err := io.ReadFull(r, msg.Payload); err != nil {
		return nil, fmt.Errorf("failed to read payload: %w", err)
	}

	if crc32(msg.Payload) != msg.Header.Checksum {
		return nil, ErrChecksumMismatch
	}

	return msg, nil
}

// DecodePayload deserializes the payload to the given type
func (m *Message) DecodePayload(v any) error {
	return json.Unmarshal(m.Payload, v)
}

// NewHandshake creates a handshake message
func NewHandshake(agentID, hostname, os, arch, version string, capabilities []string, labels map[string]string, publicKey []byte, seq uint32) (*Message, error) {
	payload := HandshakePayload{
		AgentID:      agentID,
		Hostname:     hostname,
		OS:           os,
		Arch:         arch,
		Version:      version,
		Capabilities: capabilities,
		Labels:       labels,
		PublicKey:    publicKey,
		Timestamp:    time.Now().Unix(),
	}
	return NewMessage(MsgTypeHandshake, payload, seq)
}

// NewHeartbeat creates a heartbeat message
func NewHeartbeat(agentID string, cpuUsage, memUsage, diskUsage float64, status string, seq uint32) (*Message, error) {
	payload := HeartbeatPayload{
		AgentID:   agentID,
		Timestamp: time.Now().Unix(),
		CPUUsage:  cpuUsage,
		MemUsage:  memUsage,
		DiskUsage: diskUsage,
		Status:    status,
	}
	return NewMessage(MsgTypeHeartbeat, payload, seq)
}

// NewCommand creates a command message
func NewCommand(cmd *models.Command, seq uint32) (*Message, error) {
	payload := CommandPayload{
		CommandID: cmd.ID,
		Type:      cmd.Type,
		Payload:   cmd.Payload,
		Timeout:   int64(cmd.Timeout.Seconds()),
		Priority:  cmd.Priority,
	}
	return NewMessage(MsgTypeCommand, payload, seq)
}

// NewResult creates a result message
func NewResult(result *models.CommandResult, seq uint32) (*Message, error) {
	payload := ResultPayload{
		CommandID:   result.CommandID,
		Success:     result.Success,
		ExitCode:    result.ExitCode,
		Output:      result.Output,
		Error:       result.Error,
		StartedAt:   result.StartedAt.Unix(),
		CompletedAt: result.CompletedAt.Unix(),
	}
	return NewMessage(MsgTypeResult, payload, seq)
}

// NewError creates an error message
func NewError(code int, message, details string, seq uint32) (*Message, error) {
	payload := ErrorPayload{
		Code:    code,
		Message: message,
		Details: details,
	}
	return NewMessage(MsgTypeError, payload, seq)
}

// Simple CRC32 implementation
func crc32(data []byte) uint32 {
	var crc uint32 = 0xFFFFFFFF
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}
