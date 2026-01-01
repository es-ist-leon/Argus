package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/argus/argus/internal/protocol"
	"github.com/argus/argus/pkg/models"
)

const (
	DefaultChunkSize = 64 * 1024 // 64KB chunks
	MaxFileSize      = 1024 * 1024 * 1024 // 1GB max
)

var (
	ErrFileTooLarge   = errors.New("file exceeds maximum size")
	ErrTransferFailed = errors.New("file transfer failed")
)

// FileTransferManager handles file upload/download operations
type FileTransferManager struct {
	mu              sync.RWMutex
	activeTransfers map[string]*ActiveTransfer
	allowedPaths    []string
	blockedPaths    []string
	maxFileSize     int64
	chunkSize       int
	tempDir         string
}

// ActiveTransfer represents an in-progress transfer
type ActiveTransfer struct {
	ID          string
	Type        string // "upload" or "download"
	LocalPath   string
	RemotePath  string
	TotalSize   int64
	ChunkSize   int
	TotalChunks int
	Chunks      map[int]bool
	Received    int64
	Checksum    string
	StartedAt   time.Time
	LastUpdate  time.Time
	Status      string
	Error       error
	TempFile    *os.File
}

// NewFileTransferManager creates a new file transfer manager
func NewFileTransferManager(tempDir string) *FileTransferManager {
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	os.MkdirAll(tempDir, 0755)

	return &FileTransferManager{
		activeTransfers: make(map[string]*ActiveTransfer),
		allowedPaths:    []string{"/tmp", "/var/log", os.TempDir()},
		blockedPaths:    []string{"/etc/shadow", "/etc/passwd"},
		maxFileSize:     MaxFileSize,
		chunkSize:       DefaultChunkSize,
		tempDir:         tempDir,
	}
}

// SetAllowedPaths sets the allowed paths for file operations
func (ftm *FileTransferManager) SetAllowedPaths(paths []string) {
	ftm.mu.Lock()
	defer ftm.mu.Unlock()
	ftm.allowedPaths = paths
}

// SetBlockedPaths sets the blocked paths for file operations
func (ftm *FileTransferManager) SetBlockedPaths(paths []string) {
	ftm.mu.Lock()
	defer ftm.mu.Unlock()
	ftm.blockedPaths = paths
}

// IsPathAllowed checks if a path is allowed for file operations
func (ftm *FileTransferManager) IsPathAllowed(path string) bool {
	ftm.mu.RLock()
	defer ftm.mu.RUnlock()

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	// Check blocked paths first
	for _, blocked := range ftm.blockedPaths {
		if matchPath(absPath, blocked) {
			return false
		}
	}

	// Check allowed paths
	if len(ftm.allowedPaths) == 0 {
		return true // No restrictions if no allowed paths set
	}

	for _, allowed := range ftm.allowedPaths {
		if matchPath(absPath, allowed) {
			return true
		}
	}

	return false
}

func matchPath(path, pattern string) bool {
	absPattern, _ := filepath.Abs(pattern)
	return path == absPattern || filepath.HasPrefix(path, absPattern+string(filepath.Separator))
}

// InitUpload initializes a file upload (receiving from server)
func (ftm *FileTransferManager) InitUpload(transferID, remotePath string, totalSize int64, totalChunks int, checksum string) (*ActiveTransfer, error) {
	if !ftm.IsPathAllowed(remotePath) {
		return nil, ErrAccessDenied
	}

	if totalSize > ftm.maxFileSize {
		return nil, ErrFileTooLarge
	}

	// Create temp file
	tempFile, err := os.CreateTemp(ftm.tempDir, "argus-upload-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	transfer := &ActiveTransfer{
		ID:          transferID,
		Type:        "upload",
		LocalPath:   tempFile.Name(),
		RemotePath:  remotePath,
		TotalSize:   totalSize,
		ChunkSize:   ftm.chunkSize,
		TotalChunks: totalChunks,
		Chunks:      make(map[int]bool),
		Checksum:    checksum,
		StartedAt:   time.Now(),
		LastUpdate:  time.Now(),
		Status:      "in_progress",
		TempFile:    tempFile,
	}

	ftm.mu.Lock()
	ftm.activeTransfers[transferID] = transfer
	ftm.mu.Unlock()

	return transfer, nil
}

// ReceiveChunk receives a chunk of data for an upload
func (ftm *FileTransferManager) ReceiveChunk(transferID string, chunkIndex int, data []byte) error {
	ftm.mu.Lock()
	transfer, ok := ftm.activeTransfers[transferID]
	ftm.mu.Unlock()

	if !ok {
		return fmt.Errorf("transfer not found: %s", transferID)
	}

	if transfer.TempFile == nil {
		return fmt.Errorf("temp file not available")
	}

	// Write chunk at correct offset
	offset := int64(chunkIndex) * int64(transfer.ChunkSize)
	_, err := transfer.TempFile.WriteAt(data, offset)
	if err != nil {
		return fmt.Errorf("failed to write chunk: %w", err)
	}

	ftm.mu.Lock()
	transfer.Chunks[chunkIndex] = true
	transfer.Received += int64(len(data))
	transfer.LastUpdate = time.Now()
	ftm.mu.Unlock()

	// Check if complete
	if len(transfer.Chunks) == transfer.TotalChunks {
		return ftm.finalizeUpload(transfer)
	}

	return nil
}

func (ftm *FileTransferManager) finalizeUpload(transfer *ActiveTransfer) error {
	transfer.TempFile.Close()

	// Verify checksum if provided
	if transfer.Checksum != "" {
		actualChecksum, err := calculateFileChecksum(transfer.LocalPath)
		if err != nil {
			transfer.Status = "failed"
			transfer.Error = err
			return err
		}
		if actualChecksum != transfer.Checksum {
			transfer.Status = "failed"
			transfer.Error = ErrInvalidChecksum
			os.Remove(transfer.LocalPath)
			return ErrInvalidChecksum
		}
	}

	// Move to final destination
	destDir := filepath.Dir(transfer.RemotePath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		transfer.Status = "failed"
		transfer.Error = err
		return err
	}

	if err := os.Rename(transfer.LocalPath, transfer.RemotePath); err != nil {
		// Rename might fail across filesystems, try copy
		if err := copyFile(transfer.LocalPath, transfer.RemotePath); err != nil {
			transfer.Status = "failed"
			transfer.Error = err
			return err
		}
		os.Remove(transfer.LocalPath)
	}

	transfer.Status = "complete"
	return nil
}

// InitDownload initializes a file download (sending to server)
func (ftm *FileTransferManager) InitDownload(transferID, localPath string) (*ActiveTransfer, int64, string, error) {
	if !ftm.IsPathAllowed(localPath) {
		return nil, 0, "", ErrAccessDenied
	}

	// Check if file exists and get size
	info, err := os.Stat(localPath)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to stat file: %w", err)
	}

	if info.Size() > ftm.maxFileSize {
		return nil, 0, "", ErrFileTooLarge
	}

	// Calculate checksum
	checksum, err := calculateFileChecksum(localPath)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to calculate checksum: %w", err)
	}

	totalChunks := int((info.Size() + int64(ftm.chunkSize) - 1) / int64(ftm.chunkSize))

	transfer := &ActiveTransfer{
		ID:          transferID,
		Type:        "download",
		LocalPath:   localPath,
		TotalSize:   info.Size(),
		ChunkSize:   ftm.chunkSize,
		TotalChunks: totalChunks,
		Chunks:      make(map[int]bool),
		Checksum:    checksum,
		StartedAt:   time.Now(),
		LastUpdate:  time.Now(),
		Status:      "in_progress",
	}

	ftm.mu.Lock()
	ftm.activeTransfers[transferID] = transfer
	ftm.mu.Unlock()

	return transfer, info.Size(), checksum, nil
}

// GetChunk reads a chunk from a file for download
func (ftm *FileTransferManager) GetChunk(transferID string, chunkIndex int) ([]byte, error) {
	ftm.mu.RLock()
	transfer, ok := ftm.activeTransfers[transferID]
	ftm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("transfer not found: %s", transferID)
	}

	file, err := os.Open(transfer.LocalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	offset := int64(chunkIndex) * int64(transfer.ChunkSize)
	chunkData := make([]byte, transfer.ChunkSize)

	n, err := file.ReadAt(chunkData, offset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read chunk: %w", err)
	}

	ftm.mu.Lock()
	transfer.Chunks[chunkIndex] = true
	transfer.Received += int64(n)
	transfer.LastUpdate = time.Now()

	if len(transfer.Chunks) == transfer.TotalChunks {
		transfer.Status = "complete"
	}
	ftm.mu.Unlock()

	return chunkData[:n], nil
}

// CancelTransfer cancels an active transfer
func (ftm *FileTransferManager) CancelTransfer(transferID string) {
	ftm.mu.Lock()
	defer ftm.mu.Unlock()

	if transfer, ok := ftm.activeTransfers[transferID]; ok {
		transfer.Status = "cancelled"
		if transfer.TempFile != nil {
			transfer.TempFile.Close()
			os.Remove(transfer.LocalPath)
		}
		delete(ftm.activeTransfers, transferID)
	}
}

// GetTransfer returns the status of a transfer
func (ftm *FileTransferManager) GetTransfer(transferID string) (*ActiveTransfer, bool) {
	ftm.mu.RLock()
	defer ftm.mu.RUnlock()
	t, ok := ftm.activeTransfers[transferID]
	return t, ok
}

// CleanupStaleTransfers removes transfers that haven't been updated
func (ftm *FileTransferManager) CleanupStaleTransfers(maxAge time.Duration) {
	ftm.mu.Lock()
	defer ftm.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for id, transfer := range ftm.activeTransfers {
		if transfer.LastUpdate.Before(cutoff) {
			if transfer.TempFile != nil {
				transfer.TempFile.Close()
				os.Remove(transfer.LocalPath)
			}
			delete(ftm.activeTransfers, id)
		}
	}
}

func calculateFileChecksum(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// HandleFileTransfer processes file transfer commands
func (a *Agent) HandleFileTransfer(cmd *protocol.CommandPayload, result *models.CommandResult) {
	operation, _ := cmd.Payload["operation"].(string)
	remotePath, _ := cmd.Payload["remote_path"].(string)
	transferID, _ := cmd.Payload["transfer_id"].(string)

	if a.fileTransfer == nil {
		a.fileTransfer = NewFileTransferManager("")
	}

	switch operation {
	case "init_upload":
		totalSize := int64(cmd.Payload["total_size"].(float64))
		totalChunks := int(cmd.Payload["total_chunks"].(float64))
		checksum, _ := cmd.Payload["checksum"].(string)

		_, err := a.fileTransfer.InitUpload(transferID, remotePath, totalSize, totalChunks, checksum)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true
		result.Output = "Upload initialized"

	case "upload_chunk":
		chunkIndex := int(cmd.Payload["chunk_index"].(float64))
		// Data would be base64 encoded in payload
		dataStr, _ := cmd.Payload["data"].(string)
		data := []byte(dataStr) // In real impl, base64 decode

		if err := a.fileTransfer.ReceiveChunk(transferID, chunkIndex, data); err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true

	case "init_download":
		localPath, _ := cmd.Payload["local_path"].(string)
		transfer, size, checksum, err := a.fileTransfer.InitDownload(transferID, localPath)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true
		result.Output = fmt.Sprintf(`{"transfer_id":"%s","size":%d,"chunks":%d,"checksum":"%s"}`,
			transfer.ID, size, transfer.TotalChunks, checksum)

	case "download_chunk":
		chunkIndex := int(cmd.Payload["chunk_index"].(float64))
		data, err := a.fileTransfer.GetChunk(transferID, chunkIndex)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true
		result.Output = string(data) // In real impl, base64 encode

	case "cancel":
		a.fileTransfer.CancelTransfer(transferID)
		result.Success = true
		result.Output = "Transfer cancelled"

	case "delete":
		if !a.fileTransfer.IsPathAllowed(remotePath) {
			result.Success = false
			result.Error = "access denied"
			return
		}
		if err := os.Remove(remotePath); err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true
		result.Output = "File deleted"

	case "list":
		if !a.fileTransfer.IsPathAllowed(remotePath) {
			result.Success = false
			result.Error = "access denied"
			return
		}
		entries, err := os.ReadDir(remotePath)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}

		var output string
		for _, e := range entries {
			info, _ := e.Info()
			output += fmt.Sprintf("%s\t%d\t%s\n", e.Name(), info.Size(), info.ModTime())
		}
		result.Success = true
		result.Output = output

	default:
		result.Success = false
		result.Error = "unknown file operation: " + operation
	}
}
