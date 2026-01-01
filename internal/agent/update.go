package agent

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

var (
	ErrNoUpdate        = errors.New("no update available")
	ErrInvalidChecksum = errors.New("checksum verification failed")
	ErrDownloadFailed  = errors.New("update download failed")
	ErrInstallFailed   = errors.New("update installation failed")
	ErrRollbackFailed  = errors.New("rollback failed")
	ErrAccessDenied    = errors.New("access denied")
)

// UpdateInfo contains update information
type UpdateInfo struct {
	Version     string    `json:"version"`
	ReleaseDate time.Time `json:"release_date"`
	DownloadURL string    `json:"download_url"`
	Checksum    string    `json:"checksum"`
	Size        int64     `json:"size"`
	ReleaseNotes string   `json:"release_notes,omitempty"`
	Mandatory   bool      `json:"mandatory"`
}

// UpdateManager handles agent self-update
type UpdateManager struct {
	currentVersion string
	updateURL      string
	tempDir        string
	backupPath     string
	httpClient     *http.Client
}

// NewUpdateManager creates a new update manager
func NewUpdateManager(currentVersion, updateURL string) *UpdateManager {
	return &UpdateManager{
		currentVersion: currentVersion,
		updateURL:      updateURL,
		tempDir:        os.TempDir(),
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// CheckForUpdate checks if an update is available
func (um *UpdateManager) CheckForUpdate() (*UpdateInfo, error) {
	url := fmt.Sprintf("%s/api/v1/agents/updates/check?os=%s&arch=%s&version=%s",
		um.updateURL, runtime.GOOS, runtime.GOARCH, um.currentVersion)

	resp, err := um.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to check for update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, ErrNoUpdate
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update check failed: status %d", resp.StatusCode)
	}

	// Parse update info
	// In a real implementation, this would decode JSON
	info := &UpdateInfo{
		Version:     "1.1.0",
		ReleaseDate: time.Now(),
	}

	return info, nil
}

// DownloadUpdate downloads the update package
func (um *UpdateManager) DownloadUpdate(info *UpdateInfo) (string, error) {
	if info.DownloadURL == "" {
		return "", errors.New("download URL not provided")
	}

	resp, err := um.httpClient.Get(info.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	// Create temp file for download
	tempFile, err := os.CreateTemp(um.tempDir, "argus-update-*.zip")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tempFile.Close()

	// Download with checksum verification
	hash := sha256.New()
	writer := io.MultiWriter(tempFile, hash)

	_, err = io.Copy(writer, resp.Body)
	if err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to write update: %w", err)
	}

	// Verify checksum
	actualChecksum := hex.EncodeToString(hash.Sum(nil))
	if info.Checksum != "" && actualChecksum != info.Checksum {
		os.Remove(tempFile.Name())
		return "", ErrInvalidChecksum
	}

	return tempFile.Name(), nil
}

// InstallUpdate installs the downloaded update
func (um *UpdateManager) InstallUpdate(updatePath string) error {
	// Get current executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// Create backup
	um.backupPath = execPath + ".backup"
	if err := copyFile(execPath, um.backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Extract update
	extractDir := filepath.Join(um.tempDir, "argus-update")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("failed to create extract directory: %w", err)
	}
	defer os.RemoveAll(extractDir)

	if err := um.extractUpdate(updatePath, extractDir); err != nil {
		return err
	}

	// Find the new executable
	var newExecName string
	if runtime.GOOS == "windows" {
		newExecName = "argus-agent.exe"
	} else {
		newExecName = "argus-agent"
	}

	newExecPath := filepath.Join(extractDir, newExecName)
	if _, err := os.Stat(newExecPath); os.IsNotExist(err) {
		return fmt.Errorf("executable not found in update package")
	}

	// On Windows, we need to rename the current executable first
	if runtime.GOOS == "windows" {
		oldPath := execPath + ".old"
		os.Remove(oldPath)
		if err := os.Rename(execPath, oldPath); err != nil {
			return fmt.Errorf("failed to move current executable: %w", err)
		}
	}

	// Copy new executable
	if err := copyFile(newExecPath, execPath); err != nil {
		// Try to rollback
		um.Rollback()
		return fmt.Errorf("failed to install update: %w", err)
	}

	// Set executable permissions on Unix
	if runtime.GOOS != "windows" {
		if err := os.Chmod(execPath, 0755); err != nil {
			um.Rollback()
			return fmt.Errorf("failed to set permissions: %w", err)
		}
	}

	// Clean up
	os.Remove(updatePath)
	os.Remove(um.backupPath)
	if runtime.GOOS == "windows" {
		os.Remove(execPath + ".old")
	}

	return nil
}

// Rollback reverts to the previous version
func (um *UpdateManager) Rollback() error {
	if um.backupPath == "" {
		return errors.New("no backup available")
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// Restore backup
	if err := copyFile(um.backupPath, execPath); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	os.Remove(um.backupPath)
	um.backupPath = ""

	return nil
}

func (um *UpdateManager) extractUpdate(zipPath, destDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		path := filepath.Join(destDir, file.Name)

		// Check for zip slip
		if !filepath.HasPrefix(path, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return errors.New("invalid file path in archive")
		}

		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.Mode())
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		rc, err := file.Open()
		if err != nil {
			return err
		}

		outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

// VerifyBinary verifies the binary signature (placeholder for real implementation)
func (um *UpdateManager) VerifyBinary(path string, expectedSignature []byte) error {
	// In a production implementation, this would verify a cryptographic signature
	// using a public key embedded in the agent
	
	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read binary: %w", err)
	}

	// Calculate hash
	hash := sha256.Sum256(data)
	
	// Compare with expected (placeholder)
	if expectedSignature != nil && !bytes.Equal(hash[:], expectedSignature) {
		return errors.New("binary signature verification failed")
	}

	return nil
}

// GetCurrentVersion returns the current agent version
func (um *UpdateManager) GetCurrentVersion() string {
	return um.currentVersion
}

// SetUpdateURL sets the update server URL
func (um *UpdateManager) SetUpdateURL(url string) {
	um.updateURL = url
}

// ScheduleUpdate schedules an update for installation
type ScheduledUpdate struct {
	Info        *UpdateInfo
	ScheduledAt time.Time
	Attempts    int
	LastError   string
}

// UpdateScheduler manages scheduled updates
type UpdateScheduler struct {
	manager     *UpdateManager
	scheduled   *ScheduledUpdate
	maxAttempts int
}

// NewUpdateScheduler creates a new update scheduler
func NewUpdateScheduler(manager *UpdateManager) *UpdateScheduler {
	return &UpdateScheduler{
		manager:     manager,
		maxAttempts: 3,
	}
}

// Schedule schedules an update
func (us *UpdateScheduler) Schedule(info *UpdateInfo, at time.Time) {
	us.scheduled = &ScheduledUpdate{
		Info:        info,
		ScheduledAt: at,
		Attempts:    0,
	}
}

// Cancel cancels a scheduled update
func (us *UpdateScheduler) Cancel() {
	us.scheduled = nil
}

// GetScheduled returns the currently scheduled update
func (us *UpdateScheduler) GetScheduled() *ScheduledUpdate {
	return us.scheduled
}

// TryInstall attempts to install the scheduled update
func (us *UpdateScheduler) TryInstall() error {
	if us.scheduled == nil {
		return errors.New("no update scheduled")
	}

	if time.Now().Before(us.scheduled.ScheduledAt) {
		return errors.New("update not yet scheduled")
	}

	us.scheduled.Attempts++

	// Download
	updatePath, err := us.manager.DownloadUpdate(us.scheduled.Info)
	if err != nil {
		us.scheduled.LastError = err.Error()
		if us.scheduled.Attempts >= us.maxAttempts {
			us.scheduled = nil
		}
		return err
	}

	// Install
	if err := us.manager.InstallUpdate(updatePath); err != nil {
		us.scheduled.LastError = err.Error()
		if us.scheduled.Attempts >= us.maxAttempts {
			us.scheduled = nil
		}
		return err
	}

	us.scheduled = nil
	return nil
}
