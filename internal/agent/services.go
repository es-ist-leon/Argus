package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/argus/argus/internal/protocol"
	"github.com/argus/argus/pkg/models"
)

// ServiceInfo represents information about a system service
type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	StartType   string `json:"start_type"`
	PID         int    `json:"pid,omitempty"`
	Description string `json:"description,omitempty"`
}

// HandleServiceManage handles service management commands
func (a *Agent) HandleServiceManage(cmd *protocol.CommandPayload, result *models.CommandResult) {
	operation, _ := cmd.Payload["operation"].(string)
	serviceName, _ := cmd.Payload["service"].(string)

	switch operation {
	case "list":
		services, err := listServices()
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		data, _ := json.Marshal(services)
		result.Success = true
		result.Output = string(data)

	case "status":
		if serviceName == "" {
			result.Success = false
			result.Error = "service name required"
			return
		}
		info, err := getServiceStatus(serviceName)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		data, _ := json.Marshal(info)
		result.Success = true
		result.Output = string(data)

	case "start":
		if serviceName == "" {
			result.Success = false
			result.Error = "service name required"
			return
		}
		if err := startService(serviceName); err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true
		result.Output = fmt.Sprintf("Service %s started", serviceName)

	case "stop":
		if serviceName == "" {
			result.Success = false
			result.Error = "service name required"
			return
		}
		if err := stopService(serviceName); err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true
		result.Output = fmt.Sprintf("Service %s stopped", serviceName)

	case "restart":
		if serviceName == "" {
			result.Success = false
			result.Error = "service name required"
			return
		}
		if err := restartService(serviceName); err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true
		result.Output = fmt.Sprintf("Service %s restarted", serviceName)

	case "enable":
		if serviceName == "" {
			result.Success = false
			result.Error = "service name required"
			return
		}
		if err := enableService(serviceName); err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true
		result.Output = fmt.Sprintf("Service %s enabled", serviceName)

	case "disable":
		if serviceName == "" {
			result.Success = false
			result.Error = "service name required"
			return
		}
		if err := disableService(serviceName); err != nil {
			result.Success = false
			result.Error = err.Error()
			return
		}
		result.Success = true
		result.Output = fmt.Sprintf("Service %s disabled", serviceName)

	default:
		result.Success = false
		result.Error = "unknown operation: " + operation
	}
}

func listServices() ([]ServiceInfo, error) {
	if runtime.GOOS == "windows" {
		return listServicesWindows()
	}
	return listServicesLinux()
}

func listServicesWindows() ([]ServiceInfo, error) {
	cmd := exec.Command("powershell", "-Command",
		"Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	var services []struct {
		Name        string `json:"Name"`
		DisplayName string `json:"DisplayName"`
		Status      int    `json:"Status"`
		StartType   int    `json:"StartType"`
	}

	if err := json.Unmarshal(output, &services); err != nil {
		return nil, fmt.Errorf("failed to parse service list: %w", err)
	}

	result := make([]ServiceInfo, len(services))
	for i, s := range services {
		result[i] = ServiceInfo{
			Name:        s.Name,
			DisplayName: s.DisplayName,
			Status:      windowsServiceStatus(s.Status),
			StartType:   windowsStartType(s.StartType),
		}
	}
	return result, nil
}

func windowsServiceStatus(status int) string {
	switch status {
	case 1:
		return "stopped"
	case 2:
		return "start_pending"
	case 3:
		return "stop_pending"
	case 4:
		return "running"
	case 5:
		return "continue_pending"
	case 6:
		return "pause_pending"
	case 7:
		return "paused"
	default:
		return "unknown"
	}
}

func windowsStartType(startType int) string {
	switch startType {
	case 0:
		return "boot"
	case 1:
		return "system"
	case 2:
		return "automatic"
	case 3:
		return "manual"
	case 4:
		return "disabled"
	default:
		return "unknown"
	}
}

func listServicesLinux() ([]ServiceInfo, error) {
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		// Try init.d fallback
		return listServicesInitD()
	}

	lines := strings.Split(string(output), "\n")
	services := make([]ServiceInfo, 0)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			name := strings.TrimSuffix(fields[0], ".service")
			services = append(services, ServiceInfo{
				Name:   name,
				Status: fields[3],
			})
		}
	}

	return services, nil
}

func listServicesInitD() ([]ServiceInfo, error) {
	cmd := exec.Command("service", "--status-all")
	output, _ := cmd.CombinedOutput() // Ignore error, parse output

	lines := strings.Split(string(output), "\n")
	services := make([]ServiceInfo, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) < 5 {
			continue
		}

		status := "unknown"
		if strings.Contains(line, "[ + ]") {
			status = "running"
		} else if strings.Contains(line, "[ - ]") {
			status = "stopped"
		}

		// Extract service name
		parts := strings.Split(line, "]")
		if len(parts) >= 2 {
			name := strings.TrimSpace(parts[len(parts)-1])
			services = append(services, ServiceInfo{
				Name:   name,
				Status: status,
			})
		}
	}

	return services, nil
}

func getServiceStatus(name string) (*ServiceInfo, error) {
	if runtime.GOOS == "windows" {
		return getServiceStatusWindows(name)
	}
	return getServiceStatusLinux(name)
}

func getServiceStatusWindows(name string) (*ServiceInfo, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf("Get-Service -Name '%s' | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json", name))
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("service not found: %s", name)
	}

	var s struct {
		Name        string `json:"Name"`
		DisplayName string `json:"DisplayName"`
		Status      int    `json:"Status"`
		StartType   int    `json:"StartType"`
	}

	if err := json.Unmarshal(output, &s); err != nil {
		return nil, fmt.Errorf("failed to parse service status: %w", err)
	}

	return &ServiceInfo{
		Name:        s.Name,
		DisplayName: s.DisplayName,
		Status:      windowsServiceStatus(s.Status),
		StartType:   windowsStartType(s.StartType),
	}, nil
}

func getServiceStatusLinux(name string) (*ServiceInfo, error) {
	cmd := exec.Command("systemctl", "show", name+".service",
		"--property=ActiveState,SubState,MainPID,Description")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get service status: %w", err)
	}

	info := &ServiceInfo{Name: name}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		switch key {
		case "ActiveState":
			info.Status = value
		case "MainPID":
			fmt.Sscanf(value, "%d", &info.PID)
		case "Description":
			info.Description = value
		}
	}

	return info, nil
}

func startService(name string) error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("net", "start", name)
		return cmd.Run()
	}
	cmd := exec.Command("systemctl", "start", name)
	return cmd.Run()
}

func stopService(name string) error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("net", "stop", name)
		return cmd.Run()
	}
	cmd := exec.Command("systemctl", "stop", name)
	return cmd.Run()
}

func restartService(name string) error {
	if runtime.GOOS == "windows" {
		stopService(name)
		return startService(name)
	}
	cmd := exec.Command("systemctl", "restart", name)
	return cmd.Run()
}

func enableService(name string) error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("sc", "config", name, "start=auto")
		return cmd.Run()
	}
	cmd := exec.Command("systemctl", "enable", name)
	return cmd.Run()
}

func disableService(name string) error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("sc", "config", name, "start=disabled")
		return cmd.Run()
	}
	cmd := exec.Command("systemctl", "disable", name)
	return cmd.Run()
}
