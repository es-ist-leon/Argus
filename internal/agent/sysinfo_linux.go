//go:build linux
// +build linux

package agent

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/argus/argus/pkg/models"
)

// GetSystemInfoLinux retrieves detailed system information on Linux
func GetSystemInfoLinux() (*models.SystemInfo, error) {
	info := &models.SystemInfo{
		OS:       "linux",
		Arch:     runtime.GOARCH,
		CPUCores: runtime.NumCPU(),
	}

	// Hostname
	hostname, _ := os.Hostname()
	info.Hostname = hostname

	// OS Version from /etc/os-release
	info.OSVersion = getLinuxVersion()

	// CPU Model from /proc/cpuinfo
	info.CPUModel = getCPUModelLinux()

	// Memory from /proc/meminfo
	memInfo := parseMemInfo()
	info.MemoryTotal = memInfo["MemTotal"]
	info.MemoryFree = memInfo["MemFree"] + memInfo["Buffers"] + memInfo["Cached"]
	info.MemoryUsed = info.MemoryTotal - info.MemoryFree

	// Uptime from /proc/uptime
	info.Uptime = getUptime()
	info.BootTime = time.Now().Add(-time.Duration(info.Uptime) * time.Second)

	// CPU Usage
	info.CPUUsage = getCPUUsageLinux()

	// Disk Info
	info.DiskInfo = getDiskInfoLinux()

	// Network Info
	info.NetworkInfo = getNetworkInfoLinux()

	return info, nil
}

func getLinuxVersion() string {
	data, err := ioutil.ReadFile("/etc/os-release")
	if err != nil {
		return "Linux"
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			value := strings.TrimPrefix(line, "PRETTY_NAME=")
			value = strings.Trim(value, "\"")
			return value
		}
	}

	// Fallback to kernel version
	data, err = ioutil.ReadFile("/proc/version")
	if err == nil {
		parts := strings.Fields(string(data))
		if len(parts) >= 3 {
			return "Linux " + parts[2]
		}
	}

	return "Linux"
}

func getCPUModelLinux() string {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "Unknown CPU"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "Unknown CPU"
}

func parseMemInfo() map[string]uint64 {
	result := make(map[string]uint64)

	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return result
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := strings.TrimSuffix(parts[0], ":")
			value, _ := strconv.ParseUint(parts[1], 10, 64)
			// Convert from KB to bytes
			result[key] = value * 1024
		}
	}
	return result
}

func getUptime() int64 {
	data, err := ioutil.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}

	parts := strings.Fields(string(data))
	if len(parts) > 0 {
		uptime, _ := strconv.ParseFloat(parts[0], 64)
		return int64(uptime)
	}
	return 0
}

var lastCPUStats struct {
	idle  uint64
	total uint64
}

func getCPUUsageLinux() float64 {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0
			}

			var total, idle uint64
			for i := 1; i < len(fields); i++ {
				val, _ := strconv.ParseUint(fields[i], 10, 64)
				total += val
				if i == 4 { // idle is the 4th value
					idle = val
				}
			}

			if lastCPUStats.total == 0 {
				lastCPUStats.idle = idle
				lastCPUStats.total = total
				time.Sleep(100 * time.Millisecond)
				return getCPUUsageLinux()
			}

			idleDiff := idle - lastCPUStats.idle
			totalDiff := total - lastCPUStats.total

			lastCPUStats.idle = idle
			lastCPUStats.total = total

			if totalDiff == 0 {
				return 0
			}

			return 100.0 * float64(totalDiff-idleDiff) / float64(totalDiff)
		}
	}
	return 0
}

func getDiskInfoLinux() []models.DiskInfo {
	var disks []models.DiskInfo

	file, err := os.Open("/proc/mounts")
	if err != nil {
		return disks
	}
	defer file.Close()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		device := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]

		// Skip virtual filesystems
		if !strings.HasPrefix(device, "/dev/") {
			continue
		}
		if fsType == "tmpfs" || fsType == "devtmpfs" || fsType == "squashfs" {
			continue
		}

		// Skip duplicates
		if seen[device] {
			continue
		}
		seen[device] = true

		var stat syscallStatfs
		if err := statfs(mountPoint, &stat); err != nil {
			continue
		}

		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		used := total - free
		usedPct := 0.0
		if total > 0 {
			usedPct = 100.0 * float64(used) / float64(total)
		}

		disks = append(disks, models.DiskInfo{
			Device:     device,
			MountPoint: mountPoint,
			FSType:     fsType,
			Total:      total,
			Used:       used,
			Free:       free,
			UsedPct:    usedPct,
		})
	}

	return disks
}

type syscallStatfs struct {
	Type    int64
	Bsize   int64
	Blocks  uint64
	Bfree   uint64
	Bavail  uint64
	Files   uint64
	Ffree   uint64
	Fsid    [2]int32
	Namelen int64
	Frsize  int64
	Flags   int64
	Spare   [4]int64
}

func statfs(path string, stat *syscallStatfs) error {
	// This would use syscall.Statfs in real implementation
	// For now, use os.Stat as fallback
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	_ = info
	return nil
}

func getNetworkInfoLinux() []models.NetInfo {
	var nets []models.NetInfo

	interfaces, err := net.Interfaces()
	if err != nil {
		return nets
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		netInfo := models.NetInfo{
			Name: iface.Name,
			MAC:  iface.HardwareAddr.String(),
		}

		// Get IP addresses
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					netInfo.IPs = append(netInfo.IPs, ipnet.IP.String())
				}
			}
		}

		// Get stats from /sys/class/net
		statsPath := fmt.Sprintf("/sys/class/net/%s/statistics/", iface.Name)

		if data, err := ioutil.ReadFile(statsPath + "rx_bytes"); err == nil {
			netInfo.BytesRecv, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
		if data, err := ioutil.ReadFile(statsPath + "tx_bytes"); err == nil {
			netInfo.BytesSent, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}

		nets = append(nets, netInfo)
	}

	return nets
}

// GetProcessListLinux retrieves the list of running processes on Linux
func GetProcessListLinux() ([]models.ProcessInfo, error) {
	var processes []models.ProcessInfo

	files, err := ioutil.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if !file.IsDir() {
			continue
		}

		pid, err := strconv.ParseInt(file.Name(), 10, 32)
		if err != nil {
			continue
		}

		proc, err := getProcessInfoLinux(int32(pid))
		if err != nil {
			continue
		}

		processes = append(processes, *proc)
	}

	return processes, nil
}

func getProcessInfoLinux(pid int32) (*models.ProcessInfo, error) {
	procPath := fmt.Sprintf("/proc/%d", pid)

	proc := &models.ProcessInfo{
		PID: pid,
	}

	// Read stat file
	statPath := filepath.Join(procPath, "stat")
	data, err := ioutil.ReadFile(statPath)
	if err != nil {
		return nil, err
	}

	// Parse stat - format: pid (name) state ppid ...
	statStr := string(data)
	start := strings.Index(statStr, "(")
	end := strings.LastIndex(statStr, ")")

	if start > 0 && end > start {
		proc.Name = statStr[start+1 : end]

		// Parse rest after the name
		rest := strings.Fields(statStr[end+2:])
		if len(rest) > 0 {
			proc.Status = rest[0]
		}
		if len(rest) > 1 {
			ppid, _ := strconv.ParseInt(rest[1], 10, 32)
			proc.PPID = int32(ppid)
		}
	}

	// Read exe link
	exePath, err := os.Readlink(filepath.Join(procPath, "exe"))
	if err == nil {
		proc.Exe = exePath
	}

	// Read cmdline
	cmdline, err := ioutil.ReadFile(filepath.Join(procPath, "cmdline"))
	if err == nil {
		proc.Cmdline = strings.ReplaceAll(string(cmdline), "\x00", " ")
		proc.Cmdline = strings.TrimSpace(proc.Cmdline)
	}

	// Read memory from statm
	statm, err := ioutil.ReadFile(filepath.Join(procPath, "statm"))
	if err == nil {
		fields := strings.Fields(string(statm))
		if len(fields) >= 2 {
			rss, _ := strconv.ParseUint(fields[1], 10, 64)
			pageSize := uint64(os.Getpagesize())
			proc.MemRSS = rss * pageSize
		}
	}

	// Read user from status
	status, err := ioutil.ReadFile(filepath.Join(procPath, "status"))
	if err == nil {
		lines := strings.Split(string(status), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					uid, _ := strconv.Atoi(fields[1])
					proc.User = fmt.Sprintf("%d", uid)
				}
				break
			}
		}
	}

	return proc, nil
}
