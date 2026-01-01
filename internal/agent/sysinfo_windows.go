//go:build windows
// +build windows

package agent

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/argus/argus/pkg/models"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	psapi              = windows.NewLazySystemDLL("psapi.dll")

	procGetSystemTimes          = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx    = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeSpaceExW     = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetLogicalDrives        = kernel32.NewProc("GetLogicalDrives")
	procGetVolumeInformationW   = kernel32.NewProc("GetVolumeInformationW")
	procGetTickCount64          = kernel32.NewProc("GetTickCount64")
	procEnumProcesses           = psapi.NewProc("EnumProcesses")
	procGetProcessMemoryInfo    = psapi.NewProc("GetProcessMemoryInfo")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type processMemoryCountersEx struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

// GetSystemInfoWindows retrieves detailed system information on Windows
func GetSystemInfoWindows() (*models.SystemInfo, error) {
	info := &models.SystemInfo{
		OS:       "windows",
		Arch:     runtime.GOARCH,
		CPUCores: runtime.NumCPU(),
	}

	// Hostname
	hostname, _ := os.Hostname()
	info.Hostname = hostname

	// OS Version
	info.OSVersion = getWindowsVersion()

	// CPU Model
	info.CPUModel = getCPUModel()

	// Memory
	var memStatus memoryStatusEx
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if ret != 0 {
		info.MemoryTotal = memStatus.TotalPhys
		info.MemoryFree = memStatus.AvailPhys
		info.MemoryUsed = info.MemoryTotal - info.MemoryFree
	}

	// Uptime
	ret, _, _ = procGetTickCount64.Call()
	info.Uptime = int64(ret) / 1000
	info.BootTime = time.Now().Add(-time.Duration(info.Uptime) * time.Second)

	// CPU Usage
	info.CPUUsage = getCPUUsageWindows()

	// Disk Info
	info.DiskInfo = getDiskInfoWindows()

	// Network Info
	info.NetworkInfo = getNetworkInfoWindows()

	return info, nil
}

func getWindowsVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer k.Close()

	productName, _, _ := k.GetStringValue("ProductName")
	buildNumber, _, _ := k.GetStringValue("CurrentBuildNumber")

	if productName != "" {
		if buildNumber != "" {
			return fmt.Sprintf("%s (Build %s)", productName, buildNumber)
		}
		return productName
	}
	return "Windows"
}

func getCPUModel() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err != nil {
		return "Unknown CPU"
	}
	defer k.Close()

	name, _, err := k.GetStringValue("ProcessorNameString")
	if err != nil {
		return "Unknown CPU"
	}
	return name
}

var lastIdleTime, lastKernelTime, lastUserTime uint64

func getCPUUsageWindows() float64 {
	var idleTime, kernelTime, userTime windows.Filetime
	ret, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)))
	if ret == 0 {
		return 0
	}

	idle := uint64(idleTime.HighDateTime)<<32 | uint64(idleTime.LowDateTime)
	kernel := uint64(kernelTime.HighDateTime)<<32 | uint64(kernelTime.LowDateTime)
	user := uint64(userTime.HighDateTime)<<32 | uint64(userTime.LowDateTime)

	if lastIdleTime == 0 {
		lastIdleTime = idle
		lastKernelTime = kernel
		lastUserTime = user
		time.Sleep(100 * time.Millisecond)
		return getCPUUsageWindows()
	}

	idleDiff := idle - lastIdleTime
	kernelDiff := kernel - lastKernelTime
	userDiff := user - lastUserTime

	lastIdleTime = idle
	lastKernelTime = kernel
	lastUserTime = user

	total := kernelDiff + userDiff
	if total == 0 {
		return 0
	}

	return 100.0 * float64(total-idleDiff) / float64(total)
}

func getDiskInfoWindows() []models.DiskInfo {
	var disks []models.DiskInfo

	ret, _, _ := procGetLogicalDrives.Call()
	drives := uint32(ret)

	for i := 0; i < 26; i++ {
		if drives&(1<<uint(i)) == 0 {
			continue
		}

		drive := string('A'+i) + ":\\"
		drivePtr, _ := syscall.UTF16PtrFromString(drive)

		driveType := windows.GetDriveType(drivePtr)
		if driveType != windows.DRIVE_FIXED && driveType != windows.DRIVE_REMOVABLE {
			continue
		}

		var freeBytesAvailable, totalBytes, totalFreeBytes uint64
		ret, _, _ := procGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(drivePtr)),
			uintptr(unsafe.Pointer(&freeBytesAvailable)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFreeBytes)))

		if ret == 0 {
			continue
		}

		// Get filesystem type
		var volumeNameBuf [256]uint16
		var fsNameBuf [256]uint16
		procGetVolumeInformationW.Call(
			uintptr(unsafe.Pointer(drivePtr)),
			uintptr(unsafe.Pointer(&volumeNameBuf[0])), 256,
			0, 0, 0,
			uintptr(unsafe.Pointer(&fsNameBuf[0])), 256)

		fsType := syscall.UTF16ToString(fsNameBuf[:])

		used := totalBytes - totalFreeBytes
		usedPct := 0.0
		if totalBytes > 0 {
			usedPct = 100.0 * float64(used) / float64(totalBytes)
		}

		disks = append(disks, models.DiskInfo{
			Device:     drive,
			MountPoint: drive,
			FSType:     fsType,
			Total:      totalBytes,
			Used:       used,
			Free:       totalFreeBytes,
			UsedPct:    usedPct,
		})
	}

	return disks
}

func getNetworkInfoWindows() []models.NetInfo {
	// Simplified network info using Go's net package
	var nets []models.NetInfo

	// Use standard library for network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nets
	}

	for _, iface := range ifaces {
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

		nets = append(nets, netInfo)
	}

	return nets
}

// GetProcessListWindows retrieves the list of running processes on Windows
func GetProcessListWindows() ([]models.ProcessInfo, error) {
	var processes []models.ProcessInfo

	// Get list of process IDs
	var pids [4096]uint32
	var needed uint32
	ret, _, _ := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)*4),
		uintptr(unsafe.Pointer(&needed)))
	if ret == 0 {
		return nil, fmt.Errorf("EnumProcesses failed")
	}

	numProcs := needed / 4

	for i := uint32(0); i < numProcs; i++ {
		pid := pids[i]
		if pid == 0 {
			continue
		}

		proc, err := getProcessInfo(pid)
		if err != nil {
			continue
		}
		processes = append(processes, *proc)
	}

	return processes, nil
}

func getProcessInfo(pid uint32) (*models.ProcessInfo, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ,
		false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	proc := &models.ProcessInfo{
		PID:    int32(pid),
		Status: "running",
	}

	// Get process name
	var exePath [windows.MAX_PATH]uint16
	size := uint32(windows.MAX_PATH)
	err = windows.QueryFullProcessImageName(handle, 0, &exePath[0], &size)
	if err == nil {
		proc.Exe = syscall.UTF16ToString(exePath[:size])
		// Extract just the filename
		for i := len(proc.Exe) - 1; i >= 0; i-- {
			if proc.Exe[i] == '\\' {
				proc.Name = proc.Exe[i+1:]
				break
			}
		}
		if proc.Name == "" {
			proc.Name = proc.Exe
		}
	}

	// Get memory info
	var memInfo processMemoryCountersEx
	memInfo.CB = uint32(unsafe.Sizeof(memInfo))
	ret, _, _ := procGetProcessMemoryInfo.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&memInfo)),
		uintptr(memInfo.CB))
	if ret != 0 {
		proc.MemRSS = uint64(memInfo.WorkingSetSize)
	}

	// Get creation time
	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	err = windows.GetProcessTimes(handle, &creationTime, &exitTime, &kernelTime, &userTime)
	if err == nil {
		// Convert FILETIME to Unix timestamp
		nsec := int64(creationTime.HighDateTime)<<32 | int64(creationTime.LowDateTime)
		nsec -= 116444736000000000 // Difference between Windows and Unix epochs
		proc.CreateTime = time.Unix(nsec/10000000, (nsec%10000000)*100)
	}

	return proc, nil
}
