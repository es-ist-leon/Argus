package native

/*
#cgo CFLAGS: -I${SRCDIR}/../../native/sysinfo/include
#cgo windows LDFLAGS: -L${SRCDIR}/../../native/build -largus_sysinfo_static -lpdh -lpsapi -liphlpapi -lws2_32
#cgo linux LDFLAGS: -L${SRCDIR}/../../native/build -largus_sysinfo_static -lpthread -lstdc++

#include "sysinfo.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/argus/argus/pkg/models"
)

// NativeModule provides access to C++ native functions
type NativeModule struct {
	initialized bool
}

// NewNativeModule creates a new native module instance
func NewNativeModule() (*NativeModule, error) {
	ret := C.sysinfo_init()
	if ret != C.SYSINFO_OK {
		return nil, fmt.Errorf("failed to initialize native module: %s", C.GoString(C.sysinfo_get_error()))
	}

	return &NativeModule{initialized: true}, nil
}

// Close cleans up the native module
func (nm *NativeModule) Close() {
	if nm.initialized {
		C.sysinfo_cleanup()
		nm.initialized = false
	}
}

// GetSystemInfo retrieves system information using native code
func (nm *NativeModule) GetSystemInfo() (*models.SystemInfo, error) {
	var info C.SystemInfo
	ret := C.sysinfo_get_system_info(&info)
	if ret != C.SYSINFO_OK {
		return nil, fmt.Errorf("failed to get system info: %s", C.GoString(C.sysinfo_get_error()))
	}

	// Get disk info
	var disks [16]C.DiskInfo
	var diskCount C.int32_t
	C.sysinfo_get_disk_info(&disks[0], &diskCount, 16)

	diskInfo := make([]models.DiskInfo, int(diskCount))
	for i := 0; i < int(diskCount); i++ {
		diskInfo[i] = models.DiskInfo{
			Device:     C.GoString(&disks[i].device[0]),
			MountPoint: C.GoString(&disks[i].mount_point[0]),
			FSType:     C.GoString(&disks[i].fs_type[0]),
			Total:      uint64(disks[i].total_bytes),
			Used:       uint64(disks[i].used_bytes),
			Free:       uint64(disks[i].free_bytes),
			UsedPct:    float64(disks[i].used_percent),
		}
	}

	// Get network info
	var nets [16]C.NetworkInfo
	var netCount C.int32_t
	C.sysinfo_get_network_info(&nets[0], &netCount, 16)

	netInfo := make([]models.NetInfo, int(netCount))
	for i := 0; i < int(netCount); i++ {
		ips := make([]string, int(nets[i].ip_count))
		for j := 0; j < int(nets[i].ip_count); j++ {
			ips[j] = C.GoString(&nets[i].ip_addresses[j][0])
		}
		netInfo[i] = models.NetInfo{
			Name:      C.GoString(&nets[i].name[0]),
			MAC:       C.GoString(&nets[i].mac[0]),
			IPs:       ips,
			BytesSent: uint64(nets[i].bytes_sent),
			BytesRecv: uint64(nets[i].bytes_recv),
		}
	}

	return &models.SystemInfo{
		Hostname:    C.GoString(&info.hostname[0]),
		OS:          C.GoString(&info.os_name[0]),
		OSVersion:   C.GoString(&info.os_version[0]),
		Arch:        C.GoString(&info.arch[0]),
		CPUModel:    C.GoString(&info.cpu_model[0]),
		CPUCores:    int(info.cpu_cores),
		CPUUsage:    float64(info.cpu_usage),
		MemoryTotal: uint64(info.memory_total),
		MemoryUsed:  uint64(info.memory_used),
		MemoryFree:  uint64(info.memory_free),
		DiskInfo:    diskInfo,
		NetworkInfo: netInfo,
		Uptime:      int64(info.uptime_seconds),
		BootTime:    time.Unix(int64(info.boot_time), 0),
	}, nil
}

// GetProcessList retrieves the list of running processes
func (nm *NativeModule) GetProcessList() ([]models.ProcessInfo, error) {
	var procs [4096]C.ProcessInfo
	var count C.int32_t
	ret := C.sysinfo_get_process_list(&procs[0], &count, 4096)
	if ret != C.SYSINFO_OK {
		return nil, fmt.Errorf("failed to get process list: %s", C.GoString(C.sysinfo_get_error()))
	}

	processes := make([]models.ProcessInfo, int(count))
	for i := 0; i < int(count); i++ {
		processes[i] = models.ProcessInfo{
			PID:        int32(procs[i].pid),
			PPID:       int32(procs[i].ppid),
			Name:       C.GoString(&procs[i].name[0]),
			Exe:        C.GoString(&procs[i].exe_path[0]),
			Cmdline:    C.GoString(&procs[i].cmdline[0]),
			User:       C.GoString(&procs[i].user[0]),
			Status:     C.GoString(&procs[i].status[0]),
			CPUPercent: float64(procs[i].cpu_percent),
			MemPercent: float32(procs[i].mem_percent),
			MemRSS:     uint64(procs[i].mem_rss),
			CreateTime: time.Unix(int64(procs[i].create_time), 0),
		}
	}

	return processes, nil
}

// KillProcess terminates a process by PID
func (nm *NativeModule) KillProcess(pid int32) error {
	ret := C.sysinfo_kill_process(C.int32_t(pid), 9) // SIGKILL
	if ret != C.SYSINFO_OK {
		return fmt.Errorf("failed to kill process %d: %s", pid, C.GoString(C.sysinfo_get_error()))
	}
	return nil
}

// ExecuteCommand executes a command and returns output
func (nm *NativeModule) ExecuteCommand(cmd string, args []string, timeout time.Duration) (string, int, error) {
	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))

	argsStr := ""
	for i, arg := range args {
		if i > 0 {
			argsStr += " "
		}
		argsStr += arg
	}
	cArgs := C.CString(argsStr)
	defer C.free(unsafe.Pointer(cArgs))

	timeoutMs := int32(timeout.Milliseconds())
	if timeoutMs <= 0 {
		timeoutMs = 300000 // 5 minute default
	}

	var result C.ExecResult
	ret := C.sysinfo_exec_command(cCmd, cArgs, C.int32_t(timeoutMs), &result)
	defer C.sysinfo_free_exec_result(&result)

	if ret != C.SYSINFO_OK {
		return "", -1, fmt.Errorf("command execution failed: %s", C.GoString(C.sysinfo_get_error()))
	}

	output := ""
	if result.output != nil {
		output = C.GoString(result.output)
	}

	if result.timed_out != 0 {
		return output, int(result.exit_code), fmt.Errorf("command timed out")
	}

	if result.error[0] != 0 {
		return output, int(result.exit_code), fmt.Errorf("%s", C.GoString(&result.error[0]))
	}

	return output, int(result.exit_code), nil
}

// GetCPUUsage returns current CPU usage percentage
func (nm *NativeModule) GetCPUUsage() (float64, error) {
	var usage C.double
	ret := C.sysinfo_get_cpu_usage(&usage)
	if ret != C.SYSINFO_OK {
		return 0, fmt.Errorf("failed to get CPU usage: %s", C.GoString(C.sysinfo_get_error()))
	}
	return float64(usage), nil
}

// GetMemoryInfo returns memory statistics
func (nm *NativeModule) GetMemoryInfo() (total, used, free, cached uint64, err error) {
	var t, u, f, c C.uint64_t
	ret := C.sysinfo_get_memory_info(&t, &u, &f, &c)
	if ret != C.SYSINFO_OK {
		return 0, 0, 0, 0, fmt.Errorf("failed to get memory info: %s", C.GoString(C.sysinfo_get_error()))
	}
	return uint64(t), uint64(u), uint64(f), uint64(c), nil
}

// GetProcessCount returns the number of running processes
func (nm *NativeModule) GetProcessCount() (int, error) {
	var count C.int32_t
	ret := C.sysinfo_get_process_count(&count)
	if ret != C.SYSINFO_OK {
		return 0, fmt.Errorf("failed to get process count: %s", C.GoString(C.sysinfo_get_error()))
	}
	return int(count), nil
}

// Version returns the native library version
func (nm *NativeModule) Version() string {
	return C.GoString(C.sysinfo_get_version())
}
