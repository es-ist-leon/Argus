#include "sysinfo.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <thread>
#include <chrono>

void printSeparator(const std::string& title) {
    std::cout << "\n========================================\n";
    std::cout << "  " << title << "\n";
    std::cout << "========================================\n";
}

void testSystemInfo() {
    printSeparator("System Information");
    
    SystemInfo info;
    int ret = sysinfo_get_system_info(&info);
    
    if (ret != SYSINFO_OK) {
        std::cerr << "ERROR: Failed to get system info: " << sysinfo_get_error() << std::endl;
        return;
    }
    
    std::cout << "Hostname:    " << info.hostname << std::endl;
    std::cout << "OS:          " << info.os_name << " " << info.os_version << std::endl;
    std::cout << "Arch:        " << info.arch << std::endl;
    std::cout << "CPU Model:   " << info.cpu_model << std::endl;
    std::cout << "CPU Cores:   " << info.cpu_cores << std::endl;
    std::cout << "CPU Usage:   " << std::fixed << std::setprecision(1) << info.cpu_usage << "%" << std::endl;
    std::cout << "Memory Total: " << (info.memory_total / 1024 / 1024) << " MB" << std::endl;
    std::cout << "Memory Used:  " << (info.memory_used / 1024 / 1024) << " MB" << std::endl;
    std::cout << "Memory Free:  " << (info.memory_free / 1024 / 1024) << " MB" << std::endl;
    std::cout << "Uptime:      " << (info.uptime_seconds / 3600) << " hours" << std::endl;
    std::cout << "Boot Time:   " << info.boot_time << std::endl;
}

void testCPUUsage() {
    printSeparator("CPU Usage (5 samples)");
    
    for (int i = 0; i < 5; i++) {
        double usage;
        int ret = sysinfo_get_cpu_usage(&usage);
        
        if (ret == SYSINFO_OK) {
            std::cout << "Sample " << (i+1) << ": " 
                      << std::fixed << std::setprecision(1) << usage << "%" << std::endl;
        } else {
            std::cerr << "Failed to get CPU usage" << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void testDiskInfo() {
    printSeparator("Disk Information");
    
    DiskInfo disks[16];
    int32_t count;
    int ret = sysinfo_get_disk_info(disks, &count, 16);
    
    if (ret != SYSINFO_OK) {
        std::cerr << "ERROR: Failed to get disk info: " << sysinfo_get_error() << std::endl;
        return;
    }
    
    std::cout << "Found " << count << " disk(s):\n" << std::endl;
    
    for (int i = 0; i < count; i++) {
        std::cout << "Device:      " << disks[i].device << std::endl;
        std::cout << "Mount Point: " << disks[i].mount_point << std::endl;
        std::cout << "FS Type:     " << disks[i].fs_type << std::endl;
        std::cout << "Total:       " << (disks[i].total_bytes / 1024 / 1024 / 1024) << " GB" << std::endl;
        std::cout << "Used:        " << (disks[i].used_bytes / 1024 / 1024 / 1024) << " GB" << std::endl;
        std::cout << "Free:        " << (disks[i].free_bytes / 1024 / 1024 / 1024) << " GB" << std::endl;
        std::cout << "Used %:      " << std::fixed << std::setprecision(1) << disks[i].used_percent << "%" << std::endl;
        std::cout << std::endl;
    }
}

void testNetworkInfo() {
    printSeparator("Network Information");
    
    NetworkInfo nets[16];
    int32_t count;
    int ret = sysinfo_get_network_info(nets, &count, 16);
    
    if (ret != SYSINFO_OK) {
        std::cerr << "ERROR: Failed to get network info: " << sysinfo_get_error() << std::endl;
        return;
    }
    
    std::cout << "Found " << count << " interface(s):\n" << std::endl;
    
    for (int i = 0; i < count; i++) {
        std::cout << "Interface:   " << nets[i].name << std::endl;
        std::cout << "MAC:         " << nets[i].mac << std::endl;
        std::cout << "Status:      " << (nets[i].is_up ? "UP" : "DOWN") << std::endl;
        std::cout << "MTU:         " << nets[i].mtu << std::endl;
        
        std::cout << "IP Addresses:" << std::endl;
        for (int j = 0; j < nets[i].ip_count; j++) {
            std::cout << "  - " << nets[i].ip_addresses[j] << std::endl;
        }
        
        std::cout << "Bytes Sent:  " << (nets[i].bytes_sent / 1024 / 1024) << " MB" << std::endl;
        std::cout << "Bytes Recv:  " << (nets[i].bytes_recv / 1024 / 1024) << " MB" << std::endl;
        std::cout << std::endl;
    }
}

void testProcessList() {
    printSeparator("Process List (top 10 by memory)");
    
    ProcessInfo procs[4096];
    int32_t count;
    int ret = sysinfo_get_process_list(procs, &count, 4096);
    
    if (ret != SYSINFO_OK) {
        std::cerr << "ERROR: Failed to get process list: " << sysinfo_get_error() << std::endl;
        return;
    }
    
    std::cout << "Total processes: " << count << "\n" << std::endl;
    
    // Sort by memory (simple bubble sort for demo)
    for (int i = 0; i < count - 1 && i < 100; i++) {
        for (int j = i + 1; j < count; j++) {
            if (procs[j].mem_rss > procs[i].mem_rss) {
                ProcessInfo temp = procs[i];
                procs[i] = procs[j];
                procs[j] = temp;
            }
        }
    }
    
    std::cout << std::setw(8) << "PID"
              << std::setw(20) << "NAME"
              << std::setw(10) << "CPU %"
              << std::setw(12) << "MEM (MB)"
              << std::setw(10) << "STATUS"
              << std::endl;
    std::cout << std::string(60, '-') << std::endl;
    
    int displayed = 0;
    for (int i = 0; i < count && displayed < 10; i++) {
        if (procs[i].name[0] == '\0') continue;
        
        std::cout << std::setw(8) << procs[i].pid
                  << std::setw(20) << std::string(procs[i].name).substr(0, 19)
                  << std::setw(10) << std::fixed << std::setprecision(1) << procs[i].cpu_percent
                  << std::setw(12) << (procs[i].mem_rss / 1024 / 1024)
                  << std::setw(10) << procs[i].status
                  << std::endl;
        displayed++;
    }
}

void testCommandExecution() {
    printSeparator("Command Execution");
    
#ifdef _WIN32
    const char* cmd = "echo";
    const char* args = "Hello from native module!";
#else
    const char* cmd = "echo";
    const char* args = "Hello from native module!";
#endif
    
    ExecResult result;
    int ret = sysinfo_exec_command(cmd, args, 5000, &result);
    
    if (ret != SYSINFO_OK) {
        std::cerr << "ERROR: Command execution failed: " << sysinfo_get_error() << std::endl;
        return;
    }
    
    std::cout << "Exit Code: " << result.exit_code << std::endl;
    std::cout << "Timed Out: " << (result.timed_out ? "Yes" : "No") << std::endl;
    
    if (result.output) {
        std::cout << "Output:\n" << result.output << std::endl;
    }
    
    if (result.error[0] != '\0') {
        std::cout << "Error: " << result.error << std::endl;
    }
    
    sysinfo_free_exec_result(&result);
}

void testProcessKill() {
    printSeparator("Process Operations");
    
    // Get process count
    int32_t count;
    int ret = sysinfo_get_process_count(&count);
    
    if (ret == SYSINFO_OK) {
        std::cout << "Current process count: " << count << std::endl;
    }
    
    // Note: We don't actually kill a process in tests
    std::cout << "Skipping process kill test (would require spawning a test process)" << std::endl;
}

void testMemoryInfo() {
    printSeparator("Memory Information");
    
    uint64_t total, used, free, cached;
    int ret = sysinfo_get_memory_info(&total, &used, &free, &cached);
    
    if (ret != SYSINFO_OK) {
        std::cerr << "ERROR: Failed to get memory info: " << sysinfo_get_error() << std::endl;
        return;
    }
    
    std::cout << "Total:  " << (total / 1024 / 1024) << " MB" << std::endl;
    std::cout << "Used:   " << (used / 1024 / 1024) << " MB" << std::endl;
    std::cout << "Free:   " << (free / 1024 / 1024) << " MB" << std::endl;
    std::cout << "Cached: " << (cached / 1024 / 1024) << " MB" << std::endl;
    
    double usedPct = 100.0 * used / total;
    std::cout << "Usage:  " << std::fixed << std::setprecision(1) << usedPct << "%" << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "==================================================" << std::endl;
    std::cout << "  Argus Native Library Test Suite" << std::endl;
    std::cout << "  Version: " << sysinfo_get_version() << std::endl;
    std::cout << "==================================================" << std::endl;
    
    // Initialize library
    int ret = sysinfo_init();
    if (ret != SYSINFO_OK) {
        std::cerr << "FATAL: Failed to initialize library: " << sysinfo_get_error() << std::endl;
        return 1;
    }
    
    std::cout << "\nLibrary initialized successfully.\n" << std::endl;
    
    // Run tests
    testSystemInfo();
    testCPUUsage();
    testMemoryInfo();
    testDiskInfo();
    testNetworkInfo();
    testProcessList();
    testCommandExecution();
    testProcessKill();
    
    // Cleanup
    sysinfo_cleanup();
    
    printSeparator("Test Complete");
    std::cout << "All tests completed. Library cleaned up." << std::endl;
    
    return 0;
}
