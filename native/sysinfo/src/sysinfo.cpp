#include "sysinfo.h"

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <windows.h>
    #include <psapi.h>
    #include <tlhelp32.h>
    #include <pdh.h>
    #include <iphlpapi.h>
    #include <intrin.h>
    #pragma comment(lib, "pdh.lib")
    #pragma comment(lib, "psapi.lib")
    #pragma comment(lib, "iphlpapi.lib")
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <sys/statvfs.h>
    #include <sys/sysinfo.h>
    #include <sys/utsname.h>
    #include <sys/wait.h>
    #include <dirent.h>
    #include <pwd.h>
    #include <signal.h>
    #include <fstream>
    #include <sstream>
    #include <ifaddrs.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

// Global state
static std::mutex g_mutex;
static std::string g_last_error;
static std::atomic<bool> g_initialized{false};

// Version
static const char* VERSION = "1.0.0";

// ============================================================================
// Helper Functions
// ============================================================================

static void set_error(const char* msg) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_last_error = msg;
}

static void safe_strcpy(char* dest, size_t dest_size, const char* src) {
    if (!dest || dest_size == 0) return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    size_t len = strlen(src);
    if (len >= dest_size) len = dest_size - 1;
    memcpy(dest, src, len);
    dest[len] = '\0';
}

#ifdef _WIN32
// Windows-specific helpers
static std::string GetWindowsVersionString() {
    OSVERSIONINFOEXW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        if (fxPtr) {
            fxPtr((PRTL_OSVERSIONINFOW)&osvi);
        }
    }
    
    char buf[128];
    snprintf(buf, sizeof(buf), "%lu.%lu.%lu", 
             osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    return buf;
}

static std::string WideToUtf8(const wchar_t* wstr) {
    if (!wstr) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size, nullptr, nullptr);
    return result;
}
#endif

// ============================================================================
// System Information Implementation
// ============================================================================

SYSINFO_API int sysinfo_get_system_info(SystemInfo* info) {
    if (!info) return SYSINFO_ERR_MEMORY;
    memset(info, 0, sizeof(SystemInfo));

#ifdef _WIN32
    // Hostname
    DWORD size = sizeof(info->hostname);
    GetComputerNameA(info->hostname, &size);

    // OS info
    safe_strcpy(info->os_name, sizeof(info->os_name), "Windows");
    std::string ver = GetWindowsVersionString();
    safe_strcpy(info->os_version, sizeof(info->os_version), ver.c_str());

    // Architecture
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            safe_strcpy(info->arch, sizeof(info->arch), "x86_64");
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            safe_strcpy(info->arch, sizeof(info->arch), "arm64");
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            safe_strcpy(info->arch, sizeof(info->arch), "x86");
            break;
        default:
            safe_strcpy(info->arch, sizeof(info->arch), "unknown");
    }

    // CPU info
    info->cpu_cores = si.dwNumberOfProcessors;
    
    // Get CPU model from registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type, bufSize = sizeof(info->cpu_model);
        RegQueryValueExA(hKey, "ProcessorNameString", nullptr, &type, 
                        (LPBYTE)info->cpu_model, &bufSize);
        RegCloseKey(hKey);
    }

    // Memory info
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        info->memory_total = memStatus.ullTotalPhys;
        info->memory_free = memStatus.ullAvailPhys;
        info->memory_used = info->memory_total - info->memory_free;
    }

    // Uptime
    info->uptime_seconds = GetTickCount64() / 1000;
    info->boot_time = time(nullptr) - info->uptime_seconds;

    // CPU usage (requires PDH, simplified here)
    sysinfo_get_cpu_usage(&info->cpu_usage);

#else
    // Linux implementation
    
    // Hostname
    gethostname(info->hostname, sizeof(info->hostname));

    // OS info from uname
    struct utsname uts;
    if (uname(&uts) == 0) {
        safe_strcpy(info->os_name, sizeof(info->os_name), uts.sysname);
        safe_strcpy(info->os_version, sizeof(info->os_version), uts.release);
        safe_strcpy(info->arch, sizeof(info->arch), uts.machine);
    }

    // CPU info from /proc/cpuinfo
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        int cores = 0;
        while (std::getline(cpuinfo, line)) {
            if (line.find("model name") != std::string::npos) {
                size_t pos = line.find(':');
                if (pos != std::string::npos) {
                    std::string model = line.substr(pos + 2);
                    safe_strcpy(info->cpu_model, sizeof(info->cpu_model), model.c_str());
                }
            }
            if (line.find("processor") != std::string::npos) {
                cores++;
            }
        }
        info->cpu_cores = cores > 0 ? cores : 1;
    }

    // Memory info from /proc/meminfo
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
        std::string line;
        while (std::getline(meminfo, line)) {
            uint64_t value;
            if (sscanf(line.c_str(), "MemTotal: %lu kB", &value) == 1)
                info->memory_total = value * 1024;
            else if (sscanf(line.c_str(), "MemFree: %lu kB", &value) == 1)
                info->memory_free = value * 1024;
            else if (sscanf(line.c_str(), "Cached: %lu kB", &value) == 1)
                info->memory_cached = value * 1024;
        }
        info->memory_used = info->memory_total - info->memory_free;
    }

    // Uptime from /proc/uptime
    std::ifstream uptime_file("/proc/uptime");
    if (uptime_file.is_open()) {
        double uptime;
        uptime_file >> uptime;
        info->uptime_seconds = static_cast<int64_t>(uptime);
    }
    info->boot_time = time(nullptr) - info->uptime_seconds;

    // CPU usage
    sysinfo_get_cpu_usage(&info->cpu_usage);
#endif

    return SYSINFO_OK;
}

SYSINFO_API int sysinfo_get_cpu_usage(double* usage) {
    if (!usage) return SYSINFO_ERR_MEMORY;

#ifdef _WIN32
    static PDH_HQUERY cpuQuery = nullptr;
    static PDH_HCOUNTER cpuTotal = nullptr;
    static bool initialized = false;

    if (!initialized) {
        PdhOpenQuery(nullptr, 0, &cpuQuery);
        PdhAddEnglishCounterA(cpuQuery, "\\Processor(_Total)\\% Processor Time", 
                              0, &cpuTotal);
        PdhCollectQueryData(cpuQuery);
        initialized = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    PDH_FMT_COUNTERVALUE counterVal;
    PdhCollectQueryData(cpuQuery);
    PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_DOUBLE, nullptr, &counterVal);
    *usage = counterVal.doubleValue;

#else
    static uint64_t prev_idle = 0, prev_total = 0;
    
    std::ifstream stat("/proc/stat");
    if (!stat.is_open()) {
        set_error("Failed to open /proc/stat");
        return SYSINFO_ERR_ACCESS;
    }

    std::string line;
    std::getline(stat, line);
    
    uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
    sscanf(line.c_str(), "cpu %lu %lu %lu %lu %lu %lu %lu %lu",
           &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);

    uint64_t total_idle = idle + iowait;
    uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal;

    uint64_t diff_idle = total_idle - prev_idle;
    uint64_t diff_total = total - prev_total;

    if (diff_total > 0) {
        *usage = 100.0 * (1.0 - static_cast<double>(diff_idle) / diff_total);
    } else {
        *usage = 0.0;
    }

    prev_idle = total_idle;
    prev_total = total;
#endif

    return SYSINFO_OK;
}

SYSINFO_API int sysinfo_get_memory_info(uint64_t* total, uint64_t* used,
                                        uint64_t* free, uint64_t* cached) {
    SystemInfo info;
    int ret = sysinfo_get_system_info(&info);
    if (ret != SYSINFO_OK) return ret;

    if (total) *total = info.memory_total;
    if (used) *used = info.memory_used;
    if (free) *free = info.memory_free;
    if (cached) *cached = info.memory_cached;

    return SYSINFO_OK;
}

// ============================================================================
// Disk Functions Implementation
// ============================================================================

SYSINFO_API int sysinfo_get_disk_info(DiskInfo* disk_array, int32_t* count,
                                      int32_t max_count) {
    if (!disk_array || !count || max_count <= 0) return SYSINFO_ERR_MEMORY;
    *count = 0;

#ifdef _WIN32
    DWORD drives = GetLogicalDrives();
    char drive[] = "A:\\";
    
    for (int i = 0; i < 26 && *count < max_count; i++) {
        if (drives & (1 << i)) {
            drive[0] = 'A' + i;
            
            UINT type = GetDriveTypeA(drive);
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
                DiskInfo* disk = &disk_array[*count];
                memset(disk, 0, sizeof(DiskInfo));
                
                safe_strcpy(disk->device, sizeof(disk->device), drive);
                safe_strcpy(disk->mount_point, sizeof(disk->mount_point), drive);

                char fsName[64] = {0};
                GetVolumeInformationA(drive, nullptr, 0, nullptr, nullptr, nullptr,
                                     fsName, sizeof(fsName));
                safe_strcpy(disk->fs_type, sizeof(disk->fs_type), fsName);

                ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
                if (GetDiskFreeSpaceExA(drive, &freeBytesAvailable, &totalBytes,
                                        &totalFreeBytes)) {
                    disk->total_bytes = totalBytes.QuadPart;
                    disk->free_bytes = totalFreeBytes.QuadPart;
                    disk->used_bytes = disk->total_bytes - disk->free_bytes;
                    if (disk->total_bytes > 0) {
                        disk->used_percent = 100.0 * disk->used_bytes / disk->total_bytes;
                    }
                }

                (*count)++;
            }
        }
    }

#else
    FILE* mounts = fopen("/proc/mounts", "r");
    if (!mounts) {
        set_error("Failed to open /proc/mounts");
        return SYSINFO_ERR_ACCESS;
    }

    char line[1024];
    while (fgets(line, sizeof(line), mounts) && *count < max_count) {
        char device[256], mount_point[256], fs_type[64];
        if (sscanf(line, "%255s %255s %63s", device, mount_point, fs_type) == 3) {
            // Skip virtual filesystems
            if (strncmp(device, "/dev/", 5) != 0) continue;
            if (strcmp(fs_type, "tmpfs") == 0) continue;
            if (strcmp(fs_type, "devtmpfs") == 0) continue;

            struct statvfs stat;
            if (statvfs(mount_point, &stat) == 0) {
                DiskInfo* disk = &disk_array[*count];
                memset(disk, 0, sizeof(DiskInfo));

                safe_strcpy(disk->device, sizeof(disk->device), device);
                safe_strcpy(disk->mount_point, sizeof(disk->mount_point), mount_point);
                safe_strcpy(disk->fs_type, sizeof(disk->fs_type), fs_type);

                disk->total_bytes = stat.f_blocks * stat.f_frsize;
                disk->free_bytes = stat.f_bfree * stat.f_frsize;
                disk->used_bytes = disk->total_bytes - disk->free_bytes;
                if (disk->total_bytes > 0) {
                    disk->used_percent = 100.0 * disk->used_bytes / disk->total_bytes;
                }

                (*count)++;
            }
        }
    }

    fclose(mounts);
#endif

    return SYSINFO_OK;
}

// ============================================================================
// Network Functions Implementation
// ============================================================================

SYSINFO_API int sysinfo_get_network_info(NetworkInfo* net_array, int32_t* count,
                                         int32_t max_count) {
    if (!net_array || !count || max_count <= 0) return SYSINFO_ERR_MEMORY;
    *count = 0;

#ifdef _WIN32
    ULONG bufLen = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &bufLen);
    
    std::vector<char> buffer(bufLen);
    PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, adapters, &bufLen) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES adapter = adapters; 
             adapter && *count < max_count; 
             adapter = adapter->Next) {
            
            if (adapter->OperStatus != IfOperStatusUp) continue;
            
            NetworkInfo* net = &net_array[*count];
            memset(net, 0, sizeof(NetworkInfo));

            std::string name = WideToUtf8(adapter->FriendlyName);
            safe_strcpy(net->name, sizeof(net->name), name.c_str());

            // MAC address
            if (adapter->PhysicalAddressLength > 0) {
                snprintf(net->mac, sizeof(net->mac), 
                        "%02X:%02X:%02X:%02X:%02X:%02X",
                        adapter->PhysicalAddress[0], adapter->PhysicalAddress[1],
                        adapter->PhysicalAddress[2], adapter->PhysicalAddress[3],
                        adapter->PhysicalAddress[4], adapter->PhysicalAddress[5]);
            }

            // IP addresses
            for (PIP_ADAPTER_UNICAST_ADDRESS addr = adapter->FirstUnicastAddress;
                 addr && net->ip_count < 8;
                 addr = addr->Next) {
                
                char ip[64] = {0};
                if (addr->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in* sin = (struct sockaddr_in*)addr->Address.lpSockaddr;
                    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
                } else if (addr->Address.lpSockaddr->sa_family == AF_INET6) {
                    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)addr->Address.lpSockaddr;
                    inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
                }
                
                if (ip[0]) {
                    safe_strcpy(net->ip_addresses[net->ip_count], 64, ip);
                    net->ip_count++;
                }
            }

            net->mtu = adapter->Mtu;
            net->is_up = 1;

            (*count)++;
        }
    }

#else
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        set_error("Failed to get network interfaces");
        return SYSINFO_ERR_ACCESS;
    }

    // First pass: collect interface names
    std::vector<std::string> interfaces;
    for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        
        std::string name = ifa->ifa_name;
        bool found = false;
        for (const auto& existing : interfaces) {
            if (existing == name) {
                found = true;
                break;
            }
        }
        if (!found) interfaces.push_back(name);
    }

    // Second pass: gather info for each interface
    for (const auto& iface_name : interfaces) {
        if (*count >= max_count) break;
        
        NetworkInfo* net = &net_array[*count];
        memset(net, 0, sizeof(NetworkInfo));
        safe_strcpy(net->name, sizeof(net->name), iface_name.c_str());

        for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || iface_name != ifa->ifa_name) continue;

            if (ifa->ifa_addr->sa_family == AF_INET && net->ip_count < 8) {
                char ip[64];
                struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr;
                inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
                safe_strcpy(net->ip_addresses[net->ip_count], 64, ip);
                net->ip_count++;
            } else if (ifa->ifa_addr->sa_family == AF_INET6 && net->ip_count < 8) {
                char ip[64];
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)ifa->ifa_addr;
                inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
                safe_strcpy(net->ip_addresses[net->ip_count], 64, ip);
                net->ip_count++;
            }

            net->is_up = (ifa->ifa_flags & IFF_UP) ? 1 : 0;
        }

        // Read stats from /sys/class/net/
        std::string stats_path = "/sys/class/net/" + iface_name + "/statistics/";
        
        std::ifstream rx_bytes(stats_path + "rx_bytes");
        if (rx_bytes) rx_bytes >> net->bytes_recv;
        
        std::ifstream tx_bytes(stats_path + "tx_bytes");
        if (tx_bytes) tx_bytes >> net->bytes_sent;

        std::ifstream mtu_file("/sys/class/net/" + iface_name + "/mtu");
        if (mtu_file) mtu_file >> net->mtu;

        (*count)++;
    }

    freeifaddrs(ifaddr);
#endif

    return SYSINFO_OK;
}

// ============================================================================
// Process Functions Implementation
// ============================================================================

SYSINFO_API int sysinfo_get_process_list(ProcessInfo* proc_array, int32_t* count,
                                         int32_t max_count) {
    if (!proc_array || !count || max_count <= 0) return SYSINFO_ERR_MEMORY;
    *count = 0;

#ifdef _WIN32
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        set_error("Failed to create process snapshot");
        return SYSINFO_ERR_ACCESS;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (*count >= max_count) break;

            ProcessInfo* proc = &proc_array[*count];
            memset(proc, 0, sizeof(ProcessInfo));

            proc->pid = pe32.th32ProcessID;
            proc->ppid = pe32.th32ParentProcessID;
            proc->num_threads = pe32.cntThreads;
            proc->priority = pe32.pcPriClassBase;

            std::string name = WideToUtf8(pe32.szExeFile);
            safe_strcpy(proc->name, sizeof(proc->name), name.c_str());

            // Get additional info if we have access
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                                         FALSE, pe32.th32ProcessID);
            if (hProcess) {
                // Get exe path
                wchar_t exePath[MAX_PATH];
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, exePath, &size)) {
                    std::string path = WideToUtf8(exePath);
                    safe_strcpy(proc->exe_path, sizeof(proc->exe_path), path.c_str());
                }

                // Get memory info
                PROCESS_MEMORY_COUNTERS_EX pmc;
                if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                    proc->mem_rss = pmc.WorkingSetSize;
                    proc->mem_vms = pmc.PrivateUsage;
                }

                // Get creation time
                FILETIME create_time, exit_time, kernel_time, user_time;
                if (GetProcessTimes(hProcess, &create_time, &exit_time, &kernel_time, &user_time)) {
                    ULARGE_INTEGER uli;
                    uli.LowPart = create_time.dwLowDateTime;
                    uli.HighPart = create_time.dwHighDateTime;
                    // Convert from Windows epoch to Unix epoch
                    proc->create_time = (uli.QuadPart - 116444736000000000ULL) / 10000000ULL;
                }

                CloseHandle(hProcess);
            }

            safe_strcpy(proc->status, sizeof(proc->status), "running");
            (*count)++;

        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

#else
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        set_error("Failed to open /proc");
        return SYSINFO_ERR_ACCESS;
    }

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) && *count < max_count) {
        // Check if directory name is a number (PID)
        char* endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        ProcessInfo* proc = &proc_array[*count];
        memset(proc, 0, sizeof(ProcessInfo));
        proc->pid = static_cast<int32_t>(pid);

        std::string proc_path = "/proc/" + std::string(entry->d_name);

        // Read stat file
        std::ifstream stat(proc_path + "/stat");
        if (stat.is_open()) {
            std::string line;
            std::getline(stat, line);

            // Parse stat line (format: pid (name) state ppid ...)
            size_t start = line.find('(');
            size_t end = line.rfind(')');
            if (start != std::string::npos && end != std::string::npos) {
                std::string name = line.substr(start + 1, end - start - 1);
                safe_strcpy(proc->name, sizeof(proc->name), name.c_str());

                // Parse rest of stat
                std::string rest = line.substr(end + 2);
                char state;
                sscanf(rest.c_str(), "%c %d", &state, &proc->ppid);
                
                char status_str[2] = {state, '\0'};
                safe_strcpy(proc->status, sizeof(proc->status), status_str);
            }
        }

        // Read exe link
        char exe_path[512];
        ssize_t len = readlink((proc_path + "/exe").c_str(), exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = '\0';
            safe_strcpy(proc->exe_path, sizeof(proc->exe_path), exe_path);
        }

        // Read cmdline
        std::ifstream cmdline(proc_path + "/cmdline");
        if (cmdline.is_open()) {
            std::string cmd;
            std::getline(cmdline, cmd, '\0');
            safe_strcpy(proc->cmdline, sizeof(proc->cmdline), cmd.c_str());
        }

        // Read memory from statm
        std::ifstream statm(proc_path + "/statm");
        if (statm.is_open()) {
            uint64_t vms_pages, rss_pages;
            statm >> vms_pages >> rss_pages;
            long page_size = sysconf(_SC_PAGESIZE);
            proc->mem_vms = vms_pages * page_size;
            proc->mem_rss = rss_pages * page_size;
        }

        // Get user from status
        std::ifstream status(proc_path + "/status");
        if (status.is_open()) {
            std::string line;
            while (std::getline(status, line)) {
                unsigned int uid;
                if (sscanf(line.c_str(), "Uid: %u", &uid) == 1) {
                    struct passwd* pw = getpwuid(uid);
                    if (pw) {
                        safe_strcpy(proc->user, sizeof(proc->user), pw->pw_name);
                    }
                    break;
                }
            }
        }

        (*count)++;
    }

    closedir(proc_dir);
#endif

    return SYSINFO_OK;
}

SYSINFO_API int sysinfo_get_process_info(int32_t pid, ProcessInfo* info) {
    if (!info) return SYSINFO_ERR_MEMORY;

    ProcessInfo proc_array[1];
    int32_t count = 0;
    
    // Get full list and find the matching PID
    // This is inefficient but ensures consistent behavior
    std::vector<ProcessInfo> all_procs(4096);
    int32_t total = 0;
    int ret = sysinfo_get_process_list(all_procs.data(), &total, 4096);
    if (ret != SYSINFO_OK) return ret;

    for (int32_t i = 0; i < total; i++) {
        if (all_procs[i].pid == pid) {
            *info = all_procs[i];
            return SYSINFO_OK;
        }
    }

    set_error("Process not found");
    return SYSINFO_ERR_NOTFOUND;
}

SYSINFO_API int sysinfo_kill_process(int32_t pid, int32_t signal_num) {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        set_error("Failed to open process");
        return SYSINFO_ERR_ACCESS;
    }

    BOOL result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);

    if (!result) {
        set_error("Failed to terminate process");
        return SYSINFO_ERR_UNKNOWN;
    }
#else
    if (kill(pid, signal_num) != 0) {
        set_error("Failed to send signal to process");
        return SYSINFO_ERR_ACCESS;
    }
#endif

    return SYSINFO_OK;
}

SYSINFO_API int sysinfo_get_process_count(int32_t* count) {
    if (!count) return SYSINFO_ERR_MEMORY;

#ifdef _WIN32
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return SYSINFO_ERR_ACCESS;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    *count = 0;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            (*count)++;
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
#else
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return SYSINFO_ERR_ACCESS;

    *count = 0;
    struct dirent* entry;
    while ((entry = readdir(proc_dir))) {
        char* endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr == '\0' && pid > 0) {
            (*count)++;
        }
    }

    closedir(proc_dir);
#endif

    return SYSINFO_OK;
}

// ============================================================================
// Command Execution
// ============================================================================

SYSINFO_API int sysinfo_exec_command(const char* command, const char* args,
                                     int32_t timeout_ms, ExecResult* result) {
    if (!command || !result) return SYSINFO_ERR_MEMORY;
    
    memset(result, 0, sizeof(ExecResult));
    result->exit_code = -1;

#ifdef _WIN32
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        safe_strcpy(result->error, sizeof(result->error), "Failed to create pipe");
        return SYSINFO_ERR_UNKNOWN;
    }

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;

    PROCESS_INFORMATION pi = {0};

    std::string cmdline = std::string("cmd /c ") + command;
    if (args && args[0]) {
        cmdline += " ";
        cmdline += args;
    }

    if (!CreateProcessA(nullptr, const_cast<char*>(cmdline.c_str()),
                        nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        safe_strcpy(result->error, sizeof(result->error), "Failed to create process");
        return SYSINFO_ERR_UNKNOWN;
    }

    CloseHandle(hWritePipe);

    // Read output
    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    CloseHandle(hReadPipe);

    // Wait for process
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 
                                           timeout_ms > 0 ? timeout_ms : INFINITE);
    
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        result->timed_out = 1;
        safe_strcpy(result->error, sizeof(result->error), "Command timed out");
    }

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    result->exit_code = static_cast<int32_t>(exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Copy output
    result->output_size = output.size();
    result->output = static_cast<char*>(malloc(output.size() + 1));
    if (result->output) {
        memcpy(result->output, output.c_str(), output.size() + 1);
    }

#else
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        safe_strcpy(result->error, sizeof(result->error), "Failed to create pipe");
        return SYSINFO_ERR_UNKNOWN;
    }

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        safe_strcpy(result->error, sizeof(result->error), "Failed to fork");
        return SYSINFO_ERR_UNKNOWN;
    }

    if (pid == 0) {
        // Child process
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        std::string fullcmd = command;
        if (args && args[0]) {
            fullcmd += " ";
            fullcmd += args;
        }

        execl("/bin/sh", "sh", "-c", fullcmd.c_str(), nullptr);
        _exit(127);
    }

    // Parent process
    close(pipefd[1]);

    std::string output;
    char buffer[4096];
    ssize_t n;

    // Set non-blocking for timeout handling
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    auto start = std::chrono::steady_clock::now();
    bool timed_out = false;

    while (true) {
        n = read(pipefd[0], buffer, sizeof(buffer) - 1);
        if (n > 0) {
            buffer[n] = '\0';
            output += buffer;
        } else if (n == 0) {
            break;  // EOF
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Check timeout
            if (timeout_ms > 0) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
                if (elapsed > timeout_ms) {
                    timed_out = true;
                    kill(pid, SIGKILL);
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } else {
            break;  // Error
        }
    }

    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    if (timed_out) {
        result->timed_out = 1;
        safe_strcpy(result->error, sizeof(result->error), "Command timed out");
    }

    if (WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result->exit_code = -WTERMSIG(status);
    }

    // Copy output
    result->output_size = output.size();
    result->output = static_cast<char*>(malloc(output.size() + 1));
    if (result->output) {
        memcpy(result->output, output.c_str(), output.size() + 1);
    }
#endif

    return SYSINFO_OK;
}

SYSINFO_API void sysinfo_free_exec_result(ExecResult* result) {
    if (result && result->output) {
        free(result->output);
        result->output = nullptr;
        result->output_size = 0;
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

SYSINFO_API const char* sysinfo_get_version(void) {
    return VERSION;
}

SYSINFO_API int sysinfo_init(void) {
    if (g_initialized.exchange(true)) {
        return SYSINFO_OK;  // Already initialized
    }

#ifdef _WIN32
    // Initialize Winsock for network functions
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    return SYSINFO_OK;
}

SYSINFO_API void sysinfo_cleanup(void) {
    if (!g_initialized.exchange(false)) {
        return;  // Not initialized
    }

#ifdef _WIN32
    WSACleanup();
#endif
}

SYSINFO_API const char* sysinfo_get_error(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_last_error.c_str();
}
