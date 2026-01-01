#pragma once

#ifdef _WIN32
    #ifdef SYSINFO_EXPORTS
        #define SYSINFO_API __declspec(dllexport)
    #else
        #define SYSINFO_API __declspec(dllimport)
    #endif
#else
    #define SYSINFO_API
#endif

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define SYSINFO_OK              0
#define SYSINFO_ERR_UNKNOWN    -1
#define SYSINFO_ERR_MEMORY     -2
#define SYSINFO_ERR_ACCESS     -3
#define SYSINFO_ERR_NOTFOUND   -4
#define SYSINFO_ERR_TIMEOUT    -5

// System information structure
typedef struct {
    char hostname[256];
    char os_name[64];
    char os_version[128];
    char arch[32];
    char cpu_model[256];
    int32_t cpu_cores;
    int32_t cpu_threads;
    double cpu_usage;
    uint64_t memory_total;
    uint64_t memory_used;
    uint64_t memory_free;
    uint64_t memory_cached;
    int64_t uptime_seconds;
    int64_t boot_time;
} SystemInfo;

// Disk information
typedef struct {
    char device[256];
    char mount_point[256];
    char fs_type[64];
    uint64_t total_bytes;
    uint64_t used_bytes;
    uint64_t free_bytes;
    double used_percent;
} DiskInfo;

// Network interface information
typedef struct {
    char name[64];
    char mac[24];
    char ip_addresses[8][64];  // Up to 8 IP addresses
    int32_t ip_count;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t packets_sent;
    uint64_t packets_recv;
    int32_t mtu;
    int32_t is_up;
} NetworkInfo;

// Process information
typedef struct {
    int32_t pid;
    int32_t ppid;
    char name[256];
    char exe_path[512];
    char cmdline[1024];
    char user[64];
    char status[16];
    double cpu_percent;
    float mem_percent;
    uint64_t mem_rss;
    uint64_t mem_vms;
    int64_t create_time;
    int32_t num_threads;
    int32_t priority;
} ProcessInfo;

// Result buffer for variable-length results
typedef struct {
    void* data;
    size_t size;
    size_t capacity;
} ResultBuffer;

// ============================================================================
// System Information Functions
// ============================================================================

// Get basic system information
SYSINFO_API int sysinfo_get_system_info(SystemInfo* info);

// Get CPU usage (0-100%)
SYSINFO_API int sysinfo_get_cpu_usage(double* usage);

// Get CPU usage per core
SYSINFO_API int sysinfo_get_cpu_usage_per_core(double* usage_array, int32_t* core_count);

// Get memory information
SYSINFO_API int sysinfo_get_memory_info(uint64_t* total, uint64_t* used, 
                                        uint64_t* free, uint64_t* cached);

// ============================================================================
// Disk Functions
// ============================================================================

// Get disk information for all mounted filesystems
// Returns number of disks, fills disk_array (caller must allocate)
SYSINFO_API int sysinfo_get_disk_info(DiskInfo* disk_array, int32_t* count, 
                                      int32_t max_count);

// Get disk I/O statistics
SYSINFO_API int sysinfo_get_disk_io(const char* device, uint64_t* read_bytes,
                                    uint64_t* write_bytes, uint64_t* read_count,
                                    uint64_t* write_count);

// ============================================================================
// Network Functions
// ============================================================================

// Get network interface information
SYSINFO_API int sysinfo_get_network_info(NetworkInfo* net_array, int32_t* count,
                                         int32_t max_count);

// Get network I/O statistics
SYSINFO_API int sysinfo_get_network_io(uint64_t* bytes_sent, uint64_t* bytes_recv);

// ============================================================================
// Process Functions
// ============================================================================

// Get process list
// Returns number of processes, fills proc_array (caller must allocate)
SYSINFO_API int sysinfo_get_process_list(ProcessInfo* proc_array, int32_t* count,
                                         int32_t max_count);

// Get single process information
SYSINFO_API int sysinfo_get_process_info(int32_t pid, ProcessInfo* info);

// Kill a process
SYSINFO_API int sysinfo_kill_process(int32_t pid, int32_t signal);

// Get process count
SYSINFO_API int sysinfo_get_process_count(int32_t* count);

// ============================================================================
// Command Execution
// ============================================================================

typedef struct {
    char* output;
    size_t output_size;
    int32_t exit_code;
    int32_t timed_out;
    char error[256];
} ExecResult;

// Execute a command with timeout (in milliseconds)
SYSINFO_API int sysinfo_exec_command(const char* command, const char* args,
                                     int32_t timeout_ms, ExecResult* result);

// Free execution result
SYSINFO_API void sysinfo_free_exec_result(ExecResult* result);

// ============================================================================
// Utility Functions
// ============================================================================

// Get library version
SYSINFO_API const char* sysinfo_get_version(void);

// Initialize the library (call once at startup)
SYSINFO_API int sysinfo_init(void);

// Cleanup the library (call before exit)
SYSINFO_API void sysinfo_cleanup(void);

// Get last error message
SYSINFO_API const char* sysinfo_get_error(void);

#ifdef __cplusplus
}
#endif
