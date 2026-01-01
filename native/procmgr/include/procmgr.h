#pragma once

#ifdef _WIN32
    #ifdef PROCMGR_EXPORTS
        #define PROCMGR_API __declspec(dllexport)
    #else
        #define PROCMGR_API __declspec(dllimport)
    #endif
#else
    #define PROCMGR_API
#endif

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define PROCMGR_OK              0
#define PROCMGR_ERR_UNKNOWN    -1
#define PROCMGR_ERR_MEMORY     -2
#define PROCMGR_ERR_ACCESS     -3
#define PROCMGR_ERR_NOTFOUND   -4
#define PROCMGR_ERR_TIMEOUT    -5
#define PROCMGR_ERR_INVALID    -6

// Process priority levels
#define PROC_PRIORITY_IDLE          0
#define PROC_PRIORITY_BELOW_NORMAL  1
#define PROC_PRIORITY_NORMAL        2
#define PROC_PRIORITY_ABOVE_NORMAL  3
#define PROC_PRIORITY_HIGH          4
#define PROC_PRIORITY_REALTIME      5

// Process state
typedef enum {
    PROC_STATE_RUNNING,
    PROC_STATE_SLEEPING,
    PROC_STATE_WAITING,
    PROC_STATE_STOPPED,
    PROC_STATE_ZOMBIE,
    PROC_STATE_UNKNOWN
} ProcessState;

// Extended process information
typedef struct {
    int32_t pid;
    int32_t ppid;
    int32_t session_id;
    char name[256];
    char exe_path[512];
    char cmdline[2048];
    char user[64];
    char domain[64];
    ProcessState state;
    int32_t priority;
    int32_t base_priority;
    int32_t num_threads;
    int32_t num_handles;
    double cpu_percent;
    float mem_percent;
    uint64_t mem_rss;
    uint64_t mem_vms;
    uint64_t mem_private;
    uint64_t read_bytes;
    uint64_t write_bytes;
    int64_t create_time;
    int64_t kernel_time;
    int64_t user_time;
    int32_t is_elevated;
    int32_t is_64bit;
} ProcessInfoEx;

// Thread information
typedef struct {
    int32_t tid;
    int32_t pid;
    int32_t priority;
    int32_t base_priority;
    ProcessState state;
    uint64_t start_address;
    int64_t kernel_time;
    int64_t user_time;
} ThreadInfo;

// Module information
typedef struct {
    char name[256];
    char path[512];
    uint64_t base_address;
    uint64_t size;
    int32_t is_loaded;
} ModuleInfo;

// Memory region information
typedef struct {
    uint64_t base_address;
    uint64_t size;
    uint32_t protection;
    uint32_t state;
    uint32_t type;
} MemoryRegion;

// Process handle information
typedef struct {
    uint32_t handle;
    uint32_t type;
    char name[256];
    int32_t pid;
} HandleInfo;

// ============================================================================
// Process Management Functions
// ============================================================================

// Get extended process information
PROCMGR_API int procmgr_get_process_info_ex(int32_t pid, ProcessInfoEx* info);

// Get all processes (extended info)
PROCMGR_API int procmgr_get_process_list_ex(ProcessInfoEx* proc_array, int32_t* count, int32_t max_count);

// Create a new process
PROCMGR_API int procmgr_create_process(const char* exe_path, const char* args, 
                                        const char* working_dir, int32_t* pid);

// Terminate a process
PROCMGR_API int procmgr_terminate_process(int32_t pid, int32_t exit_code);

// Kill a process (force)
PROCMGR_API int procmgr_kill_process(int32_t pid);

// Suspend a process
PROCMGR_API int procmgr_suspend_process(int32_t pid);

// Resume a process
PROCMGR_API int procmgr_resume_process(int32_t pid);

// Set process priority
PROCMGR_API int procmgr_set_priority(int32_t pid, int32_t priority);

// Get process priority
PROCMGR_API int procmgr_get_priority(int32_t pid, int32_t* priority);

// Set process affinity
PROCMGR_API int procmgr_set_affinity(int32_t pid, uint64_t mask);

// Get process affinity
PROCMGR_API int procmgr_get_affinity(int32_t pid, uint64_t* mask);

// Wait for process to exit
PROCMGR_API int procmgr_wait_for_exit(int32_t pid, int32_t timeout_ms, int32_t* exit_code);

// Check if process is running
PROCMGR_API int procmgr_is_running(int32_t pid, int32_t* running);

// ============================================================================
// Thread Functions
// ============================================================================

// Get threads of a process
PROCMGR_API int procmgr_get_threads(int32_t pid, ThreadInfo* thread_array, 
                                     int32_t* count, int32_t max_count);

// Suspend a thread
PROCMGR_API int procmgr_suspend_thread(int32_t tid);

// Resume a thread
PROCMGR_API int procmgr_resume_thread(int32_t tid);

// Set thread priority
PROCMGR_API int procmgr_set_thread_priority(int32_t tid, int32_t priority);

// ============================================================================
// Module Functions
// ============================================================================

// Get modules of a process
PROCMGR_API int procmgr_get_modules(int32_t pid, ModuleInfo* module_array,
                                     int32_t* count, int32_t max_count);

// Get main module path
PROCMGR_API int procmgr_get_main_module(int32_t pid, char* path, int32_t path_size);

// ============================================================================
// Memory Functions
// ============================================================================

// Get memory regions of a process
PROCMGR_API int procmgr_get_memory_regions(int32_t pid, MemoryRegion* region_array,
                                            int32_t* count, int32_t max_count);

// Read process memory
PROCMGR_API int procmgr_read_memory(int32_t pid, uint64_t address, 
                                     void* buffer, size_t size, size_t* bytes_read);

// Get memory usage statistics
PROCMGR_API int procmgr_get_memory_stats(int32_t pid, uint64_t* working_set,
                                          uint64_t* private_bytes, uint64_t* virtual_bytes);

// ============================================================================
// Handle Functions (Windows only)
// ============================================================================

// Get handles of a process
PROCMGR_API int procmgr_get_handles(int32_t pid, HandleInfo* handle_array,
                                     int32_t* count, int32_t max_count);

// Close a handle in a process
PROCMGR_API int procmgr_close_handle(int32_t pid, uint32_t handle);

// ============================================================================
// Process Tree Functions
// ============================================================================

// Get child processes
PROCMGR_API int procmgr_get_children(int32_t pid, int32_t* children_array,
                                      int32_t* count, int32_t max_count);

// Get parent process
PROCMGR_API int procmgr_get_parent(int32_t pid, int32_t* parent_pid);

// Kill process tree
PROCMGR_API int procmgr_kill_tree(int32_t pid);

// ============================================================================
// Security Functions
// ============================================================================

// Check if process is elevated (running as admin)
PROCMGR_API int procmgr_is_elevated(int32_t pid, int32_t* elevated);

// Get process user
PROCMGR_API int procmgr_get_user(int32_t pid, char* user, int32_t user_size,
                                  char* domain, int32_t domain_size);

// Get process SID (Windows)
PROCMGR_API int procmgr_get_sid(int32_t pid, char* sid, int32_t sid_size);

// ============================================================================
// Job/Container Functions (Windows)
// ============================================================================

// Create job object
PROCMGR_API int procmgr_create_job(const char* name, void** job_handle);

// Add process to job
PROCMGR_API int procmgr_add_to_job(void* job_handle, int32_t pid);

// Set job limits
PROCMGR_API int procmgr_set_job_limits(void* job_handle, uint64_t memory_limit,
                                        double cpu_rate, int32_t process_limit);

// Terminate job
PROCMGR_API int procmgr_terminate_job(void* job_handle);

// Close job handle
PROCMGR_API int procmgr_close_job(void* job_handle);

// ============================================================================
// Utility Functions
// ============================================================================

// Get library version
PROCMGR_API const char* procmgr_get_version(void);

// Initialize the library
PROCMGR_API int procmgr_init(void);

// Cleanup the library
PROCMGR_API void procmgr_cleanup(void);

// Get last error message
PROCMGR_API const char* procmgr_get_error(void);

#ifdef __cplusplus
}
#endif
