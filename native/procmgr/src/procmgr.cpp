#include "procmgr.h"

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <windows.h>
    #include <psapi.h>
    #include <tlhelp32.h>
    #include <userenv.h>
    #include <sddl.h>
    #pragma comment(lib, "psapi.lib")
    #pragma comment(lib, "userenv.lib")
    #pragma comment(lib, "advapi32.lib")
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/stat.h>
    #include <sys/resource.h>
    #include <signal.h>
    #include <dirent.h>
    #include <pwd.h>
    #include <fstream>
    #include <sstream>
#endif

// Global state
static std::mutex g_mutex;
static std::string g_last_error;
static std::atomic<bool> g_initialized{false};
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
static std::string WideToUtf8(const wchar_t* wstr) {
    if (!wstr) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size, nullptr, nullptr);
    return result;
}

static ProcessState GetProcessState(HANDLE hProcess) {
    DWORD exitCode;
    if (GetExitCodeProcess(hProcess, &exitCode)) {
        if (exitCode == STILL_ACTIVE) {
            return PROC_STATE_RUNNING;
        }
        return PROC_STATE_ZOMBIE;
    }
    return PROC_STATE_UNKNOWN;
}
#endif

// ============================================================================
// Process Management Implementation
// ============================================================================

PROCMGR_API int procmgr_get_process_info_ex(int32_t pid, ProcessInfoEx* info) {
    if (!info) return PROCMGR_ERR_MEMORY;
    memset(info, 0, sizeof(ProcessInfoEx));
    info->pid = pid;

#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        set_error("Failed to open process");
        return PROCMGR_ERR_ACCESS;
    }

    info->state = GetProcessState(hProcess);

    // Get process name and path
    wchar_t exePath[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, exePath, &size)) {
        std::string path = WideToUtf8(exePath);
        safe_strcpy(info->exe_path, sizeof(info->exe_path), path.c_str());
        
        // Extract name from path
        size_t pos = path.rfind('\\');
        if (pos != std::string::npos) {
            safe_strcpy(info->name, sizeof(info->name), path.substr(pos + 1).c_str());
        } else {
            safe_strcpy(info->name, sizeof(info->name), path.c_str());
        }
    }

    // Get memory info
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        info->mem_rss = pmc.WorkingSetSize;
        info->mem_vms = pmc.PagefileUsage;
        info->mem_private = pmc.PrivateUsage;
    }

    // Get I/O counters
    IO_COUNTERS io;
    if (GetProcessIoCounters(hProcess, &io)) {
        info->read_bytes = io.ReadTransferCount;
        info->write_bytes = io.WriteTransferCount;
    }

    // Get times
    FILETIME create_time, exit_time, kernel_time, user_time;
    if (GetProcessTimes(hProcess, &create_time, &exit_time, &kernel_time, &user_time)) {
        ULARGE_INTEGER uli;
        uli.LowPart = create_time.dwLowDateTime;
        uli.HighPart = create_time.dwHighDateTime;
        info->create_time = (uli.QuadPart - 116444736000000000ULL) / 10000000ULL;
        
        uli.LowPart = kernel_time.dwLowDateTime;
        uli.HighPart = kernel_time.dwHighDateTime;
        info->kernel_time = uli.QuadPart / 10000; // Convert to ms
        
        uli.LowPart = user_time.dwLowDateTime;
        uli.HighPart = user_time.dwHighDateTime;
        info->user_time = uli.QuadPart / 10000;
    }

    // Check if elevated
    HANDLE hToken;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            info->is_elevated = elevation.TokenIsElevated ? 1 : 0;
        }
        CloseHandle(hToken);
    }

    // Check if 64-bit
    BOOL isWow64;
    if (IsWow64Process(hProcess, &isWow64)) {
        info->is_64bit = isWow64 ? 0 : 1; // If not WOW64, it's 64-bit on a 64-bit OS
    }

    // Get priority
    info->base_priority = GetPriorityClass(hProcess);

    CloseHandle(hProcess);

#else
    // Linux implementation
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    
    // Check if process exists
    struct stat st;
    if (stat(proc_path, &st) != 0) {
        set_error("Process not found");
        return PROCMGR_ERR_NOTFOUND;
    }

    // Read stat file
    char stat_path[80];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    std::ifstream stat_file(stat_path);
    if (stat_file.is_open()) {
        std::string line;
        std::getline(stat_file, line);
        
        // Parse name (in parentheses)
        size_t start = line.find('(');
        size_t end = line.rfind(')');
        if (start != std::string::npos && end != std::string::npos) {
            std::string name = line.substr(start + 1, end - start - 1);
            safe_strcpy(info->name, sizeof(info->name), name.c_str());
            
            // Parse rest
            std::string rest = line.substr(end + 2);
            char state;
            int ppid, pgrp, session, tty_nr, tpgid;
            unsigned int flags;
            unsigned long minflt, cminflt, majflt, cmajflt, utime, stime;
            long cutime, cstime, priority, nice, num_threads;
            
            sscanf(rest.c_str(), "%c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld",
                   &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags,
                   &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime,
                   &cutime, &cstime, &priority, &nice, &num_threads);
            
            info->ppid = ppid;
            info->session_id = session;
            info->priority = priority;
            info->num_threads = num_threads;
            info->user_time = utime * 10; // Convert to ms
            info->kernel_time = stime * 10;
            
            switch (state) {
                case 'R': info->state = PROC_STATE_RUNNING; break;
                case 'S': info->state = PROC_STATE_SLEEPING; break;
                case 'D': info->state = PROC_STATE_WAITING; break;
                case 'T': info->state = PROC_STATE_STOPPED; break;
                case 'Z': info->state = PROC_STATE_ZOMBIE; break;
                default: info->state = PROC_STATE_UNKNOWN;
            }
        }
    }

    // Read exe link
    char exe_path[512];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(exe_path, info->exe_path, sizeof(info->exe_path) - 1);
    if (len > 0) {
        info->exe_path[len] = '\0';
    }

    // Read memory from statm
    char statm_path[80];
    snprintf(statm_path, sizeof(statm_path), "/proc/%d/statm", pid);
    std::ifstream statm_file(statm_path);
    if (statm_file.is_open()) {
        uint64_t vms_pages, rss_pages;
        statm_file >> vms_pages >> rss_pages;
        long page_size = sysconf(_SC_PAGESIZE);
        info->mem_vms = vms_pages * page_size;
        info->mem_rss = rss_pages * page_size;
    }

    // Read I/O stats
    char io_path[80];
    snprintf(io_path, sizeof(io_path), "/proc/%d/io", pid);
    std::ifstream io_file(io_path);
    if (io_file.is_open()) {
        std::string line;
        while (std::getline(io_file, line)) {
            uint64_t value;
            if (sscanf(line.c_str(), "read_bytes: %lu", &value) == 1) {
                info->read_bytes = value;
            } else if (sscanf(line.c_str(), "write_bytes: %lu", &value) == 1) {
                info->write_bytes = value;
            }
        }
    }

    // Get user
    char status_path[80];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    std::ifstream status_file(status_path);
    if (status_file.is_open()) {
        std::string line;
        while (std::getline(status_file, line)) {
            unsigned int uid;
            if (sscanf(line.c_str(), "Uid: %u", &uid) == 1) {
                struct passwd* pw = getpwuid(uid);
                if (pw) {
                    safe_strcpy(info->user, sizeof(info->user), pw->pw_name);
                }
                break;
            }
        }
    }

    info->is_64bit = sizeof(void*) == 8 ? 1 : 0;
#endif

    return PROCMGR_OK;
}

PROCMGR_API int procmgr_get_process_list_ex(ProcessInfoEx* proc_array, int32_t* count, int32_t max_count) {
    if (!proc_array || !count || max_count <= 0) return PROCMGR_ERR_MEMORY;
    *count = 0;

#ifdef _WIN32
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        set_error("Failed to create process snapshot");
        return PROCMGR_ERR_ACCESS;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (*count >= max_count) break;
            
            ProcessInfoEx* proc = &proc_array[*count];
            memset(proc, 0, sizeof(ProcessInfoEx));
            
            proc->pid = pe32.th32ProcessID;
            proc->ppid = pe32.th32ParentProcessID;
            proc->num_threads = pe32.cntThreads;
            proc->base_priority = pe32.pcPriClassBase;
            
            std::string name = WideToUtf8(pe32.szExeFile);
            safe_strcpy(proc->name, sizeof(proc->name), name.c_str());
            
            // Get extended info
            procmgr_get_process_info_ex(proc->pid, proc);
            
            (*count)++;
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

#else
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        set_error("Failed to open /proc");
        return PROCMGR_ERR_ACCESS;
    }

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) && *count < max_count) {
        char* endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        ProcessInfoEx* proc = &proc_array[*count];
        if (procmgr_get_process_info_ex(pid, proc) == PROCMGR_OK) {
            (*count)++;
        }
    }

    closedir(proc_dir);
#endif

    return PROCMGR_OK;
}

PROCMGR_API int procmgr_create_process(const char* exe_path, const char* args,
                                        const char* working_dir, int32_t* pid) {
    if (!exe_path || !pid) return PROCMGR_ERR_INVALID;

#ifdef _WIN32
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    std::string cmdline = exe_path;
    if (args && args[0]) {
        cmdline += " ";
        cmdline += args;
    }

    if (!CreateProcessA(nullptr, const_cast<char*>(cmdline.c_str()),
                        nullptr, nullptr, FALSE, CREATE_NEW_PROCESS_GROUP,
                        nullptr, working_dir, &si, &pi)) {
        set_error("Failed to create process");
        return PROCMGR_ERR_UNKNOWN;
    }

    *pid = pi.dwProcessId;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

#else
    pid_t child = fork();
    if (child == -1) {
        set_error("Fork failed");
        return PROCMGR_ERR_UNKNOWN;
    }

    if (child == 0) {
        // Child process
        if (working_dir) {
            chdir(working_dir);
        }

        std::string fullcmd = exe_path;
        if (args && args[0]) {
            fullcmd += " ";
            fullcmd += args;
        }

        execl("/bin/sh", "sh", "-c", fullcmd.c_str(), nullptr);
        _exit(127);
    }

    *pid = child;
#endif

    return PROCMGR_OK;
}

PROCMGR_API int procmgr_terminate_process(int32_t pid, int32_t exit_code) {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        set_error("Failed to open process");
        return PROCMGR_ERR_ACCESS;
    }

    BOOL result = TerminateProcess(hProcess, exit_code);
    CloseHandle(hProcess);

    if (!result) {
        set_error("Failed to terminate process");
        return PROCMGR_ERR_UNKNOWN;
    }
#else
    if (kill(pid, SIGTERM) != 0) {
        set_error("Failed to send SIGTERM");
        return PROCMGR_ERR_ACCESS;
    }
#endif

    return PROCMGR_OK;
}

PROCMGR_API int procmgr_kill_process(int32_t pid) {
#ifdef _WIN32
    return procmgr_terminate_process(pid, 1);
#else
    if (kill(pid, SIGKILL) != 0) {
        set_error("Failed to send SIGKILL");
        return PROCMGR_ERR_ACCESS;
    }
    return PROCMGR_OK;
#endif
}

PROCMGR_API int procmgr_suspend_process(int32_t pid) {
#ifdef _WIN32
    // Windows doesn't have a direct suspend, need to suspend all threads
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return PROCMGR_ERR_ACCESS;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == (DWORD)pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
#else
    if (kill(pid, SIGSTOP) != 0) {
        set_error("Failed to send SIGSTOP");
        return PROCMGR_ERR_ACCESS;
    }
#endif

    return PROCMGR_OK;
}

PROCMGR_API int procmgr_resume_process(int32_t pid) {
#ifdef _WIN32
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return PROCMGR_ERR_ACCESS;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == (DWORD)pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
#else
    if (kill(pid, SIGCONT) != 0) {
        set_error("Failed to send SIGCONT");
        return PROCMGR_ERR_ACCESS;
    }
#endif

    return PROCMGR_OK;
}

PROCMGR_API int procmgr_set_priority(int32_t pid, int32_t priority) {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return PROCMGR_ERR_ACCESS;
    }

    DWORD winPriority;
    switch (priority) {
        case PROC_PRIORITY_IDLE: winPriority = IDLE_PRIORITY_CLASS; break;
        case PROC_PRIORITY_BELOW_NORMAL: winPriority = BELOW_NORMAL_PRIORITY_CLASS; break;
        case PROC_PRIORITY_NORMAL: winPriority = NORMAL_PRIORITY_CLASS; break;
        case PROC_PRIORITY_ABOVE_NORMAL: winPriority = ABOVE_NORMAL_PRIORITY_CLASS; break;
        case PROC_PRIORITY_HIGH: winPriority = HIGH_PRIORITY_CLASS; break;
        case PROC_PRIORITY_REALTIME: winPriority = REALTIME_PRIORITY_CLASS; break;
        default: winPriority = NORMAL_PRIORITY_CLASS;
    }

    BOOL result = SetPriorityClass(hProcess, winPriority);
    CloseHandle(hProcess);

    if (!result) {
        return PROCMGR_ERR_UNKNOWN;
    }
#else
    // Map priority to nice value (-20 to 19)
    int nice_val = 0;
    switch (priority) {
        case PROC_PRIORITY_IDLE: nice_val = 19; break;
        case PROC_PRIORITY_BELOW_NORMAL: nice_val = 10; break;
        case PROC_PRIORITY_NORMAL: nice_val = 0; break;
        case PROC_PRIORITY_ABOVE_NORMAL: nice_val = -5; break;
        case PROC_PRIORITY_HIGH: nice_val = -10; break;
        case PROC_PRIORITY_REALTIME: nice_val = -20; break;
    }

    if (setpriority(PRIO_PROCESS, pid, nice_val) != 0) {
        set_error("Failed to set priority");
        return PROCMGR_ERR_ACCESS;
    }
#endif

    return PROCMGR_OK;
}

PROCMGR_API int procmgr_is_running(int32_t pid, int32_t* running) {
    if (!running) return PROCMGR_ERR_MEMORY;

#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        *running = 0;
        return PROCMGR_OK;
    }

    DWORD exitCode;
    if (GetExitCodeProcess(hProcess, &exitCode)) {
        *running = (exitCode == STILL_ACTIVE) ? 1 : 0;
    } else {
        *running = 0;
    }

    CloseHandle(hProcess);
#else
    *running = (kill(pid, 0) == 0) ? 1 : 0;
#endif

    return PROCMGR_OK;
}

PROCMGR_API int procmgr_wait_for_exit(int32_t pid, int32_t timeout_ms, int32_t* exit_code) {
    if (!exit_code) return PROCMGR_ERR_MEMORY;

#ifdef _WIN32
    HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return PROCMGR_ERR_ACCESS;
    }

    DWORD waitResult = WaitForSingleObject(hProcess, timeout_ms > 0 ? timeout_ms : INFINITE);
    if (waitResult == WAIT_TIMEOUT) {
        CloseHandle(hProcess);
        return PROCMGR_ERR_TIMEOUT;
    }

    DWORD ec;
    GetExitCodeProcess(hProcess, &ec);
    *exit_code = static_cast<int32_t>(ec);

    CloseHandle(hProcess);
#else
    int status;
    pid_t result;
    
    if (timeout_ms > 0) {
        // Polling with timeout
        auto start = std::chrono::steady_clock::now();
        while (true) {
            result = waitpid(pid, &status, WNOHANG);
            if (result > 0) break;
            if (result == -1) return PROCMGR_ERR_UNKNOWN;
            
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
            if (elapsed > timeout_ms) {
                return PROCMGR_ERR_TIMEOUT;
            }
            usleep(10000); // 10ms
        }
    } else {
        result = waitpid(pid, &status, 0);
        if (result == -1) return PROCMGR_ERR_UNKNOWN;
    }

    if (WIFEXITED(status)) {
        *exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        *exit_code = -WTERMSIG(status);
    }
#endif

    return PROCMGR_OK;
}

PROCMGR_API int procmgr_get_children(int32_t pid, int32_t* children_array,
                                      int32_t* count, int32_t max_count) {
    if (!children_array || !count || max_count <= 0) return PROCMGR_ERR_MEMORY;
    *count = 0;

#ifdef _WIN32
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return PROCMGR_ERR_ACCESS;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ParentProcessID == (DWORD)pid && *count < max_count) {
                children_array[(*count)++] = pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
#else
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return PROCMGR_ERR_ACCESS;

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) && *count < max_count) {
        char* endptr;
        long child_pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || child_pid <= 0) continue;

        char stat_path[64];
        snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", child_pid);
        
        std::ifstream stat_file(stat_path);
        if (stat_file.is_open()) {
            std::string line;
            std::getline(stat_file, line);
            
            size_t end = line.rfind(')');
            if (end != std::string::npos) {
                int ppid;
                if (sscanf(line.substr(end + 2).c_str(), "%*c %d", &ppid) == 1) {
                    if (ppid == pid) {
                        children_array[(*count)++] = child_pid;
                    }
                }
            }
        }
    }

    closedir(proc_dir);
#endif

    return PROCMGR_OK;
}

PROCMGR_API int procmgr_kill_tree(int32_t pid) {
    // Get children first
    int32_t children[1024];
    int32_t count;
    
    if (procmgr_get_children(pid, children, &count, 1024) == PROCMGR_OK) {
        // Kill children recursively
        for (int32_t i = 0; i < count; i++) {
            procmgr_kill_tree(children[i]);
        }
    }
    
    // Kill the process itself
    return procmgr_kill_process(pid);
}

// ============================================================================
// Utility Functions
// ============================================================================

PROCMGR_API const char* procmgr_get_version(void) {
    return VERSION;
}

PROCMGR_API int procmgr_init(void) {
    if (g_initialized.exchange(true)) {
        return PROCMGR_OK;
    }
    return PROCMGR_OK;
}

PROCMGR_API void procmgr_cleanup(void) {
    g_initialized = false;
}

PROCMGR_API const char* procmgr_get_error(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_last_error.c_str();
}
