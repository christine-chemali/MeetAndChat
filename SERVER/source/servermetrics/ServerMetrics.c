#include "servermetrics/ServerMetrics.h"
#include "serverlogging/ServerLogging.h"
#include <windows.h>
#include <psapi.h>

static volatile int g_active_connections = 0;
static volatile int g_queries_count = 0;
static ULONGLONG g_last_query_time = 0;
static PROCESS_MEMORY_COUNTERS pmc;

// CPU usage
double get_cpu_usage(void) {
    char log_buffer[256];
    FILETIME idleTime, kernelTime, userTime;
    static ULARGE_INTEGER lastIdleTime = {0};
    static ULARGE_INTEGER lastKernelTime = {0};
    static ULARGE_INTEGER lastUserTime = {0};

    if (!GetSystemTimes((LPFILETIME)&idleTime, (LPFILETIME)&kernelTime, (LPFILETIME)&userTime)) {
        snprintf(log_buffer, sizeof(log_buffer),
            "METRICS: Failed to get CPU times");
        log_server_message(LOG_ERROR, log_buffer);
        return 0.0;
    }

    ULARGE_INTEGER idle, kernel, user;
    idle.LowPart = idleTime.dwLowDateTime;
    idle.HighPart = idleTime.dwHighDateTime;
    kernel.LowPart = kernelTime.dwLowDateTime;
    kernel.HighPart = kernelTime.dwHighDateTime;
    user.LowPart = userTime.dwLowDateTime;
    user.HighPart = userTime.dwHighDateTime;

    ULARGE_INTEGER idleDiff, kernelDiff, userDiff;
    idleDiff.QuadPart = idle.QuadPart - lastIdleTime.QuadPart;
    kernelDiff.QuadPart = kernel.QuadPart - lastKernelTime.QuadPart;
    userDiff.QuadPart = user.QuadPart - lastUserTime.QuadPart;

    lastIdleTime = idle;
    lastKernelTime = kernel;
    lastUserTime = user;

    ULONGLONG totalTime = kernelDiff.QuadPart + userDiff.QuadPart;
    if(totalTime == 0) {
        snprintf(log_buffer, sizeof(log_buffer),
            "METRICS: Zero total CPU time detected");
        log_server_message(LOG_WARNING, log_buffer);
        return 0.0;
    }

    return (double)(totalTime - idleDiff.QuadPart) * 100.0 / totalTime;
}

// Memory usage 
double get_memory_usage(void) {
    char log_buffer[256];
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    
    if (!GlobalMemoryStatusEx(&memInfo)) {
        snprintf(log_buffer, sizeof(log_buffer),
            "METRICS: Failed to get memory status");
        log_server_message(LOG_ERROR, log_buffer);
        return 0.0;
    }

    // info about process memory
    HANDLE process = GetCurrentProcess();
    if (GetProcessMemoryInfo(process, &pmc, sizeof(pmc))) {
        snprintf(log_buffer, sizeof(log_buffer),
            "METRICS_DETAIL: Process Memory - Working Set: %llu KB, Peak Working Set: %llu KB, Page File: %llu KB",
            pmc.WorkingSetSize / 1024,
            pmc.PeakWorkingSetSize / 1024,
            pmc.PagefileUsage / 1024);
        log_server_message(LOG_DEBUG, log_buffer);
    }

    // Info about system memory 
    snprintf(log_buffer, sizeof(log_buffer),
        "METRICS_DETAIL: System Memory - Total: %llu MB, Available: %llu MB, Used: %llu MB",
        memInfo.ullTotalPhys / (1024 * 1024),
        memInfo.ullAvailPhys / (1024 * 1024),
        (memInfo.ullTotalPhys - memInfo.ullAvailPhys) / (1024 * 1024));
    log_server_message(LOG_DEBUG, log_buffer);
    
    return (double)memInfo.dwMemoryLoad;
}

// Active connections
int get_active_connections(void) {
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer),
        "METRICS: Active connections count: %d",
        g_active_connections);
    log_server_message(LOG_DEBUG, log_buffer);
    return g_active_connections;
}

// Queries per second
int get_queries_per_second(void) {
    char log_buffer[256];
    ULONGLONG currentTime = GetTickCount64();
    ULONGLONG timeDiff = currentTime - g_last_query_time;
    
    if(timeDiff == 0) {
        snprintf(log_buffer, sizeof(log_buffer),
            "METRICS: Zero time difference for QPS calculation");
        log_server_message(LOG_WARNING, log_buffer);
        return 0;
    }
    
    int qps = (int)(g_queries_count * 1000.0 / timeDiff);
    g_queries_count = 0;
    g_last_query_time = currentTime;
    
    snprintf(log_buffer, sizeof(log_buffer),
        "METRICS: Current QPS: %d", qps);
    log_server_message(LOG_DEBUG, log_buffer);
    
    return qps;
}

// Performance Monitor thread - modifié avec intervalle plus court
DWORD WINAPI performanceMonitorThread(LPVOID lpParam) {
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer),
        "METRICS: Starting performance monitoring");
    log_server_message(LOG_INFO, log_buffer);

    while(1) {
        ServerMetrics metrics = {
            .cpu_usage = get_cpu_usage(),
            .memory_usage = get_memory_usage(),
            .active_connections = get_active_connections(),
            .queries_per_second = get_queries_per_second()
        };

        snprintf(log_buffer, sizeof(log_buffer),
            "METRICS: CPU: %.2f%%, MEM: %.2f%%, CONN: %d, QPS: %d",
            metrics.cpu_usage, metrics.memory_usage,
            metrics.active_connections, metrics.queries_per_second);
        log_server_message(LOG_PERFORMANCE, log_buffer);

        log_performance_metrics(&metrics);
        Sleep(30000); 
    }
    return 0;
}