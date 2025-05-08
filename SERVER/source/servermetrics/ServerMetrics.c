#include "servermetrics/ServerMetrics.h"
#include "serverlogging/ServerLogging.h"
#include <windows.h>
#include <psapi.h>

static volatile int g_active_connections = 0;
static volatile int g_queries_count = 0;
static ULONGLONG g_last_query_time = 0;

//Cpu usage
double get_cpu_usage(void) {
    FILETIME idleTime, kernelTime, userTime;
    static ULARGE_INTEGER lastIdleTime = {0};
    static ULARGE_INTEGER lastKernelTime = {0};
    static ULARGE_INTEGER lastUserTime = {0};

    GetSystemTimes((LPFILETIME)&idleTime, (LPFILETIME)&kernelTime, (LPFILETIME)&userTime);

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
    if(totalTime == 0) return 0.0;

    return (double)(totalTime - idleDiff.QuadPart) * 100.0 / totalTime;
}

//memory usage
double get_memory_usage(void) {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    return (double)memInfo.dwMemoryLoad;
}

//inactive connections
int get_active_connections(void) {
    return g_active_connections;
}

//Queries per sec
int get_queries_per_second(void) {
    ULONGLONG currentTime = GetTickCount64();
    ULONGLONG timeDiff = currentTime - g_last_query_time;
    
    if(timeDiff == 0) return 0;
    
    int qps = (int)(g_queries_count * 1000.0 / timeDiff);
    g_queries_count = 0;
    g_last_query_time = currentTime;
    
    return qps;
}

//Performance Monitor thread
DWORD WINAPI performanceMonitorThread(LPVOID lpParam) {
    while(1) {
        ServerMetrics metrics = {
            .cpu_usage = get_cpu_usage(),
            .memory_usage = get_memory_usage(),
            .active_connections = get_active_connections(),
            .queries_per_second = get_queries_per_second()
        };

        log_performance_metrics(&metrics);
        Sleep(60000); // Wait 1 minute before next check
    }
    return 0;
}