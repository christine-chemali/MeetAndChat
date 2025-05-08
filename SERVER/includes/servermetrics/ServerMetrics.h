#ifndef SERVER_METRICS_H
#define SERVER_METRICS_H

#include <windows.h>
#include <stdbool.h>
#include "serverlogging/ServerLogging.h" 

DWORD WINAPI performanceMonitorThread(LPVOID lpParam);
double get_cpu_usage(void);
double get_memory_usage(void);
int get_active_connections(void);
int get_queries_per_second(void);

#endif