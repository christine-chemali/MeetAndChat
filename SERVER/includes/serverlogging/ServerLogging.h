#ifndef SERVERLOGGING_H
#define SERVERLOGGING_H

#include <libpq-fe.h>
#include <stdbool.h>

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_SECURITY,    
    LOG_PERFORMANCE  
} LogLevel;

typedef struct {
    double cpu_usage;
    double memory_usage;
    int active_connections;
    int queries_per_second;
} ServerMetrics;

typedef struct {
    int total_logs;
    int error_count;
    int warning_count;
    int security_events;
} LogAnalytics;

// init func and clean
bool init_server_logging(const char *db_conninfo);
void close_server_logging(void);

// logging funcs
void log_server_message(LogLevel level, const char *message);
void log_security_event(const char *username, const char *event_type, const char *details);
void log_performance_metrics(const ServerMetrics *metrics);

// maintenance 
bool cleanup_old_logs(int days_to_retain);
bool analyze_logs(const char *start_date, const char *end_date, LogAnalytics *analytics);

#endif