#include "serverlogging/ServerLogging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

static PGconn *server_db_conn = NULL;

//Init server logging
bool init_server_logging(const char *db_conninfo) {
    if (!db_conninfo) {
        fprintf(stderr, "Invalid database connection info\n");
        return false;
    }

    server_db_conn = PQconnectdb(db_conninfo);
    if (PQstatus(server_db_conn) != CONNECTION_OK) {
        fprintf(stderr, "Database connection failed: %s\n", 
                PQerrorMessage(server_db_conn));
        return false;
    }

    //Server Log
    const char *create_tables = 
        "CREATE TABLE IF NOT EXISTS server_logs ("
        "    id SERIAL PRIMARY KEY,"
        "    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    level VARCHAR(50) NOT NULL,"
        "    message TEXT NOT NULL"
        ");"
        
        //Security Log table
        "CREATE TABLE IF NOT EXISTS security_logs ("
        "    id SERIAL PRIMARY KEY,"
        "    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    username VARCHAR(255),"
        "    event_type VARCHAR(100) NOT NULL,"
        "    details TEXT"
        ");"
        
        //Performance log table
        "CREATE TABLE IF NOT EXISTS performance_logs ("
        "    id SERIAL PRIMARY KEY,"
        "    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    cpu_usage FLOAT,"
        "    memory_usage FLOAT,"
        "    active_connections INTEGER,"
        "    queries_per_second INTEGER"
        ");"

        //index
        "CREATE INDEX IF NOT EXISTS idx_server_logs_timestamp "
        "    ON server_logs(timestamp);"
        "CREATE INDEX IF NOT EXISTS idx_server_logs_level "
        "    ON server_logs(level);"
        "CREATE INDEX IF NOT EXISTS idx_security_logs_timestamp "
        "    ON security_logs(timestamp);"
        "CREATE INDEX IF NOT EXISTS idx_security_logs_username "
        "    ON security_logs(username);"
        "CREATE INDEX IF NOT EXISTS idx_performance_logs_timestamp "
        "    ON performance_logs(timestamp);";

    PGresult *res = PQexec(server_db_conn, create_tables);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Failed to create tables: %s\n", 
                PQerrorMessage(server_db_conn));
        PQclear(res);
        return false;
    }
    PQclear(res);
    return true;
}

//log server message
void log_server_message(LogLevel level, const char *message) {
    if (!message || !server_db_conn) return;

    const char *level_str;
    const char *color;

    switch (level) {
        case LOG_DEBUG:
            level_str = "DEBUG";
            color = ANSI_COLOR_BLUE;
            break;
        case LOG_INFO:
            level_str = "INFO";
            color = ANSI_COLOR_GREEN;
            break;
        case LOG_WARNING:
            level_str = "WARNING";
            color = ANSI_COLOR_YELLOW;
            break;
        case LOG_ERROR:
            level_str = "ERROR";
            color = ANSI_COLOR_RED;
            break;
        case LOG_SECURITY:
            level_str = "SECURITY";
            color = ANSI_COLOR_MAGENTA;
            break;
        case LOG_PERFORMANCE:
            level_str = "PERFORMANCE";
            color = ANSI_COLOR_CYAN;
            break;
        default:
            level_str = "UNKNOWN";
            color = ANSI_COLOR_RESET;
    }

    // Console output
    time_t now;
    time(&now);
    char *date = ctime(&now);
    date[strlen(date) - 1] = '\0';
    printf("%s[%s][%s] %s%s\n", color, date, level_str, message, ANSI_COLOR_RESET);

    // Database logging
    const char *query = 
        "INSERT INTO server_logs (level, message) VALUES ($1, $2)";
    const char *params[2] = {level_str, message};
    
    PGresult *res = PQexecParams(server_db_conn, query, 2, 
                                NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Failed to log message: %s\n", 
                PQerrorMessage(server_db_conn));
    }
    PQclear(res);
}


//log security event
void log_security_event(const char *username, const char *event_type, 
                       const char *details) {
    if (!server_db_conn) return;

    const char *query = 
        "INSERT INTO security_logs (username, event_type, details) "
        "VALUES ($1, $2, $3)";
    const char *params[3] = {username, event_type, details};

    PGresult *res = PQexecParams(server_db_conn, query, 3, 
                                NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Failed to log security event: %s\n", 
                PQerrorMessage(server_db_conn));
    }
    PQclear(res);

    // Also log to server_logs for general tracking
    char combined_message[1024];
    snprintf(combined_message, sizeof(combined_message), 
             "Security Event - User: %s, Type: %s, Details: %s",
             username, event_type, details);
    log_server_message(LOG_SECURITY, combined_message);
}

//log performance metrics
void log_performance_metrics(const ServerMetrics *metrics) {
    if (!server_db_conn || !metrics) return;

    const char *query = 
        "INSERT INTO performance_logs "
        "(cpu_usage, memory_usage, active_connections, queries_per_second) "
        "VALUES ($1, $2, $3, $4)";

    char cpu_str[32], mem_str[32], conn_str[32], qps_str[32];
    snprintf(cpu_str, sizeof(cpu_str), "%.2f", metrics->cpu_usage);
    snprintf(mem_str, sizeof(mem_str), "%.2f", metrics->memory_usage);
    snprintf(conn_str, sizeof(conn_str), "%d", metrics->active_connections);
    snprintf(qps_str, sizeof(qps_str), "%d", metrics->queries_per_second);

    const char *params[4] = {cpu_str, mem_str, conn_str, qps_str};

    PGresult *res = PQexecParams(server_db_conn, query, 4, 
                                NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Failed to log performance metrics: %s\n", 
                PQerrorMessage(server_db_conn));
    }
    PQclear(res);
}

//Clean old logs
bool cleanup_old_logs(int days_to_retain) {
    if (!server_db_conn) return false;

    const char *queries[] = {
        "DELETE FROM server_logs WHERE timestamp < NOW() - INTERVAL '%d days'",
        "DELETE FROM security_logs WHERE timestamp < NOW() - INTERVAL '%d days'",
        "DELETE FROM performance_logs WHERE timestamp < NOW() - INTERVAL '%d days'"
    };

    char query[256];
    bool success = true;

    for (int i = 0; i < 3; i++) {
        snprintf(query, sizeof(query), queries[i], days_to_retain);
        PGresult *res = PQexec(server_db_conn, query);
        
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Failed to cleanup logs: %s\n", 
                    PQerrorMessage(server_db_conn));
            success = false;
        }
        PQclear(res);
    }

    return success;
}

//analyse log
bool analyze_logs(const char *start_date, const char *end_date, 
                 LogAnalytics *analytics) {
    if (!server_db_conn || !analytics) return false;

    const char *query = 
        "SELECT "
        "    COUNT(*) as total,"
        "    SUM(CASE WHEN level = 'ERROR' THEN 1 ELSE 0 END) as errors,"
        "    SUM(CASE WHEN level = 'WARNING' THEN 1 ELSE 0 END) as warnings,"
        "    SUM(CASE WHEN level = 'SECURITY' THEN 1 ELSE 0 END) as security "
        "FROM server_logs "
        "WHERE timestamp BETWEEN $1::timestamp AND $2::timestamp";

    const char *params[2] = {start_date, end_date};
    
    PGresult *res = PQexecParams(server_db_conn, query, 2, 
                                NULL, params, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Failed to analyze logs: %s\n", 
                PQerrorMessage(server_db_conn));
        PQclear(res);
        return false;
    }

    analytics->total_logs = atoi(PQgetvalue(res, 0, 0));
    analytics->error_count = atoi(PQgetvalue(res, 0, 1));
    analytics->warning_count = atoi(PQgetvalue(res, 0, 2));
    analytics->security_events = atoi(PQgetvalue(res, 0, 3));

    PQclear(res);
    return true;
}

//close server logging
void close_server_logging(void) {
    if (server_db_conn) {
        PQfinish(server_db_conn);
        server_db_conn = NULL;
    }
}