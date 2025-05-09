#include <stdio.h>
#include <stdlib.h>
#include <libpq-fe.h>
#include <string.h>
#include <time.h>
#include "network/log/ClientLogging.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

static PGconn *client_db_conn = NULL;

// Init database connection
void init_client_logging(const char *db_conninfo) {
    if (db_conninfo == NULL || strlen(db_conninfo) == 0) {
        fprintf(stderr, "Database connection info is invalid.\n");
        exit(EXIT_FAILURE);
    }

    client_db_conn = PQconnectdb(db_conninfo);
    if (PQstatus(client_db_conn) != CONNECTION_OK) {
        fprintf(stderr, "Failed to connect to database: %s\n", PQerrorMessage(client_db_conn));
        exit(EXIT_FAILURE);
    }

    const char *create_table_query = 
        "CREATE TABLE IF NOT EXISTS logs ("
        "id SERIAL PRIMARY KEY, "
        "level TEXT NOT NULL, "
        "message TEXT NOT NULL, "
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);";

    PGresult *res = PQexec(client_db_conn, create_table_query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Failed to create logs table: %s\n", PQerrorMessage(client_db_conn));
    }
    PQclear(res);
}

// Log message to the database
void log_client_message(LogLevel level, const char *message) {
    if (!message) return;

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
        default:
            level_str = "UNKNOWN";
            color = ANSI_COLOR_RESET;
    }

    // Console output with colors SO COOL!!!
    time_t now;
    time(&now);
    char *date = ctime(&now);
    date[strlen(date) - 1] = '\0'; 
    printf("%s[%s][%s] %s%s\n", color, date, level_str, message, ANSI_COLOR_RESET);

    // Database logging
    if (client_db_conn) {
        char formatted_message[1024];
        snprintf(formatted_message, sizeof(formatted_message), "%s", message);

        const char *query = "INSERT INTO logs (level, message) VALUES ($1, $2)";
        const char *params[2] = {level_str, formatted_message};

        PGresult *res = PQexecParams(client_db_conn, query, 2, NULL, params, NULL, NULL, 0);
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Failed to log message: %s\n", PQerrorMessage(client_db_conn));
        }
        PQclear(res);
    }
}

// Close the database connection
void close_client_logging() {
    if (client_db_conn) {
        PQfinish(client_db_conn);
        client_db_conn = NULL;
    }
}
