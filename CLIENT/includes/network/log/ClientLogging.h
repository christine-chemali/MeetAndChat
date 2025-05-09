#ifndef CLIENTLOGGING_H
#define CLIENTLOGGING_H

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} LogLevel;

void init_client_logging(const char *db_conninfo);
void log_client_message(LogLevel level, const char *message);
void close_client_logging(void);

#endif
