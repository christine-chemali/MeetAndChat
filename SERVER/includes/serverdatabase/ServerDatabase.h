#ifndef SERVERDATABASE_H
#define SERVERDATABASE_H

#include <stdbool.h>
#include <libpq-fe.h>

typedef struct {
    PGconn *conn;
} DatabaseConnection;

bool init_server_database(const char *connection_info);
void close_server_database(void);
PGconn *get_database_connection(void);

#endif


