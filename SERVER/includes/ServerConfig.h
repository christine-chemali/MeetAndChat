#ifndef SERVERCONFIG_H
#define SERVERCONFIG_H

#include <stdbool.h>

typedef struct {

    // Database
    char db_host[64];
    char db_port[8];
    char db_name[64];
    char db_user[64];
    char db_password[64];
    
    // Server
    char server_host[64];
    int server_port;
    int max_connections;
    
    // Security
    char pepper[33];
    int session_timeout;
    int max_login_attempts;
    
    // Maintenance
    int cleanup_interval;
    int log_retention_days;
    int message_retention_days;
} ServerConfig;

extern ServerConfig g_config;  
const char* get_pepper(void);  

bool load_server_config(const char *filename, ServerConfig *config);
char* get_db_connection_string(const ServerConfig *config);
void print_config(const ServerConfig *config);
bool validate_config(const ServerConfig *config);

#endif