#include "ServerConfig.h"
#include "serverlogging/ServerLogging.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LINE_LENGTH 256

//def global var
ServerConfig g_config; 
const char* get_pepper(void) {
    return g_config.pepper;
}

static char connection_string[512];

//load server config
bool load_server_config(const char *filename, ServerConfig *config) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        log_server_message(LOG_ERROR, "Failed to open config file");
        return false;
    }

    char line[MAX_LINE_LENGTH];
    char section[64] = "";

    while (fgets(line, sizeof(line), file)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') continue;

        // Check for section
        if (line[0] == '[' && line[strlen(line)-1] == ']') {
            strncpy(section, line + 1, strlen(line) - 2);
            section[strlen(line) - 2] = '\0';
            continue;
        }

        char key[64], value[256];
        if (sscanf(line, "%[^=]=%s", key, value) == 2) {
            if (strcmp(section, "database") == 0) {
                if (strcmp(key, "host") == 0) strncpy(config->db_host, value, sizeof(config->db_host)-1);
                else if (strcmp(key, "port") == 0) strncpy(config->db_port, value, sizeof(config->db_port)-1);
                else if (strcmp(key, "dbname") == 0) strncpy(config->db_name, value, sizeof(config->db_name)-1);
                else if (strcmp(key, "user") == 0) strncpy(config->db_user, value, sizeof(config->db_user)-1);
                else if (strcmp(key, "password") == 0) strncpy(config->db_password, value, sizeof(config->db_password)-1);
            }
            else if (strcmp(section, "server") == 0) {
                if (strcmp(key, "host") == 0) strncpy(config->server_host, value, sizeof(config->server_host)-1);
                else if (strcmp(key, "port") == 0) config->server_port = atoi(value);
                else if (strcmp(key, "max_connections") == 0) config->max_connections = atoi(value);
            }
            else if (strcmp(section, "security") == 0) {
                if (strcmp(key, "pepper") == 0) strncpy(config->pepper, value, sizeof(config->pepper)-1);
                else if (strcmp(key, "session_timeout") == 0) config->session_timeout = atoi(value);
                else if (strcmp(key, "max_login_attempts") == 0) config->max_login_attempts = atoi(value);
            }
            else if (strcmp(section, "maintenance") == 0) {
                if (strcmp(key, "cleanup_interval") == 0) config->cleanup_interval = atoi(value);
                else if (strcmp(key, "log_retention_days") == 0) config->log_retention_days = atoi(value);
                else if (strcmp(key, "message_retention_days") == 0) config->message_retention_days = atoi(value);
            }
        }
    }

    fclose(file);
    return validate_config(config);
}

char* get_db_connection_string(const ServerConfig *config) {
    snprintf(connection_string, sizeof(connection_string),
             "host=%s port=%s dbname=%s user=%s password=%s",
             config->db_host, config->db_port, config->db_name,
             config->db_user, config->db_password);
    return connection_string;
}

//Validate config
bool validate_config(const ServerConfig *config) {
    if (strlen(config->db_host) == 0 || 
        strlen(config->db_port) == 0 || 
        strlen(config->db_name) == 0 || 
        strlen(config->db_user) == 0 || 
        strlen(config->db_password) == 0 || 
        strlen(config->pepper) == 0) {
        log_server_message(LOG_ERROR, "Invalid configuration: Missing required fields");
        return false;
    }
    return true;
}

