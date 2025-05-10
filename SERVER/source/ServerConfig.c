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
    char log_buffer[256];
    
    FILE *file = fopen(filename, "r");
    if (!file) {
        snprintf(log_buffer, sizeof(log_buffer),
            "CFG: Cannot access configuration file");
        log_server_message(LOG_ERROR, log_buffer);
        return false;
    }

    char line[MAX_LINE_LENGTH];
    char section[64] = "";

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;
        if (line[0] == '\0' || line[0] == '#') continue;

        if (line[0] == '[' && line[strlen(line)-1] == ']') {
            strncpy(section, line + 1, strlen(line) - 2);
            section[strlen(line) - 2] = '\0';
            
            snprintf(log_buffer, sizeof(log_buffer),
                "CFG: Processing section [%s]", section);
            log_server_message(LOG_DEBUG, log_buffer);
            continue;
        }

        char key[64], value[256];
        if (sscanf(line, "%[^=]=%s", key, value) == 2) {
            // Ne pas logger les valeurs sensibles
            if (strcmp(key, "password") != 0 && 
                strcmp(key, "pepper") != 0 &&
                strcmp(key, "user") != 0) {
                snprintf(log_buffer, sizeof(log_buffer),
                    "CFG: Loaded %s.%s", section, key);
                log_server_message(LOG_DEBUG, log_buffer);
            }

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
    
    snprintf(log_buffer, sizeof(log_buffer),
        "CFG: Configuration file processed");
    log_server_message(LOG_INFO, log_buffer);
    
    return validate_config(config);
}

//Return connection string
char* get_db_connection_string(const ServerConfig *config) {
    if (!config) {
        log_server_message(LOG_ERROR, "CFG: Null config in connection string generation");
        return NULL;
    }

    snprintf(connection_string, sizeof(connection_string),
             "host=%s port=%s dbname=%s user=%s password=%s",
             config->db_host, config->db_port, config->db_name,
             config->db_user, config->db_password);
             
    log_server_message(LOG_DEBUG, "CFG: Database connection string generated");
    return connection_string;
}

//Validate config
bool validate_config(const ServerConfig *config) {
    char log_buffer[256];
    
    if (!config) {
        log_server_message(LOG_ERROR, "CFG: Null configuration");
        return false;
    }

    // Liste des champs manquants sans exposer les valeurs
    int missing = 0;
    if (strlen(config->db_host) == 0) missing++;
    if (strlen(config->db_port) == 0) missing++;
    if (strlen(config->db_name) == 0) missing++;
    if (strlen(config->db_user) == 0) missing++;
    if (strlen(config->db_password) == 0) missing++;
    if (strlen(config->pepper) == 0) missing++;

    if (missing > 0) {
        snprintf(log_buffer, sizeof(log_buffer),
            "CFG: Configuration validation failed - %d required field(s) missing",
            missing);
        log_server_message(LOG_ERROR, log_buffer);
        return false;
    }

    log_server_message(LOG_INFO, "CFG: Configuration validated successfully");
    return true;
}