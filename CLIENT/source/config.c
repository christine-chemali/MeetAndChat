#include "config.h"
#include <stdio.h>
#include <string.h>

int read_config_file(const char *filename, char *connection_info) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        return 1;
    }

    char host[64] = "";
    char port[8] = "";
    char dbname[64] = "";
    char user[64] = "";
    char password[64] = "";

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "host=")) sscanf(line, "host=%63s", host);
        if (strstr(line, "port=")) sscanf(line, "port=%7s", port);
        if (strstr(line, "dbname=")) sscanf(line, "dbname=%63s", dbname);
        if (strstr(line, "user=")) sscanf(line, "user=%63s", user);
        if (strstr(line, "password=")) sscanf(line, "password=%63s", password);
    }

    snprintf(connection_info, 256, "host=%s port=%s dbname=%s user=%s password=%s",
             host, port, dbname, user, password);

    fclose(file);
    return 0;
}
