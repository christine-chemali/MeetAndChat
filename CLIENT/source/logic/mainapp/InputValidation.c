#include <string.h>
#include <ctype.h>
#include "logic/mainapp/InputValidation.h"

bool validate_channel_name(const char *channel_name) {
    if (channel_name == NULL || strlen(channel_name) == 0) {
        return false;
    }

    size_t len = strlen(channel_name);
    if (len > 50) {
        return false;
    }

    bool has_non_space = false;
    for (size_t i = 0; i < len; i++) {
        if (!isspace((unsigned char)channel_name[i])) {
            has_non_space = true;
            break;
        }
    }

    return has_non_space;
}


// Rules to validate the category name
bool validate_category_name(const char *category_name) {
    if (category_name == NULL || strlen(category_name) == 0) {
        return false;
    }

    size_t len = strlen(category_name);
    if (len > 50) {
        return false;
    }

    bool has_non_space = false;
    for (size_t i = 0; i < len; i++) {
        if (!isspace((unsigned char)category_name[i])) {
            has_non_space = true;
            break;
        }
    }

    return has_non_space;
}

// Rules to validate the server name
bool validate_server_name(const char *server_name) {
    if (server_name == NULL || strlen(server_name) == 0) {
        return false;
    }

    size_t len = strlen(server_name);
    if (len > 50) {
        return false;
    }

    bool has_non_space = false;
    for (size_t i = 0; i < len; i++) {
        if (!isspace((unsigned char)server_name[i])) {
            has_non_space = true;
            break;
        }
    }

    return has_non_space;
}