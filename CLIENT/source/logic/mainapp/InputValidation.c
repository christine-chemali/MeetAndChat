#include <string.h>
#include <ctype.h>
#include "logic/mainapp/InputValidation.h"

// Rules to validate the channel name
bool validate_channel_name(const char *channel_name) {
    if (channel_name == NULL || strlen(channel_name) == 0) {
        return false; 
    }
    for (size_t i = 0; i < strlen(channel_name); i++) {
        if (!isalnum(channel_name[i]) && channel_name[i] != '_' && channel_name[i] != '-') {
            return false; 
        }
    }
    return true; 
}

// Rules to validate the category name
bool validate_category_name(const char *category_name) {
    if (category_name == NULL || strlen(category_name) == 0) {
        return false; 
    }

    return true; 
}