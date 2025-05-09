#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "logic/login/ValidationProcess.h"

// Validate email process
bool validate_email(const char *email) {
    return strstr(email, "@") != NULL && strstr(email, ".") != NULL;
}

// Validate password process
bool validate_password(const char *password) {
    if (strlen(password) < 10) return false;
    bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
    for (int i = 0; i < strlen(password); i++) {
        if (isupper(password[i])) has_upper = true;
        if (islower(password[i])) has_lower = true;
        if (isdigit(password[i])) has_digit = true;
        if (strchr("?,.;/:§!%&*()-+|@", password[i])) has_special = true;
    }
    return has_upper && has_lower && has_digit && has_special;
}
