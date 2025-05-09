#include "network/core/MessageSender.h"
#include "network/core/SessionManager.h"
#include "network/core/NetworkCore.h"
#include "network/log/ClientLogging.h"
#include "network/session/ClientSession.h"
#include "security/NetworkSecurity.h"
#include <string.h>
#include <stdio.h>

//global var
char current_user[256] = {0};

// Get the current user
const char* get_current_user(void) {
    return current_user;
}

// Set the current user
void set_current_user(const char* username) {
    if (!check_connection_status()) {
        return;
    }
    
    if (username) {
        strncpy(current_user, username, sizeof(current_user) - 1);
        current_user[sizeof(current_user) - 1] = '\0';
    } else {
        memset(current_user, 0, sizeof(current_user));
    }
}

// Send a disconnect request
bool send_disconnect_request(const char* username) {
    if (!check_connection_status()) {
        return false;
    }

    Message msg;
    msg.type = LOGOUT_REQUEST;
    strncpy(msg.data, username, sizeof(msg.data) - 1);
    msg.length = strlen(msg.data);
    msg.checksum = calculate_checksum(msg.data, msg.length);

    bool result = send_message_to_server(&msg);
    if (result) {
        cleanup_network();
    }
    return result;
}

// Send a logout request
bool send_logout_request(void) {
    Message msg;
    msg.type = LOGOUT_REQUEST;
    msg.length = 0;
    bool result = send_message_to_server(&msg);

    if (result) {
        cleanup_network();
    }
    return result;
}

// Update the user status
void update_user_status(const char* username, bool is_online) {
    if (!check_connection_status()) {
        return;
    }

    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Updating status for user %s: %s", 
             username, is_online ? "online" : "offline");
    log_client_message(LOG_INFO, log_message);
    
    Message msg;
    msg.type = USER_STATUS_UPDATE;
    snprintf(msg.data, sizeof(msg.data), "%s:%d", username, is_online);
    msg.length = strlen(msg.data);
    send_message_to_server(&msg);
}

// Request the user list
void request_user_list(void) {
    if (!check_connection_status()) {
        return;
    }

    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Requesting user list");
    log_client_message(LOG_INFO, log_message);
    
    Message msg;
    msg.type = USER_LIST_REQUEST;
    msg.length = 0;
    send_message_to_server(&msg);
}