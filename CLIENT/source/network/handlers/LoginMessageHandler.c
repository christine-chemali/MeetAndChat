
#include "network/core/MessageSender.h"
#include "network/handlers/LoginMessageHandler.h"
#include "network/core/NetworkCore.h"
#include "network/core/SessionManager.h"
#include "network/log/ClientLogging.h"
#include "callbacks/GuiCallbacks.h"
#include "security/NetworkSecurity.h"
#include "network/session/ClientSession.h"
#include <glib.h>
#include <stdio.h>
#include <string.h>

    // Handle login response
void handle_login_response(Message* msg) {
    bool success = false;
    char message[256] = {0};
    char username[256] = {0};

    // Convert UTF-8 
    char* utf8_data = g_utf8_make_valid(msg->data, -1);
    
    if (sscanf(utf8_data, "%d:%[^\n]", &success, message) != 2) { 
        success = false;
        strncpy(message, "Invalid server response", sizeof(message) - 1);
        log_client_message(LOG_ERROR, "Invalid login response from server");
    }

    ClientSession* session = get_current_session();
    
    if (success && session) {
        authenticate_session(session, username);
        strncpy(current_user, username, sizeof(current_user) - 1);
        current_user[sizeof(current_user) - 1] = '\0';
        log_client_message(LOG_INFO, "User authenticated successfully");
    } else {
        if (session) {
            invalidate_session(session);
        }
        log_client_message(LOG_WARNING, "Authentication failed");
    }
    
    g_free(utf8_data);
    
    // struct def
    typedef struct {
        bool success;
        char message[256];
    } LoginResponse;
    
    // Allocate memory
    LoginResponse* response_data = g_new0(LoginResponse, 1);
    
    // fill the struct
    response_data->success = success;
    strncpy(response_data->message, message, sizeof(response_data->message) - 1);
    
    // Add callback
    g_idle_add((GSourceFunc)on_login_response, response_data);
}

// Handle disconnect response
void handle_disconnect_response(Message* msg) {
    bool success = false;
    char message[256] = {0};

    if (sscanf(msg->data, "%d:%[^\n]", &success, message) != 2) {
        success = false;
        strncpy(message, "Invalid server response", sizeof(message) - 1);
    }
    
    g_idle_add((GSourceFunc)on_disconnect_response, g_memdup2(&(struct {
        bool success;
        char message[256];
    }){success, {0}}, sizeof(struct {
        bool success;
        char message[256];
    })));
}

// Send login request
bool send_login_request(const char* username, const char* password) {
    if (!check_connection_status()) {
        return false;
    }

    if (!username || !password) {
        log_client_message(LOG_ERROR, "Invalid login credentials");
        return false;
    }

    log_client_message(LOG_INFO, "Preparing login request");
    Message msg;
    memset(&msg, 0, sizeof(Message));
    msg.type = LOGIN_REQUEST;
    
    if (snprintf(msg.data, sizeof(msg.data), "%s:%s", username, password) >= sizeof(msg.data)) {
        log_client_message(LOG_ERROR, "Login credentials too long");
        return false;
    }
    
    msg.length = strlen(msg.data);
    log_client_message(LOG_INFO, "Sending login request...");
    
    return send_message_to_server(&msg);
}