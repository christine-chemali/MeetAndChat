#include "network/core/MessageSender.h"
#include "network/handlers/CreateAccountHandler.h"
#include "network/core/NetworkCore.h"
#include "network/core/SessionManager.h"
#include "network/log/ClientLogging.h"
#include "callbacks/GuiCallbacks.h"
#include "security/NetworkSecurity.h"
#include "network/session/ClientSession.h"
#include <glib.h>
#include <stdio.h>
#include <string.h>

// Send registration request
bool send_registration_request(const char *first_name, const char *last_name, 
    const char *username, const char *email, 
    const char *password, const char *first_question, 
    const char *second_question) {
    
    if (!check_connection_status()) {
        return false;
    }

    if (!username || !email || !password) {
        log_client_message(LOG_ERROR, "Invalid registration data");
        return false;
    }

    log_client_message(LOG_INFO, "Preparing registration request");
    Message msg;
    memset(&msg, 0, sizeof(Message));
    msg.type = REGISTER_REQUEST;

    int written = snprintf(msg.data, MAX_MESSAGE_LENGTH, 
        "%s|%s|%s|%s|%s|%s|%s",
        first_name ? first_name : "",
        last_name ? last_name : "",
        username ? username : "",
        email ? email : "",
        password ? password : "",
        first_question ? first_question : "",
        second_question ? second_question : "");

    if (written < 0 || written >= MAX_MESSAGE_LENGTH) {
        log_client_message(LOG_ERROR, "Registration data exceeds maximum length");
        return false;
    }

    msg.length = written;
    msg.checksum = calculate_checksum(msg.data, msg.length);
    
    log_client_message(LOG_INFO, "Sending registration request...");
    return send_message_to_server(&msg);
}

// Handle registration response
void handle_register_response(Message* msg) {
    bool success = false;
    char message[256] = {0};

    // Convert to UTF-8
    char* utf8_data = g_utf8_make_valid(msg->data, -1);
    
    if (sscanf(utf8_data, "%d:%[^\n]", &success, message) != 2) {
        success = false;
        strncpy(message, "Invalid server response", sizeof(message) - 1);
        log_client_message(LOG_ERROR, "Invalid registration response from server");
    }

    ClientSession* session = get_current_session();
    
    if (success && session) {
        log_client_message(LOG_INFO, "Registration successful");
    } else {
        if (session) {
            log_client_message(LOG_WARNING, "Registration failed");
        }
    }
    
    g_free(utf8_data);
    
    // Struct definition
    typedef struct {
        bool success;
        char message[256];
    } RegisterResponse;
    
    // Allocate memory
    RegisterResponse* response_data = g_new0(RegisterResponse, 1);
    
    // Fill the struct
    response_data->success = success;
    strncpy(response_data->message, message, sizeof(response_data->message) - 1);
    
    // Add callback
    g_idle_add((GSourceFunc)on_register_response, response_data);
}