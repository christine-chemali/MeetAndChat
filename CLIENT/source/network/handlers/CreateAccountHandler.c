#include "network/core/MessageSender.h"
#include "network/handlers/CreateAccountHandler.h"
#include "network/core/NetworkCore.h"
#include "network/log/ClientLogging.h"
#include "callbacks/GuiCallbacks.h"
#include "security/NetworkSecurity.h"
#include <glib.h>
#include <stdio.h>
#include <string.h>

// Send a registration request
bool send_registration_request(const char *first_name, const char *last_name, 
    const char *username, const char *email, 
    const char *password, const char *first_question, 
    const char *second_question) {
    
    Message msg;
    msg.type = REGISTER_REQUEST;

    snprintf(msg.data, MAX_MESSAGE_LENGTH, "%s|%s|%s|%s|%s|%s|%s",
             first_name, last_name, username, email, 
             password, first_question, second_question);

    msg.length = strlen(msg.data);
    msg.checksum = calculate_checksum(msg.data, msg.length);

    return send_message_to_server(&msg);  
}

// Handle registration response
void handle_register_response(Message* msg) {
    bool success = false;
    char message[256] = {0};
    
    if (sscanf(msg->data, "%d:%[^\n]", &success, message) != 2) {
        success = false;
        strncpy(message, "Invalid server response", sizeof(message) - 1);
        log_client_message(LOG_ERROR, "Invalid registration response from server");
    }
    
    log_client_message(LOG_INFO, "Received registration response from server");
    g_idle_add((GSourceFunc)on_register_response, g_memdup2(&(struct {
        bool success;
        char message[256];
    }){success, {0}}, sizeof(struct {
        bool success;
        char message[256];
    })));
}