#include "network/core/MessageSender.h"
#include "network/handlers/MainAppHandler.h"
#include "network/core/NetworkCore.h"
#include "network/log/ClientLogging.h"
#include "callbacks/GuiCallbacks.h"
#include <glib.h>
#include <stdio.h>
#include <string.h>

// Handle message response
void handle_message_response(Message* msg) {  
    char username[256], message[768];    
    sscanf(msg->data, "%[^:]:%s", username, message);
    on_message_received(username, message);
}

// Parse and handle fetched messages  
void handle_fetch_messages_response(Message* msg) {   
  //see if needed
}

// Send a chat message
bool send_chat_message(const char* username, const char* message) {
    if (!check_connection_status()) {
        return false;
    }

    Message msg;
    msg.type = SEND_MESSAGE;
    snprintf(msg.data, sizeof(msg.data), "%s:%s", username, message);
    msg.length = strlen(msg.data);
    return send_message_to_server(&msg);
}

// Request message history
bool request_message_history(const char* username) {
    if (!check_connection_status()) {
        return false;
    }

    Message msg;
    msg.type = FETCH_MESSAGES;
    strncpy(msg.data, username, sizeof(msg.data) - 1);
    msg.length = strlen(msg.data);
    return send_message_to_server(&msg);
}

// Notify the server about a conversation opening
void notify_server_conversation_opened(const char* username) {
    if (!check_connection_status()) {
        return;
    }

    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Opening conversation with %s", username);
    log_client_message(LOG_INFO, log_message);
    
    Message msg;
    msg.type = CONVERSATION_OPENED; 
    strncpy(msg.data, username, sizeof(msg.data) - 1);
    msg.length = strlen(msg.data);
    send_message_to_server(&msg);
}

// Request conversation history
void request_conversation_history(const char* username) {
    if (!check_connection_status()) {
        return;
    }

    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Requesting history for user: %s", username);
    log_client_message(LOG_DEBUG, log_message);
    
    request_message_history(username);
}

// Subscribe to messages from a user
void subscribe_to_messages(const char* username) {
    if (!check_connection_status()) {
        return;
    }

    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Subscribing to messages from: %s", username);
    log_client_message(LOG_INFO, log_message);
    
    Message msg;
    msg.type = SUBSCRIBE_REQUEST; 
    strncpy(msg.data, username, sizeof(msg.data) - 1);
    msg.length = strlen(msg.data);
    send_message_to_server(&msg);
}