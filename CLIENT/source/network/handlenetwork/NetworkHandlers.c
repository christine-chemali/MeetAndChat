#include "network/handlenetwork/NetworkHandlers.h"
#include "network/log/ClientLogging.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

//Notify opening conversation
void notify_server_conversation_opened(const char *username) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Opening conversation with %s", username);
    log_client_message(LOG_INFO, log_message);
}
//to request conversation history 
void request_conversation_history(const char *username) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Requesting history for user: %s", username);
    log_client_message(LOG_DEBUG, log_message);
    
    const char *test_messages[] = {"Message 1", "Message 2"};
    on_history_received(username, test_messages, 2);
}
// to subscribe to messages 
void subscribe_to_messages(const char *username) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Subscribing to messages from: %s", username);
    log_client_message(LOG_INFO, log_message);
}
// to send messages
void send_message(const char *username, const char *message) {
    if (!username || !message) {
        log_client_message(LOG_ERROR, "Attempted to send message with null username or message");
        return;
    }

    char log_message[512];
    snprintf(log_message, sizeof(log_message), "Sending message to %s: %s", username, message);
    log_client_message(LOG_DEBUG, log_message);
    
    on_message_received(username, "Test reply");
}
// Receving messages
void on_message_received(const char *username, const char *message) {
    if (!username || !message) {
        log_client_message(LOG_ERROR, "Received message with null username or content");
        return;
    }

    char log_message[512];
    snprintf(log_message, sizeof(log_message), "Received message from %s: %s", username, message);
    log_client_message(LOG_INFO, log_message);
}
//Receving history messages
void on_history_received(const char *username, const char **messages, int count) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Received %d messages from history with %s", 
             count, username);
    log_client_message(LOG_INFO, log_message);
}
//change status user online offline
void on_user_status_changed(const char *username, bool is_online) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "User %s status changed to: %s", 
             username, is_online ? "online" : "offline");
    log_client_message(LOG_INFO, log_message);
}
//request user list
void request_user_list(void) {
    log_client_message(LOG_DEBUG, "Requesting user list");
    const char *users[] = {"User1", "User2", "User3"};
    // Simulate Ui update
}
// Server Connection
void connect_to_server(const char *address, int port) {
    if (!address) {
        log_client_message(LOG_ERROR, "Attempted to connect with null address");
        return;
    }

    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Connecting to server at %s:%d", address, port);
    log_client_message(LOG_INFO, log_message);

    if (port < 1024) {
        log_client_message(LOG_ERROR, "Connection failed: privileged port requires root access");
        return;
    }
}
//Server Disconnection
void disconnect_from_server(void) {
    log_client_message(LOG_INFO, "Disconnecting from server");
}