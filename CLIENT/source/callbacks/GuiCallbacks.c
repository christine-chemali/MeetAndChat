
#include "callbacks/GuiCallbacks.h"
#include <stdio.h>  

//TODO: those are temporary versions
void on_message_received(const char* username, const char* message) {
    printf("Message received from %s: %s\n", username, message);
}

void on_login_response(bool success, const char* message) {
    printf("Login response: %s - %s\n", success ? "Success" : "Failed", message);
}

void on_history_received(const char* username, const char** messages, int count) {
    printf("History received from %s (%d messages)\n", username, count);
}

void on_user_status_changed(const char* username, bool is_online) {
    printf("User %s is now %s\n", username, is_online ? "online" : "offline");
}

void on_register_response(bool success, const char* message) {
    printf("Register response: %s - %s\n", success ? "Success" : "Failed", message);
}