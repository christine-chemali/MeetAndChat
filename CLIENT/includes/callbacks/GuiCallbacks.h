#ifndef GUICALLBACKS_H
#define GUICALLBACKS_H

#include <stdbool.h>

// Message handling callbacks
void on_message_received(const char* username, const char* message);
void on_history_received(const char* username, const char** messages, int count);

// User management callbacks
void on_user_status_changed(const char* username, bool is_online);
void on_login_response(bool success, const char* message);
void on_register_response(bool success, const char* message);

#endif