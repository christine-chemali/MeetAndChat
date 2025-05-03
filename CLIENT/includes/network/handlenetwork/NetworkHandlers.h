#ifndef NETWORKHANDLERS_H
#define NETWORKHANDLERS_H


#include <stdbool.h>
#include "network/log/ClientLogging.h" 

// Communication functions
void notify_server_conversation_opened(const char *username);
void request_conversation_history(const char *username);
void subscribe_to_messages(const char *username);
void send_message(const char *username, const char *message);
void on_message_received(const char *username, const char *message);
void on_history_received(const char *username, const char **messages, int count);
void on_user_status_changed(const char *username, bool is_online);
void request_user_list(void);
void connect_to_server(const char *address, int port);
void disconnect_from_server(void);

#endif