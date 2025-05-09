#ifndef MAINAPPHANDLER_H
#define MAINAPPHANDLER_H

#include "utilsnetwork/Message.h"
#include <stdbool.h>

void handle_message_response(Message* msg);
void handle_fetch_messages_response(Message* msg);
bool send_chat_message(const char* username, const char* message);
bool request_message_history(const char* username);
void notify_server_conversation_opened(const char* username);
void request_conversation_history(const char* username);
void subscribe_to_messages(const char* username);

#endif