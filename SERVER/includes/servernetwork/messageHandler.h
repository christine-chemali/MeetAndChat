#ifndef MESSAGE_HANDLER_H
#define MESSAGE_HANDLER_H

#include <winsock2.h>
#include "servernetwork/ServerSession.h"
#include <stdbool.h>

Message* receive_message(SOCKET socket);
void free_message(Message* msg);
bool send_message_to_client(ClientSession* session, Message* msg);
Message* create_heartbeat_message(void);
void handle_client_message(ClientSession* session, Message* msg);

#endif 