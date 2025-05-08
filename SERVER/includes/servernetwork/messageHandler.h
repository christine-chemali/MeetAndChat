#ifndef MESSAGEHANDLER_H
#define MESSAGEHANDLER_H

#include <winsock2.h>
#include "utilsnetwork/Message.h"
#include "servernetwork/login/LoginHandler.h"
#include "security/NetworkSecurity.h"

Message* receive_message(SOCKET socket);
void free_message(Message* msg);
void handle_client_message(ClientSession* session, Message* msg);
bool send_message_to_client(ClientSession* session, Message* msg);

#endif