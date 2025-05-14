#ifndef REGISTERHANDLER_H
#define REGISTERHANDLER_H

#include "utilsnetwork/Message.h"
#include "servernetwork/ServerSession.h"
#include <winsock2.h>
#include <stdbool.h>

bool handle_register_request(ClientSession* session, Message* msg);
bool send_register_response(ClientSession* session, bool success, const char* message);

#endif