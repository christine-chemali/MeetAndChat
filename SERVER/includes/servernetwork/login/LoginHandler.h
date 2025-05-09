#ifndef LOGINHANDLER_H
#define LOGINHANDLER_H

#include "utilsnetwork/Message.h"
#include "servernetwork/ServerSession.h"  
#include <winsock2.h>
#include <stdbool.h>

bool handle_login_request(ClientSession* session, Message* msg);
bool send_login_response(ClientSession* session, bool success, const char* message);
bool handle_disconnect_request(ClientSession* session, const char* email);
void handle_logout_request(ClientSession* session);

#endif