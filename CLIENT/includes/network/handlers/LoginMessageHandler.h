#ifndef LOGINMESSAGEHANDLER_H
#define LOGINMESSAGEHANDLER_H

#include <stdbool.h>
#include "utilsnetwork/Message.h"

// Login and authentication functions
void handle_login_response(Message* msg);
void handle_disconnect_response(Message* msg);
bool send_login_request(const char* username, const char* password);

#endif