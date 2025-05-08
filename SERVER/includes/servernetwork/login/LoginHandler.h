#ifndef LOGINHANDLER_H
#define LOGINHANDLER_H

#include "utilsnetwork/Message.h"
#include <winsock2.h>
#include <stdbool.h>

typedef struct {
    SOCKET clientSocket;
    bool isAuthenticated;
    char email[256];
    int userId;
} ClientSession;

bool handle_login_request(ClientSession* session, Message* msg);
bool send_login_response(ClientSession* session, bool success, const char* message);
void handle_logout_request(ClientSession* session);

#endif