#ifndef SERVERFUNCS_H
#define SERVERFUNCS_H

#include <winsock2.h>
#include "servernetwork/login/LoginHandler.h"

int bindServer(SOCKET serverSocket, struct sockaddr_in* address);
int listenConnection(SOCKET serverSocket);
DWORD WINAPI clientThread(LPVOID lpParam);
DWORD WINAPI recvThread(LPVOID lpParam);
bool handle_new_connection(SOCKET clientSocket);
bool send_session_key_to_client(ClientSession* session);
Message* rotate_session_key(void); 

#endif
