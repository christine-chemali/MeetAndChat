#ifndef SERVER_FUNCS_H
#define SERVER_FUNCS_H

#include <winsock2.h>
#include "servernetwork/login/LoginHandler.h"

int bindServer(SOCKET serverSocket, struct sockaddr_in* address);
int listenConnection(SOCKET serverSocket);
DWORD WINAPI clientThread(LPVOID lpParam);
DWORD WINAPI recvThread(LPVOID lpParam);

#endif
//ea