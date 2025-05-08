#ifndef NETWORKFUNCS_H
#define NETWORKFUNCS_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

int initWinsock();

SOCKET createSocket();

struct sockaddr_in createAddress(const char* ip, int port);

HANDLE newThread(SOCKET* socket, LPTHREAD_START_ROUTINE routine);

DWORD WINAPI recvThread(LPVOID lpParam);

DWORD WINAPI sendThread(LPVOID lpParam); //TODO implement for notifications and other non client requests

#endif
//ea