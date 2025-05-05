#include "utilsnetwork/networkFuncs.h"


int initWinsock(){
    WSADATA wsaData;
    int WSAStartCode= WSAStartup(MAKEWORD(2,2), &wsaData);
    if (WSAStartCode!=0){
        printf("WSAStartup failed, code: %d \n", WSAStartCode);
        return 0;
    }
    printf("WSA started successfully \n");
    return 1;
}

SOCKET createSocket(){
    SOCKET newSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (newSocket==INVALID_SOCKET){
        printf("invalid socket, code: %d \n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    return newSocket;
}

struct sockaddr_in createAddress(const char* ip, int port){
    struct sockaddr_in newAddress;
    newAddress.sin_family=AF_INET;
    newAddress.sin_port= htons(port);
    newAddress.sin_addr.s_addr=inet_addr(ip);

    if (newAddress.sin_addr.s_addr==INADDR_NONE){
        printf("invalid ip address: %s\n", ip);
    }

    return newAddress;
}

HANDLE newThread(SOCKET* socket, LPTHREAD_START_ROUTINE routine){
    SOCKET* sockCopy=malloc(sizeof(SOCKET));
    if (sockCopy){
    *sockCopy= *socket;
    } else {
        printf("memory allocation failed \n");
        return NULL;
    }

    HANDLE threadHandle= CreateThread(NULL, 0, routine, sockCopy, 0, NULL);
    if (threadHandle==NULL){
        printf("failed to create thread, error: %d", GetLastError());
        free(sockCopy);
    }

    return threadHandle;
}

//ea