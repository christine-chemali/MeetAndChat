#ifndef SERVERSESSION_H
#define SERVERSESSION_H

#include <winsock2.h>
#include <stdbool.h> 
#include "utilsnetwork/Message.h"

// Client session struct
typedef struct ClientSession {
    SOCKET clientSocket;
    char session_key[32];  
    bool isAuthenticated;
    unsigned int userId;
    char username[100];   
    char email[256];       
    struct ClientSession* next; 
    time_t lastActivity; 
} ClientSession;

// handleling sessions
ClientSession* create_client_session(SOCKET client_socket);
void destroy_client_session(ClientSession* session);
void cleanup_all_sessions(void);

// handeling list of sessions
void add_session_to_list(ClientSession* session);
void remove_session_from_list(ClientSession* session);

#endif