#include "servernetwork/ServerSession.h"
#include "serverlogging/ServerLogging.h"
#include <stdlib.h>
#include <string.h>

static ClientSession* session_list = NULL;

//Create client session
ClientSession* create_client_session(SOCKET client_socket) {
    ClientSession* session = (ClientSession*)malloc(sizeof(ClientSession));
    if (!session) {
        log_server_message(ERROR, "Memory allocation failed for new session");
        return NULL;
    }

    memset(session, 0, sizeof(ClientSession));
    session->clientSocket = client_socket;
    session->isAuthenticated = false;
    session->userId = 0;
    session->next = NULL;

    add_session_to_list(session);
    return session;
}

// destroy client session
void destroy_client_session(ClientSession* session) {
    if (!session) return;

    remove_session_from_list(session);
    closesocket(session->clientSocket);
    free(session);
}

// handle thread-safe list of sessions
void add_session_to_list(ClientSession* session) {
    if (!session) return;
    
    session->next = session_list;
    session_list = session;
}

//Remove session from list
void remove_session_from_list(ClientSession* target) {
    ClientSession** pp = &session_list;
    
    while (*pp) {
        if (*pp == target) {
            *pp = target->next;
            break;
        }
        pp = &(*pp)->next;
    }
}

//Cleanup client sessions
void cleanup_all_sessions(void) {
    ClientSession* current = session_list;
    while (current) {
        ClientSession* next = current->next;
        destroy_client_session(current);
        current = next;
    }
    session_list = NULL;
} 
