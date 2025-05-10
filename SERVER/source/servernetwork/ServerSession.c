#include "servernetwork/ServerSession.h"
#include "serverlogging/ServerLogging.h"
#include <stdlib.h>
#include <string.h>

static ClientSession* session_list = NULL;

//Create client session
ClientSession* create_client_session(SOCKET client_socket) {
    char log_buffer[256];
    
    ClientSession* session = (ClientSession*)malloc(sizeof(ClientSession));
    if (!session) {
        snprintf(log_buffer, sizeof(log_buffer),
            "SESS: Memory allocation failed for socket %d", 
            (int)client_socket);
        log_server_message(LOG_ERROR, log_buffer);
        return NULL;
    }

    memset(session, 0, sizeof(ClientSession));
    session->clientSocket = client_socket;
    session->isAuthenticated = false;
    session->userId = 0;
    session->next = NULL;

    add_session_to_list(session);
    
    snprintf(log_buffer, sizeof(log_buffer),
        "SESS: Created session for socket %d", 
        (int)client_socket);
    log_server_message(LOG_INFO, log_buffer);
    
    return session;
}

// destroy client session
void destroy_client_session(ClientSession* session) {
    char log_buffer[256];
    
    if (!session) {
        log_server_message(LOG_WARNING, "SESS: Attempt to destroy null session");
        return;
    }

    snprintf(log_buffer, sizeof(log_buffer),
        "SESS: Destroying session for socket %d", 
        (int)session->clientSocket);
    log_server_message(LOG_INFO, log_buffer);

    remove_session_from_list(session);
    closesocket(session->clientSocket);
    free(session);
}

// handle thread-safe list of sessions
void add_session_to_list(ClientSession* session) {
    char log_buffer[256];
    
    if (!session) {
        log_server_message(LOG_WARNING, "SESS: Attempt to add null session to list");
        return;
    }
    
    session->next = session_list;
    session_list = session;
    
    snprintf(log_buffer, sizeof(log_buffer),
        "SESS: Added socket %d to session list", 
        (int)session->clientSocket);
    log_server_message(LOG_DEBUG, log_buffer);
}

//Remove session from list
void remove_session_from_list(ClientSession* target) {
    char log_buffer[256];
    
    if (!target) {
        log_server_message(LOG_WARNING, "SESS: Attempt to remove null session from list");
        return;
    }

    ClientSession** pp = &session_list;
    
    while (*pp) {
        if (*pp == target) {
            *pp = target->next;
            snprintf(log_buffer, sizeof(log_buffer),
                "SESS: Removed socket %d from session list", 
                (int)target->clientSocket);
            log_server_message(LOG_DEBUG, log_buffer);
            break;
        }
        pp = &(*pp)->next;
    }
}

//Cleanup client sessions
void cleanup_all_sessions(void) {
    char log_buffer[256];
    int count = 0;
    
    ClientSession* current = session_list;
    while (current) {
        ClientSession* next = current->next;
        count++;
        destroy_client_session(current);
        current = next;
    }
    session_list = NULL;

    snprintf(log_buffer, sizeof(log_buffer),
        "SESS: Cleaned up %d sessions", count);
    log_server_message(LOG_INFO, log_buffer);
}