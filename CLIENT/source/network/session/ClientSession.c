#include "network/session/ClientSession.h"
#include "network/log/ClientLogging.h"
#include "security/NetworkSecurity.h"
#include "utilsnetwork/Message.h"
#include "network/core/MessageSender.h" 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Global variable for the current session
static ClientSession* current_session = NULL;

// Create a new client session
ClientSession* create_client_session(SOCKET socket) {
    ClientSession* session = (ClientSession*)malloc(sizeof(ClientSession));
    if (!session) {
        log_client_message(LOG_ERROR, "Failed to allocate memory for session");
        return NULL;
    }

    memset(session, 0, sizeof(ClientSession));
    session->socket = socket;
    session->isAuthenticated = false;
    session->lastActivity = time(NULL);
    memset(session->username, 0, sizeof(session->username));

    log_client_message(LOG_INFO, "Client session created successfully");
    return session;
}

// Set the current session
bool set_current_session(ClientSession* session) {
    if (current_session) {
        log_client_message(LOG_WARNING, "Overwriting existing session");
        destroy_client_session(current_session);
    }
    current_session = session;
    log_client_message(LOG_INFO, "Current session updated");
    return true;
}

// Get the current session
ClientSession* get_current_session(void) {
    if (!current_session) {
        log_client_message(LOG_WARNING, "Attempting to get null session");
    }
    return current_session;
}

// Destroy a client session
void destroy_client_session(ClientSession* session) {
    if (session) {
        if (session->socket != INVALID_SOCKET) {
            closesocket(session->socket);
            session->socket = INVALID_SOCKET;
        }
        if (session == current_session) {
            current_session = NULL;
        }
        free(session);
        log_client_message(LOG_INFO, "Client session destroyed");
    }
}

// Authenticate a session with a username
bool authenticate_session(ClientSession* session, const char* username) {
    if (!session || !username) {
        log_client_message(LOG_ERROR, "Invalid parameters for session authentication");
        return false;
    }
    
    session->isAuthenticated = true;
    strncpy(session->username, username, sizeof(session->username) - 1);
    session->username[sizeof(session->username) - 1] = '\0';
    session->lastActivity = time(NULL);
    
    log_client_message(LOG_INFO, "Session authenticated successfully");
    return true;
}

// Invalidate a session
void invalidate_session(ClientSession* session) {
    if (session) {
        session->isAuthenticated = false;
        memset(session->username, 0, sizeof(session->username));
        log_client_message(LOG_INFO, "Session invalidated");
    }
}

// Check if a session is valid
bool is_session_valid(ClientSession* session) {
    if (!session) {
        return false;
    }
    
    time_t current_time = time(NULL);
    const time_t SESSION_TIMEOUT = 3600; // 1 hour timeout
    
    if (!session->isAuthenticated || 
        (current_time - session->lastActivity) > SESSION_TIMEOUT) {
        return false;
    }
    
    return true;
}

// Check if an initial session is valid
bool is_session_valid_initial(ClientSession* session) {
    return session && session->socket != INVALID_SOCKET;
}