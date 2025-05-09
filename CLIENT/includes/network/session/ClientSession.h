#ifndef CLIENTSESSION_H
#define CLIENTSESSION_H

#include <stdbool.h>
#include <winsock2.h>
#include <time.h>

#define MAX_USERNAME_LENGTH 32

typedef struct {
    SOCKET socket;
    bool isAuthenticated;
    char username[MAX_USERNAME_LENGTH];
    time_t lastActivity;
} ClientSession;

ClientSession* create_client_session(SOCKET socket);
void destroy_client_session(ClientSession* session);
bool authenticate_session(ClientSession* session, const char* username);
void invalidate_session(ClientSession* session);
bool is_session_valid(ClientSession* session);
bool is_session_valid_initial(ClientSession* session);
ClientSession* get_current_session(void);
bool set_current_session(ClientSession* session); 

#endif