//SessionManager.h
#ifndef SESSIONMANAGER_H
#define SESSIONMANAGER_H

#include <stdbool.h>
#include "utilsnetwork/Message.h"

// External variable declaration
extern char current_user[256];

// User management
const char* get_current_user(void);
void set_current_user(const char* username);

// Session management
bool send_disconnect_request(const char* username);
bool send_logout_request(void);
void update_user_status(const char* username, bool is_online);
void request_user_list(void);

#endif