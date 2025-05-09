#ifndef CREATEACCOUNTHANDLER_H
#define CREATEACCOUNTHANDLER_H

#include <stdbool.h>
#include "utilsnetwork/Message.h"

// Registration functions
bool send_registration_request(const char *first_name, const char *last_name, 
    const char *username, const char *email, 
    const char *password, const char *first_question, 
    const char *second_question);
    
void handle_register_response(Message* msg);

#endif 