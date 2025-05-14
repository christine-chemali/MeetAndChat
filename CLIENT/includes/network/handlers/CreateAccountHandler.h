#ifndef CREATEACCOUNTHANDLER_H
#define CREATEACCOUNTHANDLER_H

#include "utilsnetwork/Message.h"
#include <stdbool.h>

// Fonction d'envoi de la requête d'inscription
bool send_registration_request(
    const char *first_name, 
    const char *last_name, 
    const char *username, 
    const char *email, 
    const char *password, 
    const char *first_question, 
    const char *second_question
);

// Fonction de gestion de la réponse d'inscription
void handle_register_response(Message* msg);

#endif // CREATE_ACCOUNT_HANDLER_H