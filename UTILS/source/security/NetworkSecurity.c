#include "security/NetworkSecurity.h"
#include "security/encrypt_decrypt.h"
#include "utilsnetwork/Message.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

#ifdef IS_CLIENT
#include "network/handlenetwork/NetworkHandlers.h"
#endif

//session key used for encryption/decryption
static char session_key[SECURITY_KEY_LENGTH + 1];

//Init security generating session key
bool initialize_security(void) {
    if (session_key == NULL) {
        return false;
    }
    generate_random_key(session_key, SECURITY_KEY_LENGTH);
    session_key[SECURITY_KEY_LENGTH] = '\0';
    if (strlen(session_key) != SECURITY_KEY_LENGTH) {
        return false;
    }
    return true;
}

//Encrypts the message using the provided key
void encrypt_message(Message* msg, const char* key) {
    if (msg && key) {
        xor_cipher(msg->data, key);
    }
}

//Decrypts the message using the provided key
void decrypt_message(Message* msg, const char* key) {
    if (msg && key) {
        xor_cipher(msg->data, key);
    }
}

//Returns the current session key
char* get_session_key(void) {
    return session_key;
}

//Calculate a checksum for the given data
unsigned int calculate_checksum(const char* data, int length) {
    unsigned int sum = 0;
    for (int i = 0; i < length; i++) {
        sum += (unsigned char)data[i]; 
    }
    return sum;
}

//verify if the message's checksum matches its data
bool verify_message_checksum(Message* msg) {
    if (!msg) return false;
    unsigned int calculated = calculate_checksum(msg->data, msg->length);
    return calculated == msg->checksum;
}

//prepares the message by calculating its checksum
void prepare_message(Message* msg) {
    msg->checksum = calculate_checksum(msg->data, msg->length);
}

#ifdef IS_CLIENT
// Client-specific code
void handle_key_rotation(Message* msg) {
    if (msg && msg->type == KEY_ROTATION && msg->length == SECURITY_KEY_LENGTH) {
        strncpy(session_key, msg->data, SECURITY_KEY_LENGTH);
        session_key[SECURITY_KEY_LENGTH] = '\0';
    }
}

bool request_key_rotation(void) {
    Message key_request;
    key_request.type = KEY_ROTATION_REQUEST;
    key_request.length = 0;
    prepare_message(&key_request);
    
    return send_message_to_server(&key_request);
}

#else
// Server-specific code
Message* rotate_session_key(void) {
    char new_key[SECURITY_KEY_LENGTH + 1];
    generate_random_key(new_key, SECURITY_KEY_LENGTH);
    new_key[SECURITY_KEY_LENGTH] = '\0';
    
    Message* key_rotation = malloc(sizeof(Message));
    if (key_rotation == NULL) {
        return NULL;
    }
    
    key_rotation->type = KEY_ROTATION;
    strncpy(key_rotation->data, new_key, SECURITY_KEY_LENGTH);
    key_rotation->length = SECURITY_KEY_LENGTH;
    prepare_message(key_rotation);
    
    strncpy(session_key, new_key, SECURITY_KEY_LENGTH + 1);
    
    return key_rotation;
}
#endif
//cc