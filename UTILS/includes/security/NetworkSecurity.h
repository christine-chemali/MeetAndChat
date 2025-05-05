#ifndef NETWORKSECURITY_H
#define NETWORKSECURITY_H
#define KEYROTATIONINTERVAL 3600  // 1 hour

#include "encrypt_decrypt.h"
#include "utilsnetwork/Message.h"
#include <stdbool.h>

#define SECURITY_KEY_LENGTH 16

// Secure message structure
typedef struct {
    Message msg;
    char encryption_key[SECURITY_KEY_LENGTH + 1];
} SecureMessage;

// Common functions
bool verify_message_checksum(Message* msg);
void encrypt_message(Message* msg, const char* key);
void decrypt_message(Message* msg, const char* key);
bool initialize_security(void);  
char* get_session_key(void);
void prepare_message(Message* msg);
unsigned int calculate_checksum(const char* data, int length);

// Client/Server specific functions
#ifdef IS_CLIENT
void handle_key_rotation(Message* msg);
bool request_key_rotation(void);
#else
Message* rotate_session_key(void);
#endif

#endif
//cc