#include "security/NetworkSecurity.h"
#include "security/encrypt_decrypt.h"
#include "utilsnetwork/Message.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

// to compile including the right header depending on client or server side 
#ifdef IS_CLIENT
    #include "network/core/MessageSender.h"
    #include "network/log/ClientLogging.h"
    #define LOG_MESSAGE log_client_message
#else
    #include "serverlogging/ServerLogging.h"
    #define LOG_MESSAGE log_server_message
#endif

// Session key used for encryption/decryption
static char session_key[SECURITY_KEY_LENGTH + 1];
static bool is_security_initialized = false;

// Init security generating session key
bool initialize_security(void) {
    if (is_security_initialized) {
        return true;  
    }

    memset(session_key, 0, sizeof(session_key));
    generate_random_key(session_key, SECURITY_KEY_LENGTH);
    session_key[SECURITY_KEY_LENGTH] = '\0';
    
    if (strlen(session_key) != SECURITY_KEY_LENGTH) {
        LOG_MESSAGE(LOG_ERROR, "Failed to generate valid session key");
        return false;
    }

    is_security_initialized = true;
    LOG_MESSAGE(LOG_INFO, "Security initialized successfully");
    return true;
}

// Encrypts the message using the provided key
void encrypt_message(Message* msg, const char* key) {
    if (!msg || !key) {
        LOG_MESSAGE(LOG_ERROR, "Invalid parameters for message encryption");
        return;
    }
    
    if (!is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "Security not initialized");
        return;
    }

    xor_cipher(msg->data, key);
}

// Decrypts the message using the provided key
void decrypt_message(Message* msg, const char* key) {
    if (!msg || !key) {
        LOG_MESSAGE(LOG_ERROR, "Invalid parameters for message decryption");
        return;
    }
    
    if (!is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "Security not initialized");
        return;
    }

    xor_cipher(msg->data, key);
}

// Returns the current session key
char* get_session_key(void) {
    if (!is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "Attempting to get session key before security initialization");
        return NULL;
    }
    return session_key;
}

// Calculate a checksum for the given data
    unsigned int calculate_checksum(const char* data, int length) {
        if (length < 0 || length > MAX_MESSAGE_LENGTH) {
            return 0;
        }
        
        unsigned int checksum = 0;
        if (length == 0) {
            return checksum;  // return 0 for empty messages
        }
        
        if (!data) {
            return 0;
        }

        for (int i = 0; i < length; i++) {
            checksum += (unsigned char)data[i];
        }
        return checksum;
    }

// Verify if the message's checksum matches its data
bool verify_message_checksum(Message* msg) {
    if (!msg) {
        LOG_MESSAGE(LOG_ERROR, "Null message pointer in checksum verification");
        return false;
    }

    // Verifying declared lenght
    if (msg->length <= 0 || msg->length > MAX_MESSAGE_LENGTH) {
        LOG_MESSAGE(LOG_ERROR, "Invalid message length: %d");
        return false;
    }

    // Verify real data lenght 
    size_t actual_length = strnlen(msg->data, MAX_MESSAGE_LENGTH);
    if (actual_length != msg->length) {
        LOG_MESSAGE(LOG_ERROR, 
            "Data length mismatch (declared: %d, actual: %zu)");
        return false;
    }

    // Calcul and compare checksum
    unsigned int calculated = calculate_checksum(msg->data, msg->length);
    if (calculated != msg->checksum) {
        LOG_MESSAGE(LOG_WARNING, 
            "Checksum mismatch (expected: %u, got: %u)");
        return false;
    }

    return true;
}

// Prepares the message by calculating its checksum
void prepare_message(Message* msg) {
    if (!msg) {
        LOG_MESSAGE(LOG_ERROR, "Null message in prepare_message");
        return;
    }

    // Secure data truncation
    size_t data_len = strnlen(msg->data, MAX_MESSAGE_LENGTH);
    if (data_len >= MAX_MESSAGE_LENGTH) {
        LOG_MESSAGE(LOG_WARNING, "Message data truncated");
        msg->data[MAX_MESSAGE_LENGTH - 1] = '\0';
        data_len = MAX_MESSAGE_LENGTH - 1;
    }
    
    // update data
    msg->length = (int)data_len;
    msg->checksum = calculate_checksum(msg->data, msg->length);
}

#ifdef IS_CLIENT
// Client specific code
void handle_key_rotation(Message* msg) {
    if (!msg) {
        LOG_MESSAGE(LOG_ERROR, "Null message in key rotation handler");
        return;
    }

    if (msg->type != KEY_ROTATION || msg->length != SECURITY_KEY_LENGTH) {
        LOG_MESSAGE(LOG_ERROR, "Invalid key rotation message");
        return;
    }

    strncpy(session_key, msg->data, SECURITY_KEY_LENGTH);
    session_key[SECURITY_KEY_LENGTH] = '\0';
    LOG_MESSAGE(LOG_INFO, "Session key rotated successfully");
}

bool request_key_rotation(void) {
    if (!is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "Security not initialized for key rotation");
        return false;
    }

    Message key_request;
    memset(&key_request, 0, sizeof(Message));
    key_request.type = KEY_ROTATION_REQUEST;
    key_request.length = 0;
    prepare_message(&key_request);
    
    return send_message_to_server(&key_request);
}

#else
// Server specific code
Message* rotate_session_key(void) {
    if (!is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "Security not initialized for key rotation");
        return NULL;
    }

    char new_key[SECURITY_KEY_LENGTH + 1];
    memset(new_key, 0, sizeof(new_key));
    generate_random_key(new_key, SECURITY_KEY_LENGTH);
    new_key[SECURITY_KEY_LENGTH] = '\0';
    
    Message* key_rotation = malloc(sizeof(Message));
    if (!key_rotation) {
        LOG_MESSAGE(LOG_ERROR, "Failed to allocate memory for key rotation message");
        return NULL;
    }
    
    memset(key_rotation, 0, sizeof(Message));
    key_rotation->type = KEY_ROTATION;
    strncpy(key_rotation->data, new_key, SECURITY_KEY_LENGTH);
    key_rotation->length = SECURITY_KEY_LENGTH;
    prepare_message(key_rotation);
    
    strncpy(session_key, new_key, SECURITY_KEY_LENGTH + 1);
    LOG_MESSAGE(LOG_INFO, "New session key generated");
    
    return key_rotation;
}
#endif