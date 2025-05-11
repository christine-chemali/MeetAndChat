#include "security/NetworkSecurity.h"
#include "security/encrypt_decrypt.h"
#include "utilsnetwork/Message.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <stdio.h>

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
    char log_buffer[256];
    static const size_t expected_size = sizeof(int) * 3 + MAX_MESSAGE_LENGTH;
    
    if (sizeof(Message) != expected_size) {
        snprintf(log_buffer, sizeof(log_buffer), 
            "SEC: Structure size validation failed");
        LOG_MESSAGE(LOG_WARNING, log_buffer);
    }
    
    if (is_security_initialized) {
        return true;  
    }

    memset(session_key, 0, sizeof(session_key));
    generate_random_key(session_key, SECURITY_KEY_LENGTH);
    session_key[SECURITY_KEY_LENGTH] = '\0';
    
    if (strlen(session_key) != SECURITY_KEY_LENGTH) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Initialization failed");
        return false;
    }

    is_security_initialized = true;
    LOG_MESSAGE(LOG_INFO, "SEC: Initialization complete");
    return true;
}

// Encrypt message
void encrypt_message(Message* msg, const char* key) {
    if (!msg || !key || !is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Encryption failed - invalid state");
        return;
    }

    if (msg->type == HEARTBEAT) {
        msg->length = 0;
        msg->checksum = 0;
        memset(msg->data, 0, MAX_MESSAGE_LENGTH);
        return;
    }

    // Calculate checksum on non encrypted data 
    msg->checksum = calculate_checksum(msg->data, msg->length);
    
    // encrypt data
    xor_cipher(msg->data, key, msg->length);

    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer), 
        "SEC: Message encrypted with checksum: %u", msg->checksum);
    LOG_MESSAGE(LOG_DEBUG, log_buffer);
}

// decrypt message
void decrypt_message(Message* msg, const char* key) {
    if (!msg || !key || !is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Decryption failed - invalid state");
        return;
    }

    if (msg->type == HEARTBEAT) {
        return;
    }

    // Sauve original checksum
    unsigned int original_checksum = msg->checksum;
    
    // Decrypt data
    xor_cipher(msg->data, key, msg->length);
    
    // Calculate checksum on decrypted data
    unsigned int calculated_checksum = calculate_checksum(msg->data, msg->length);

    if (calculated_checksum != original_checksum) {
        char log_buffer[256];
        snprintf(log_buffer, sizeof(log_buffer), 
            "SEC: Checksum mismatch - Expected: %u, Got: %u", 
            original_checksum, calculated_checksum);
        LOG_MESSAGE(LOG_ERROR, log_buffer);
        
        // Re encrypt data in error cases
        xor_cipher(msg->data, key, msg->length);
        msg->checksum = original_checksum;
        return;
    }

    LOG_MESSAGE(LOG_DEBUG, "SEC: Message decrypted successfully");
}

// Returns the current session key
char* get_session_key(void) {
    if (!is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Key access denied - not initialized");
        return NULL;
    }
    return session_key;
}

// Calculate a checksum for the given data
unsigned int calculate_checksum(const char* data, int length) {
    if (!data || length < 0 || length > MAX_MESSAGE_LENGTH) {
        return 0;
    }
    
    unsigned int checksum = 0;
    for (int i = 0; i < length; i++) {
        checksum += (unsigned char)data[i];
    }
    return checksum;
}

// Verify if the message's checksum matches its data
bool verify_message_checksum(Message* msg) {
    char log_buffer[256];
    
    if (!msg) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Verification failed - null message");
        return false;
    }

    // For heartbeats accept 0 for length
    if (msg->type == HEARTBEAT) {
        if (msg->length != 0) {
            snprintf(log_buffer, sizeof(log_buffer), 
                "SEC: Invalid heartbeat detected");
            LOG_MESSAGE(LOG_ERROR, log_buffer);
            return false;
        }
        return true;
    }

    // For other messages: standard verification
    if (msg->length < 0 || msg->length > MAX_MESSAGE_LENGTH) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Invalid message length");
        return false;
    }

    // Verify real data length
    size_t actual_length = strnlen(msg->data, MAX_MESSAGE_LENGTH);
    if (actual_length != msg->length) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Message length mismatch");
        return false;
    }

    // Calculate and compare checksum
    unsigned int calculated = calculate_checksum(msg->data, msg->length);
    if (calculated != msg->checksum) {
        LOG_MESSAGE(LOG_WARNING, "SEC: Checksum verification failed");
        return false;
    }

    LOG_MESSAGE(LOG_DEBUG, "SEC: Verification successful");
    return true;
}

// Prepares the message by calculating its checksum
void prepare_message(Message* msg) {
    if (!msg) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Message preparation failed");
        return;
    }

    // Secure data truncation
    size_t data_len = strnlen(msg->data, MAX_MESSAGE_LENGTH);
    if (data_len >= MAX_MESSAGE_LENGTH) {
        LOG_MESSAGE(LOG_WARNING, "SEC: Message truncated");
        msg->data[MAX_MESSAGE_LENGTH - 1] = '\0';
        data_len = MAX_MESSAGE_LENGTH - 1;
    }
    
    msg->length = (int)data_len;
    msg->checksum = calculate_checksum(msg->data, msg->length);
    LOG_MESSAGE(LOG_DEBUG, "SEC: Message prepared");
}

#ifdef IS_CLIENT
// Client specific code - Handle key rotation message
void handle_key_rotation(Message* msg) {
    if (!msg || msg->type != KEY_ROTATION || 
        msg->length != SECURITY_KEY_LENGTH) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Key rotation failed");
        return;
    }

    strncpy(session_key, msg->data, SECURITY_KEY_LENGTH);
    session_key[SECURITY_KEY_LENGTH] = '\0';
    LOG_MESSAGE(LOG_INFO, "SEC: Key rotation complete");
}

// Request a new key rotation from server
bool request_key_rotation(void) {
    if (!is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Cannot request key rotation");
        return false;
    }

    Message key_request = {0};
    key_request.type = KEY_ROTATION_REQUEST;
    key_request.length = 0;
    prepare_message(&key_request);
    
    LOG_MESSAGE(LOG_INFO, "SEC: Key rotation requested");
    return send_message_to_server(&key_request);
}

#else
// Server specific code - Generate and send new session key
Message* rotate_session_key(void) {
    if (!is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Key rotation failed - not initialized");
        return NULL;
    }

    char new_key[SECURITY_KEY_LENGTH + 1] = {0};
    generate_random_key(new_key, SECURITY_KEY_LENGTH);
    new_key[SECURITY_KEY_LENGTH] = '\0';
    
    Message* key_rotation = malloc(sizeof(Message));
    if (!key_rotation) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Key rotation failed - memory error");
        return NULL;
    }
    
    memset(key_rotation, 0, sizeof(Message));
    key_rotation->type = KEY_ROTATION;
    strncpy(key_rotation->data, new_key, SECURITY_KEY_LENGTH);
    key_rotation->length = SECURITY_KEY_LENGTH;
    prepare_message(key_rotation);
    
    strncpy(session_key, new_key, SECURITY_KEY_LENGTH + 1);
    LOG_MESSAGE(LOG_INFO, "SEC: Key rotation complete");
    
    return key_rotation;
}
#endif