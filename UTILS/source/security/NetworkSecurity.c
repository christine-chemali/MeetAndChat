#include "security/NetworkSecurity.h"
#include "security/encrypt_decrypt.h"
#include "utilsnetwork/Message.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <stdio.h>
#include <winsock2.h>


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
char session_key[SECURITY_KEY_LENGTH + 1];
bool is_security_initialized = false;

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
        LOG_MESSAGE(LOG_INFO, "SEC: Security already initialized.");
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

// Debug helper function to track message content through processing stages
void debug_message_content(const Message* msg, const char* prefix) {
    if (!msg) {
        LOG_MESSAGE(LOG_ERROR, "DEBUG: Null message pointer");
        return;
    }
    
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer), 
        "%s: type=%d, length=%d, checksum=%u", 
        prefix, msg->type, msg->length, msg->checksum);
    LOG_MESSAGE(LOG_DEBUG, log_buffer);
    
    // Debug the first few bytes of data
    if (msg->length > 0) {
        char data_preview[32] = {0};
        int preview_len = msg->length > 10 ? 10 : msg->length;
        
        for (int i = 0; i < preview_len; i++) {
            snprintf(data_preview + (i*2), 3, "%02X", (unsigned char)msg->data[i]);
        }
        
        snprintf(log_buffer, sizeof(log_buffer), 
            "%s: First %d bytes: %s%s", 
            prefix, preview_len, data_preview, 
            msg->length > 10 ? "..." : "");
        LOG_MESSAGE(LOG_DEBUG, log_buffer);
    }
}

// encrypt message
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
    
    // For key rotation messages, we need special handling
    if (msg->type == KEY_ROTATION) {
        debug_message_content(msg, "SEC: Before key rotation encryption");
        // Calculate checksum but don't encrypt the message
        // This is because the client needs to receive the new key in plaintext
        msg->checksum = calculate_checksum(msg->data, msg->length);
        debug_message_content(msg, "SEC: After key rotation encryption");
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

//Decrypt message
void decrypt_message(Message* msg, const char* key) {
    if (!msg || !key || !is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Decryption failed - invalid state");
        return;
    }

    if (msg->type == HEARTBEAT) {
        return;
    }
    
    // For key rotation messages, we need special handling
    if (msg->type == KEY_ROTATION) {
        debug_message_content(msg, "SEC: Before key rotation decryption");
        // The message should already be in plaintext, just verify checksum
        unsigned int calculated_checksum = calculate_checksum(msg->data, msg->length);
        if (calculated_checksum != msg->checksum) {
            LOG_MESSAGE(LOG_WARNING, "SEC: Key rotation checksum mismatch");
        }
        debug_message_content(msg, "SEC: After key rotation decryption");
        return;
    }

    unsigned int original_checksum = msg->checksum;

    xor_cipher(msg->data, key, msg->length);
    unsigned int calculated_checksum = calculate_checksum(msg->data, msg->length);

    if (calculated_checksum != original_checksum) {
        char log_buffer[256];
        snprintf(log_buffer, sizeof(log_buffer), 
                "SEC: Checksum mismatch - Expected: %u, Got: %u", 
                original_checksum, calculated_checksum);
        LOG_MESSAGE(LOG_ERROR, log_buffer);

        xor_cipher(msg->data, key, msg->length);
        msg->checksum = original_checksum;
        return;
    }

    LOG_MESSAGE(LOG_DEBUG, "SEC: Message decrypted successfully");
}

//Get session key
char* get_session_key(void) {
    if (!is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Key access denied - not initialized");
        return NULL;
    }
    return session_key;
}

//Calculate checksum
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

// Verify message checksum
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

//Prepare message
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

//Special for Client
#ifdef IS_CLIENT
void handle_key_rotation(Message* msg) {
    char log_buffer[256];
    
    if (!msg) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Key rotation failed - null message");
        return;
    }
    
    if (msg->type != KEY_ROTATION) {
        snprintf(log_buffer, sizeof(log_buffer), 
            "SEC: Key rotation failed - wrong message type: %d", msg->type);
        LOG_MESSAGE(LOG_ERROR, log_buffer);
        return;
    }
    
    // Debug the received message
    snprintf(log_buffer, sizeof(log_buffer), 
        "SEC: Processing key rotation message: length=%d, checksum=%u", 
        msg->length, msg->checksum);
    LOG_MESSAGE(LOG_DEBUG, log_buffer);
    
    // Check if the message contains a key of proper length
    if (msg->length != SECURITY_KEY_LENGTH) {
        snprintf(log_buffer, sizeof(log_buffer), 
            "SEC: Key rotation failed - invalid key length: %d, expected: %d", 
            msg->length, SECURITY_KEY_LENGTH);
        LOG_MESSAGE(LOG_ERROR, log_buffer);
        
        // TEMPORARY WORKAROUND: If length is 0 but data contains valid key,
        // try to process it anyway (may happen due to encryption issues)
        if (msg->length == 0) {
            size_t data_len = strnlen(msg->data, MAX_MESSAGE_LENGTH);
            if (data_len >= SECURITY_KEY_LENGTH) {
                LOG_MESSAGE(LOG_WARNING, "SEC: Attempting key rotation recovery with length 0");
                msg->length = SECURITY_KEY_LENGTH;
            } else {
                return;
            }
        } else {
            return;
        }
    }
    
    // Copy the new key ensuring null termination
    memset(session_key, 0, sizeof(session_key));
    memcpy(session_key, msg->data, SECURITY_KEY_LENGTH);
    session_key[SECURITY_KEY_LENGTH] = '\0';
    
    // Log the key rotation (only log a portion of the key for security)
    char masked_key[10] = {0};
    if (SECURITY_KEY_LENGTH > 6) {
        strncpy(masked_key, session_key, 3);
        strcat(masked_key, "...");
    }
    
    snprintf(log_buffer, sizeof(log_buffer), 
        "SEC: Key rotation complete. New key starts with: %s", masked_key);
    LOG_MESSAGE(LOG_INFO, log_buffer);
}

//Request key rotation
bool request_key_rotation(void) {
    if (!is_security_initialized) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Cannot request key rotation");
        return false;
    }

    Message key_request = {0};
    key_request.type = KEY_ROTATION_REQUEST;
    key_request.length = 0;
    prepare_message(&key_request);
    
    LOG_MESSAGE(LOG_INFO, "SEC: Key rotation requested to the server.");
    return send_message_to_server(&key_request);
}

#else
//Rotate session key
Message* rotate_session_key(void) {
    char log_buffer[256];
    
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
    
    // Copy the key into the message data
    memcpy(key_rotation->data, new_key, SECURITY_KEY_LENGTH);
    key_rotation->length = SECURITY_KEY_LENGTH;
    
    // DEBUG: Log the message structure before preparation
    snprintf(log_buffer, sizeof(log_buffer), 
        "SEC: Key rotation message created with length %d", key_rotation->length);
    LOG_MESSAGE(LOG_DEBUG, log_buffer);
    
    // Explicitly set checksum, but don't call prepare_message as it might interfere
    key_rotation->checksum = calculate_checksum(key_rotation->data, key_rotation->length);
    
    // Update session key ensuring null termination
    strncpy(session_key, new_key, SECURITY_KEY_LENGTH);
    session_key[SECURITY_KEY_LENGTH] = '\0';
    
    // Only log a masked version of the key
    char masked_key[10] = {0};
    if (SECURITY_KEY_LENGTH > 6) {
        strncpy(masked_key, new_key, 3);
        strcat(masked_key, "...");
    }
    
    snprintf(log_buffer, sizeof(log_buffer), 
        "SEC: Key rotation prepared. New key starts with: %s", masked_key);
    LOG_MESSAGE(LOG_INFO, log_buffer);
    
    return key_rotation;
}

// Add a function to send key rotation messages directly to clients
void send_key_rotation_to_client(int client_socket) {
    Message* key_msg = rotate_session_key();
    if (!key_msg) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Failed to create key rotation message");
        return;
    }
    
    // Log the message we're about to send
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer), 
        "SEC: Sending key rotation message, type: %d, length: %d, checksum: %u", 
        key_msg->type, key_msg->length, key_msg->checksum);
    LOG_MESSAGE(LOG_DEBUG, log_buffer);
    
    // Don't encrypt the key rotation message - it needs to be sent in plaintext 
    // since the client won't have the new key yet
    
    if (send(client_socket, (char*)key_msg, sizeof(Message), 0) != sizeof(Message)) {
        LOG_MESSAGE(LOG_ERROR, "SEC: Failed to send key rotation message");
    } else {
        LOG_MESSAGE(LOG_INFO, "SEC: Key rotation message sent successfully");
    }
    
    free(key_msg);
}
#endif