#include "network/session/ClientSession.h"
#include "network/core/MessageSender.h"
#include "network/core/NetworkCore.h"
#include "network/core/SessionManager.h"
#include "network/log/ClientLogging.h"
#include "security/NetworkSecurity.h"
#include <string.h>
#include <stdio.h>

// Send a message to the server
bool send_message_to_server(Message* msg) {
    char log_buffer[256];
    static const size_t expected_size = sizeof(int) * 3 + MAX_MESSAGE_LENGTH;
    
    if (sizeof(Message) != expected_size) {
        snprintf(log_buffer, sizeof(log_buffer), 
            "SND: WARNING - Message structure size mismatch (actual: %zu, expected: %zu)", 
            sizeof(Message), expected_size);
        log_client_message(LOG_WARNING, log_buffer);
    }
    
    if (!check_connection_status()) {
        log_client_message(LOG_ERROR, "SND: Connection check failed");
        return false;
    }

    ClientSession* session = get_current_session();
    if (!msg || !session) {
        log_client_message(LOG_ERROR, "SND: Invalid message or session");
        return false;
    }

    snprintf(log_buffer, sizeof(log_buffer), 
        "SND: Preparing to send message type %d (struct size: %zu)", 
        msg->type, sizeof(Message));
    log_client_message(LOG_DEBUG, log_buffer);

    // Create a copy of the message
    Message send_msg;
    memset(&send_msg, 0, sizeof(Message));
    memcpy(&send_msg, msg, sizeof(Message));

    // Handeling different type of messages
    if (send_msg.type == HEARTBEAT) {
        send_msg.length = 0;
        send_msg.checksum = 0;
        memset(send_msg.data, 0, MAX_MESSAGE_LENGTH);
        
        snprintf(log_buffer, sizeof(log_buffer), 
            "SND: Sending heartbeat (message size: %zu)", sizeof(Message));
        log_client_message(LOG_DEBUG, log_buffer);
    } else {
        // Calculate checksum before encryption
        prepare_message(&send_msg);
        
        snprintf(log_buffer, sizeof(log_buffer), 
            "SND: Message prepared with checksum: %u", send_msg.checksum);
        log_client_message(LOG_DEBUG, log_buffer);
        
        encrypt_message(&send_msg, get_session_key());
    }

    // Send message
    size_t message_size = sizeof(Message);
    int total_sent = 0;
    char* buffer = (char*)&send_msg;

    while (total_sent < message_size && isConnected) {
        int to_send = (int)(message_size - total_sent);
        int sent = send(session->socket, buffer + total_sent, to_send, 0);
        
        if (sent <= 0) {
            int error = WSAGetLastError();
            snprintf(log_buffer, sizeof(log_buffer), 
                "SND: Send failed (type: %d, error: %d)", 
                send_msg.type, error);
            log_client_message(LOG_ERROR, log_buffer);
            return false;
        }
        total_sent += sent;
    }

    // Verify if the sending is complete
    if (total_sent != message_size) {
        snprintf(log_buffer, sizeof(log_buffer), 
            "SND: Incomplete send - only %d of %zu bytes sent", 
            total_sent, message_size);
        log_client_message(LOG_ERROR, log_buffer);
        return false;
    }

    snprintf(log_buffer, sizeof(log_buffer), 
        "SND: Message sent successfully (type: %d, bytes: %d)", 
        send_msg.type, total_sent);
    log_client_message(LOG_DEBUG, log_buffer);

    return true;
}

// Sending a generic message prototype
bool send_generic_message(int type, const char* data, size_t length) {
    Message msg;
    char log_buffer[256];
    memset(&msg, 0, sizeof(Message));
    msg.type = type;
   
    // Log begining of the sending
    snprintf(log_buffer, sizeof(log_buffer), "Beginning to send a message of type %d", type);
    log_client_message(LOG_INFO, log_buffer);
   
    // Verifying if data is sent
    if (data && length > 0) {

        snprintf(log_buffer, sizeof(log_buffer), "Preparing a message with %zu bytes of data", length);
        log_client_message(LOG_DEBUG, log_buffer);
       
        // Verify data size
        if (length > sizeof(msg.data)) {
            snprintf(log_buffer, sizeof(log_buffer), 
                "ERROR: Message size (%zu) exceeds maximum capacity (%zu)", 
                length, sizeof(msg.data));
            log_client_message(LOG_ERROR, log_buffer);
            return false;
        }
        
        // Copying data message
        memcpy(msg.data, data, length);
        msg.length = length;
        
        // Logging first bytes: may not be relevant for confidentiality 
        if (length <= 16) {

            char hex_dump[48] = {0};
            for (size_t i = 0; i < length && i < 16; i++) {
                sprintf(hex_dump + i*3, "%02X ", (unsigned char)data[i]);
            }
            snprintf(log_buffer, sizeof(log_buffer), "Message content: %s", hex_dump);
            log_client_message(LOG_DEBUG, log_buffer);
        } else {

            char hex_dump[48] = {0};
            for (size_t i = 0; i < 8; i++) {
                sprintf(hex_dump + i*3, "%02X ", (unsigned char)data[i]);
            }
            snprintf(log_buffer, sizeof(log_buffer), 
                "Start of message: %s... (%zu bytes total)", hex_dump, length);
            log_client_message(LOG_DEBUG, log_buffer);
        }
    } else {

        log_client_message(LOG_DEBUG, "Sending a message without data");
    }
   
    // Register time 
    time_t start_time = time(NULL);
    
    // Sending to server
    log_client_message(LOG_DEBUG, "Attempting to send the message...");
    bool result = send_message_to_server(&msg);
    
    // Calculate time of the sending
    time_t end_time = time(NULL);
    double elapsed_time = difftime(end_time, start_time);
   
    // result of the sending
    if (result) {
        snprintf(log_buffer, sizeof(log_buffer), 
            "Message of type %d sent successfully in %.1f seconds", type, elapsed_time);
        log_client_message(LOG_INFO, log_buffer);
    } else {
        snprintf(log_buffer, sizeof(log_buffer), 
            "FAILURE to send message of type %d after %.1f seconds", type, elapsed_time);
        log_client_message(LOG_ERROR, log_buffer);
    }
   
    return result;
}