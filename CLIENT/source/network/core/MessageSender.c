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
    if (!check_connection_status()) {
        log_client_message(LOG_ERROR, "Connection check failed");
        return false;
    }

    ClientSession* session = get_current_session();
    if (!msg || !session) {
        log_client_message(LOG_ERROR, "Invalid message or session");
        return false;
    }

    if (session->socket == INVALID_SOCKET) {
        log_client_message(LOG_ERROR, "Invalid socket in session");
        return false;
    }

    // Create a copy of the message to send it 
    Message send_msg;
    memset(&send_msg, 0, sizeof(Message));

    // Special treatment for heartbeat
    if (msg->type == HEARTBEAT) {
        send_msg.type = HEARTBEAT;
        send_msg.length = 0;
        send_msg.checksum = 0;
        
        char log_msg[64];
        snprintf(log_msg, sizeof(log_msg), "Sending heartbeat message");
        log_client_message(LOG_DEBUG, log_msg);

        int total_sent = 0;
        int remaining = sizeof(Message);
        char* buffer = (char*)&send_msg;

        while (total_sent < remaining) {
            int sent = send(session->socket, buffer + total_sent, remaining - total_sent, 0);
            if (sent <= 0) {
                int error = WSAGetLastError();
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "Heartbeat send failed with error: %d", error);
                log_client_message(LOG_ERROR, error_msg);
                return false;
            }
            total_sent += sent;
        }

        return true;
    }

    //For all others message types
    if (msg->length > MAX_MESSAGE_LENGTH || msg->length < 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Invalid message length: %d", msg->length);
        log_client_message(LOG_ERROR, error_msg);
        return false;
    }

    // Copy and prepare message
    memcpy(&send_msg, msg, sizeof(Message));
    
    // Log befor encryption
    char msg_info[256];
    snprintf(msg_info, sizeof(msg_info), "Preparing to send message - Type: %d, Length: %d", 
             send_msg.type, send_msg.length);
    log_client_message(LOG_INFO, msg_info);

    // Calculate checksum before encryption
    if (send_msg.length > 0) {
        send_msg.checksum = calculate_checksum(send_msg.data, send_msg.length);
    }

    // Encryption 
    encrypt_message(&send_msg, get_session_key());

    // Send message
    int total_sent = 0;
    int remaining = sizeof(Message);
    char* buffer = (char*)&send_msg;

    while (total_sent < remaining) {
        int sent = send(session->socket, buffer + total_sent, remaining - total_sent, 0);
        if (sent <= 0) {
            int error = WSAGetLastError();
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "Message send failed with error: %d", error);
            log_client_message(LOG_ERROR, error_msg);
            
            // Decrypt message for login
            decrypt_message(&send_msg, get_session_key());
            return false;
        }
        total_sent += sent;
    }

    // Log after a successful sending message
    snprintf(msg_info, sizeof(msg_info), "Message sent successfully - Type: %d, Bytes sent: %d", 
             send_msg.type, total_sent);
    log_client_message(LOG_INFO, msg_info);

    return true;
}

//Send generic message :TODO implement in all files where it is needed
bool send_generic_message(int type, const char* data, size_t length) {
    Message msg;
    char log_buffer[256];
    memset(&msg, 0, sizeof(Message));
    msg.type = type;
   
    // Log the beginning of the function with the message type
    snprintf(log_buffer, sizeof(log_buffer), "Beginning to send a message of type %d", type);
    log_client_message(LOG_INFO, log_buffer);
   
    // Check if data is provided
    if (data && length > 0) {
        // Log message details
        snprintf(log_buffer, sizeof(log_buffer), "Preparing a message with %zu bytes of data", length);
        log_client_message(LOG_DEBUG, log_buffer);
       
        // Check if the message size is acceptable
        if (length > sizeof(msg.data)) {
            snprintf(log_buffer, sizeof(log_buffer), 
                "ERROR: Message size (%zu) exceeds maximum capacity (%zu)", 
                length, sizeof(msg.data));
            log_client_message(LOG_ERROR, log_buffer);
            return false;
        }
        
        // Copy data into the message
        memcpy(msg.data, data, length);
        msg.length = length;
        
        // Log the content of the message (first bytes if large)
        if (length <= 16) {
            // For small messages, we can display the entire content
            char hex_dump[48] = {0};
            for (size_t i = 0; i < length && i < 16; i++) {
                sprintf(hex_dump + i*3, "%02X ", (unsigned char)data[i]);
            }
            snprintf(log_buffer, sizeof(log_buffer), "Message content: %s", hex_dump);
            log_client_message(LOG_DEBUG, log_buffer);
        } else {
            // For large messages, we just display the first bytes
            char hex_dump[48] = {0};
            for (size_t i = 0; i < 8; i++) {
                sprintf(hex_dump + i*3, "%02X ", (unsigned char)data[i]);
            }
            snprintf(log_buffer, sizeof(log_buffer), 
                "Start of message: %s... (%zu bytes total)", hex_dump, length);
            log_client_message(LOG_DEBUG, log_buffer);
        }
    } else {
        // Log that this is a message without data
        log_client_message(LOG_DEBUG, "Sending a message without data");
    }
   
    // Record the start time of sending
    time_t start_time = time(NULL);
    
    // Send the message to the server
    log_client_message(LOG_DEBUG, "Attempting to send the message...");
    bool result = send_message_to_server(&msg);
    
    // Calculate the sending time
    time_t end_time = time(NULL);
    double elapsed_time = difftime(end_time, start_time);
   
    // Log the result of the sending
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