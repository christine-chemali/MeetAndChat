#include "servernetwork/messageHandler.h"
#include "servernetwork/login/LoginHandler.h"
#include "security/NetworkSecurity.h"
#include "servernetwork/ServerSession.h"
#include "serverlogging/ServerLogging.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN_MESSAGE_LENGTH 0
#define MAX_MESSAGE_LENGTH 1024

static bool security_initialized = false;

// To validate message lenght
static bool validate_message_length(int length) {
    return (length >= MIN_MESSAGE_LENGTH && length <= MAX_MESSAGE_LENGTH);
}

// Receives message 
Message* receive_message(SOCKET socket) {
    if (socket == INVALID_SOCKET) {
        log_server_message(LOG_ERROR, "Invalid socket provided");
        return NULL;
    }

    Message* msg = malloc(sizeof(Message));
    if (!msg) {
        log_server_message(LOG_ERROR, "Failed to allocate memory for message");
        return NULL;
    }
    memset(msg, 0, sizeof(Message));

    // receiving the complete message
    int total_received = 0;
    int remaining = sizeof(Message);
    char* buffer = (char*)msg;

    while (total_received < remaining) {
        int received = recv(socket, buffer + total_received, remaining - total_received, 0);
        if (received <= 0) {
            int error = WSAGetLastError();
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "Connection lost during receive. Error: %d", error);
            log_server_message(LOG_ERROR, error_msg);
            free(msg);
            return NULL;
        }
        total_received += received;
    }

    // Special treatment for the heartbeat
    if (msg->type == HEARTBEAT) {
        log_server_message(LOG_DEBUG, "Received heartbeat message");
        return msg;
    }

    // Validate lenght before decrypting
    if (!validate_message_length(msg->length)) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Invalid message length received: %d", msg->length);
        log_server_message(LOG_ERROR, error_msg);
        free(msg);
        return NULL;
    }

    // decrypting message
    decrypt_message(msg, get_session_key());

    // Vérify checksum after decrypting
    if (msg->length > 0) {
        unsigned int calculated_checksum = calculate_checksum(msg->data, msg->length);
        if (calculated_checksum != msg->checksum) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), 
                     "Checksum mismatch. Expected: %u, Got: %u", 
                     msg->checksum, calculated_checksum);
            log_server_message(LOG_ERROR, error_msg);
            free(msg);
            return NULL;
        }
    }

    return msg;
}

// Frees a message's allocated memory
void free_message(Message* msg) {
    if (msg) free(msg);
}

// Send message to client
bool send_message_to_client(ClientSession* session, Message* msg) {
    if (!msg || !session) return false;

    Message send_msg;
    memset(&send_msg, 0, sizeof(Message));
    memcpy(&send_msg, msg, sizeof(Message));

    // special treatment for heartbeat no cheksum
    if (send_msg.type == HEARTBEAT) {
        send_msg.length = 0;
        send_msg.checksum = 0;  
    } else {
        send_msg.checksum = calculate_checksum(send_msg.data, send_msg.length);
    }

    encrypt_message(&send_msg, get_session_key());

    int total_size = sizeof(Message);
    int sent = send(session->clientSocket, (char*)&send_msg, total_size, 0);
    
    return (sent == total_size);
}

// Create heartbeat message
Message* create_heartbeat_message() {
    Message* msg = malloc(sizeof(Message));
    if (!msg) return NULL;
    
    msg->length = 0;
    msg->type = HEARTBEAT;
    msg->checksum = calculate_checksum(msg->data, msg->length);
    
    return msg;
}

// Processes a client message based on its type
void handle_client_message(ClientSession* session, Message* msg) {
    if (!msg || !session) {
        log_server_message(LOG_ERROR, "Null message or session");
        return;
    }

    // Special treatment for heatbeat had to be before verifiying lenght and checksum
    if (msg->type == HEARTBEAT) {
        Message response;
        memset(&response, 0, sizeof(Message));
        response.type = HEARTBEAT;
        response.length = 0;
        response.checksum = 0;
        
        if (!send_message_to_client(session, &response)) {
            log_server_message(LOG_ERROR, "Failed to send heartbeat response");
        }
        return;
    }

    // Switch
    switch(msg->type) {
        case LOGIN_REQUEST: {
            log_server_message(LOG_INFO, "Processing login request");
            handle_login_request(session, msg);
            break;
        }
           
        case LOGOUT: {
            log_server_message(LOG_INFO, "Processing logout request");
            handle_logout_request(session);
            break;
        }
    
        case HEARTBEAT: {
            // TODO : ADD CODE FOR HEARTBEAT
            break;
        }
    
        default: {
            char unknown_msg[256];
            snprintf(unknown_msg, sizeof(unknown_msg), 
                    "Unknown message type received: %d from %s", 
                    msg->type,
                    session->username ? session->username : "unknown");
            log_server_message(LOG_WARNING, unknown_msg);
        }
    }
    // Update activity timestamp
    session->lastActivity = time(NULL);
} 