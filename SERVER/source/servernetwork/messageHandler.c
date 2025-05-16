#include "servernetwork/messageHandler.h"
#include "servernetwork/login/LoginHandler.h"
#include "security/NetworkSecurity.h"
#include "servernetwork/ServerSession.h"
#include "servernetwork/login/RegisterHandler.h"
#include "serverlogging/ServerLogging.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN_MESSAGE_LENGTH 0
#define MAX_MESSAGE_LENGTH 1024

static bool security_initialized = false;


// To validate message lenght
static bool validate_message_length(int length, int message_type) {

    if (message_type == HEARTBEAT) {
        return length == 0;
    }

    return (length >= MIN_MESSAGE_LENGTH && length <= MAX_MESSAGE_LENGTH);
}

// Frees a message's allocated memory
void free_message(Message* msg) {
    if (msg) free(msg);
}

// Receives message 
Message* receive_message(SOCKET socket) {
    char log_buffer[256];
    
    if (socket == INVALID_SOCKET) {
        log_server_message(LOG_ERROR, "RCV: Invalid socket provided");
        return NULL;
    }

    Message* msg = malloc(sizeof(Message));
    if (!msg) {
        log_server_message(LOG_ERROR, "RCV: Memory allocation failed");
        return NULL;
    }
    memset(msg, 0, sizeof(Message));

    // Receiving the complete message
    int total_received = 0;
    int remaining = sizeof(Message);
    char* buffer = (char*)msg;

    while (total_received < remaining) {
        int received = recv(socket, buffer + total_received, remaining - total_received, 0);
        if (received <= 0) {
            int error = WSAGetLastError();
            snprintf(log_buffer, sizeof(log_buffer), "RCV: Connection lost. Error: %d", error);
            log_server_message(LOG_ERROR, log_buffer);
            free(msg);
            return NULL;
        }
        total_received += received;
    }

    // Validate message length before decryption
    if (!validate_message_length(msg->length, msg->type)) {
        snprintf(log_buffer, sizeof(log_buffer), 
            "RCV: Invalid length %d for message type %d", 
            msg->length, msg->type);
        log_server_message(LOG_ERROR, log_buffer);
        free(msg);
        return NULL;
    }

    // Decrypt and verify checksum for non-heartbeat messages
    if (msg->type != HEARTBEAT) {
        decrypt_message(msg, get_session_key());
    }

    return msg;
}

//Create heartbeat message
Message* create_heartbeat_message() {
    char log_buffer[256];
    
    Message* msg = malloc(sizeof(Message));
    if (!msg) {
        log_server_message(LOG_ERROR, "HB: Failed to allocate heartbeat message");
        return NULL;
    }
    
    memset(msg, 0, sizeof(Message));
    msg->type = HEARTBEAT;
    msg->length = 0;
    msg->checksum = 0;  
    
    snprintf(log_buffer, sizeof(log_buffer), 
        "HB: Created heartbeat message (type: %d, length: %d, checksum: %u)", 
        msg->type, msg->length, msg->checksum);
    log_server_message(LOG_DEBUG, log_buffer);
    
    return msg;
}

// Send message to client
bool send_message_to_client(ClientSession* session, Message* msg) {
    char log_buffer[256];
    if (!msg || !session) {
        log_server_message(LOG_ERROR, "SND: Null message or session");
        return false;
    }

    Message send_msg;
    memset(&send_msg, 0, sizeof(Message));
    memcpy(&send_msg, msg, sizeof(Message));
    
    snprintf(log_buffer, sizeof(log_buffer), "SND: Preparing message type %d, length %d", 
        send_msg.type, send_msg.length);
    log_server_message(LOG_DEBUG, log_buffer);

    prepare_message(&send_msg);
    
    if (send_msg.length > 0) {
        char hex_dump[48] = {0};
        for (size_t i = 0; i < (send_msg.length > 8 ? 8 : send_msg.length); i++) {
            sprintf(hex_dump + i*3, "%02X ", (unsigned char)send_msg.data[i]);
        }
        snprintf(log_buffer, sizeof(log_buffer), "SND: Data preview: %s%s", 
            hex_dump, send_msg.length > 8 ? "..." : "");
        log_server_message(LOG_DEBUG, log_buffer);
    }

    //encrypt message
    encrypt_message(&send_msg, get_session_key());

    time_t start_time = time(NULL);
    int total_size = sizeof(Message);
    int sent = send(session->clientSocket, (char*)&send_msg, total_size, 0);
    
    time_t end_time = time(NULL);
    double elapsed_time = difftime(end_time, start_time);

    if (sent == total_size) {
        snprintf(log_buffer, sizeof(log_buffer), 
            "SND: Message sent successfully in %.1f seconds", elapsed_time);
        log_server_message(LOG_INFO, log_buffer);
        return true;
    } else {
        snprintf(log_buffer, sizeof(log_buffer), 
            "SND: Failed to send message after %.1f seconds", elapsed_time);
        log_server_message(LOG_ERROR, log_buffer);
        return false;
    }
}

// Processes a client message based on its type
void handle_client_message(ClientSession* session, Message* msg) {
    char log_buffer[256];
    
    if (!msg || !session) {
        log_server_message(LOG_ERROR, "MSG: Null message or session");
        return;
    }

    // Calculate idle before update 
    time_t current_time = time(NULL);
    time_t idle_time = current_time - session->lastActivity;
    
    snprintf(log_buffer, sizeof(log_buffer), 
        "MSG: Processing message type %d from socket %d (idle: %02d:%02d:%02d)", 
        msg->type,
        (int)session->clientSocket,
        (int)(idle_time/3600), (int)((idle_time%3600)/60), (int)(idle_time%60));
    log_server_message(LOG_DEBUG, log_buffer);

    //switch
    switch(msg->type) {
        case LOGIN_REQUEST: {
            snprintf(log_buffer, sizeof(log_buffer), 
                "MSG: Login attempt from socket %d", 
                (int)session->clientSocket);
            log_server_message(LOG_INFO, log_buffer);
            handle_login_request(session, msg);
            break;
        }

    case LOGOUT_REQUEST: {
        snprintf(log_buffer, sizeof(log_buffer), 
            "MSG: Processing disconnect request from socket %d", 
            (int)session->clientSocket);
        log_server_message(LOG_INFO, log_buffer);
        break;  // Simplement accuser réception du message
    }
    
    case LOGOUT: {
        snprintf(log_buffer, sizeof(log_buffer), 
            "MSG: Processing logout request from socket %d", 
            (int)session->clientSocket);
        log_server_message(LOG_INFO, log_buffer);
        handle_logout_request(session);
        break;
    }

        case HEARTBEAT: {
            snprintf(log_buffer, sizeof(log_buffer), 
                "MSG: Processing heartbeat from socket %d (idle: %02d:%02d:%02d)", 
                (int)session->clientSocket,
                (int)(idle_time/3600), (int)((idle_time%3600)/60), (int)(idle_time%60));
            log_server_message(LOG_DEBUG, log_buffer);
            
            Message* response = create_heartbeat_message();
            if (!response) {
                log_server_message(LOG_ERROR, "MSG: Failed to create heartbeat response");
                break;
            }
            
            if (!send_message_to_client(session, response)) {
                log_server_message(LOG_ERROR, "MSG: Failed to send heartbeat response");
            }
            
            free(response);
            break;
        }

        case REGISTER_REQUEST: {
            snprintf(log_buffer, sizeof(log_buffer), 
                "MSG: Registration attempt from socket %d", 
                (int)session->clientSocket);
            log_server_message(LOG_INFO, log_buffer);
            handle_register_request(session, msg);
            break;
        }
        
        default: {
            snprintf(log_buffer, sizeof(log_buffer), 
                "MSG: Unknown message type %d from socket %d", 
                msg->type,
                (int)session->clientSocket);
            log_server_message(LOG_WARNING, log_buffer);
        }
    }

    // Update activity timestamp
    session->lastActivity = current_time;
    
    snprintf(log_buffer, sizeof(log_buffer), 
        "MSG: Updated activity timestamp for socket %d", 
        (int)session->clientSocket);
    log_server_message(LOG_DEBUG, log_buffer);
}