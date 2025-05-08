#include "servernetwork/messageHandler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Receives a message from a socket
Message* receive_message(SOCKET socket) {
    Message* msg = malloc(sizeof(Message));
    if (!msg) return NULL;

    int received = recv(socket, (char*)msg, sizeof(Message), 0);
    if (received <= 0) {
        free(msg);
        return NULL;
    }

    decrypt_message(msg, get_session_key());
    if (!verify_message_checksum(msg)) {
        free(msg);
        return NULL;
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

    msg->checksum = calculate_checksum(msg->data, msg->length);
    encrypt_message(msg, get_session_key());
    
    int result = send(session->clientSocket, (char*)msg, sizeof(Message), 0);
    decrypt_message(msg, get_session_key());
    
    return result > 0;
}

// Processes a client message based on its type
void handle_client_message(ClientSession* session, Message* msg) {
    if (!msg || !session) return;

    switch(msg->type) {
        case LOGIN_REQUEST:
            handle_login_request(session, msg);
            break;
            
        case LOGOUT:
            handle_logout_request(session);
            break;
            
        case HEARTBEAT:
            // Traiter le heartbeat
            break;
            
        default:
            if (!session->isAuthenticated) {
                printf("Unauthorized message type: %d\n", msg->type);
                return;
            }
            
            switch(msg->type) {
                case SEND_MESSAGE:
                    // handle_chat_message(session, msg);
                    break;
                    
                case KEY_ROTATION:
                    // handle_key_rotation(session, msg);
                    break;
                    
                case RECONNECT_REQUEST:
                    // handle_reconnect_request(session, msg);
                    break;
                    
                default:
                    printf("Unknown message type: %d\n", msg->type);
            }
    }
}