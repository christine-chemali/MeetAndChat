#include "network/session/ClientSession.h"
#include "network/core/MessageSender.h"
#include "network/core/NetworkThread.h"
#include "network/core/NetworkCore.h"
#include "network/core/SessionManager.h"
#include "network/handlers/LoginMessageHandler.h"
#include "network/handlers/CreateAccountHandler.h"
#include "network/handlers/MainAppHandler.h"
#include "network/log/ClientLogging.h"
#include "callbacks/GuiCallbacks.h"
#include "security/NetworkSecurity.h"
#include <glib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

HANDLE networkThread = NULL;
HANDLE heartbeatThread = NULL;


static volatile bool networkThreadRunning = false;
static volatile bool heartbeatThreadRunning = false;

//Receiving message process
void process_received_message(Message* msg) {
    char log_buffer[256];
    
    if (!msg) {
        log_client_message(LOG_ERROR, "NET: Null message received");
        return;
    } 

    snprintf(log_buffer, sizeof(log_buffer), 
            "NET: Received message type %d, size %d bytes", 
            msg->type, msg->length);
    log_client_message(LOG_DEBUG, log_buffer);
    
    // Decrypt with actual key
    decrypt_message(msg, get_session_key());
    
    // Verifying type of the message and act in consequence
    switch (msg->type) {
        case HEARTBEAT:
            log_client_message(LOG_DEBUG, "NET: Received heartbeat response");
            break;

        case LOGIN_RESPONSE:
            handle_login_response(msg);
            break;
                
        case SEND_MESSAGE_RESPONSE:
            handle_message_response(msg);
            break;
                
        case FETCH_MESSAGES_RESPONSE:
            handle_fetch_messages_response(msg);
            break;
                
        case USER_STATUS_UPDATE:
            {
                char username[256];
                bool is_online;
                if (sscanf(msg->data, "%[^:]:%d", username, &is_online) == 2) {
                    on_user_status_changed(username, is_online);
                }
            }
            break;

        case DISCONNECT_RESPONSE:
            handle_disconnect_response(msg);
            break;

        case REGISTER_RESPONSE:
            handle_register_response(msg);
            break;

        case KEY_ROTATION:
            snprintf(log_buffer, sizeof(log_buffer), 
                "NET: Received key rotation message, length: %d", msg->length);
            log_client_message(LOG_INFO, log_buffer);
            handle_key_rotation(msg);
            log_client_message(LOG_INFO, "NET: Key rotation message processed.");
            break;

        default:
            snprintf(log_buffer, sizeof(log_buffer), 
                "NET: Unknown message type received: %d", msg->type);
            log_client_message(LOG_WARNING, log_buffer);
            break;
    }
}

// Network receive Thread 
DWORD WINAPI network_receive_thread(LPVOID lpParam) {
    char log_buffer[256];
    Message received_message;
    int recv_result;
    ClientSession* session;
    
    log_client_message(LOG_INFO, "Starting network receive thread");
    networkThreadRunning = true;
    
    while (networkThreadRunning && isConnected) {
        // Verify if session is still valid
        session = get_current_session();
        if (!session || !is_session_valid_initial(session)) {
            log_client_message(LOG_ERROR, "Invalid session in network thread");
            break;
        }
        
        // Re init message struct
        memset(&received_message, 0, sizeof(Message));
        
        // Receive message
        recv_result = recv(session->socket, (char*)&received_message, sizeof(Message), 0);
        
        if (recv_result == SOCKET_ERROR) {
            int error_code = WSAGetLastError();
            
            // Ignore timeout errors
            if (error_code == WSAETIMEDOUT) {
                continue;
            }
            
            // Handle connection errors
            if (error_code == WSAECONNRESET || error_code == WSAECONNABORTED) {
                log_client_message(LOG_WARNING, "Connection closed by server");
                break;
            }
            
            snprintf(log_buffer, sizeof(log_buffer), 
                    "Socket error in receive thread: %d", error_code);
            log_client_message(LOG_ERROR, log_buffer);
            break;
        }
        
        if (recv_result == 0) {
            log_client_message(LOG_WARNING, "Connection closed gracefully by server");
            break;
        }
        
        if (recv_result != sizeof(Message)) {
            snprintf(log_buffer, sizeof(log_buffer), 
                    "Incomplete message received: %d bytes instead of %zu", 
                    recv_result, sizeof(Message));
            log_client_message(LOG_WARNING, log_buffer);
            continue;
        }
        
        process_received_message(&received_message);
    }
    
    if (isConnected) {
        log_client_message(LOG_ERROR, "Network thread terminated unexpectedly");
        handle_network_error();
    } else {
        log_client_message(LOG_INFO, "Network thread terminated normally");
    }
    
    networkThreadRunning = false;
    return 0;
}


//Run the heatbeat thread
DWORD WINAPI heartbeat_thread(LPVOID lpParam) {
    char log_buffer[256];
    ClientSession* session = get_current_session();
    if (!session) {
        log_client_message(LOG_ERROR, "HB: Invalid session in heartbeat thread");
        return 1;
    }

    log_client_message(LOG_INFO, "HB: Heartbeat thread started");
    
    Message heartbeat;
    memset(&heartbeat, 0, sizeof(Message));
    heartbeat.type = HEARTBEAT;
    heartbeat.length = 0;
    heartbeat.checksum = 0;
    
    log_client_message(LOG_DEBUG, "HB: Sending initial heartbeat");
    if (!send_message_to_server(&heartbeat)) {
        log_client_message(LOG_ERROR, "HB: Failed to send initial heartbeat");
        handle_network_error();
        return 1;
    }

    while (isConnected) {

        Sleep(15000);  // 15 sec 

        if (!isConnected) {
            log_client_message(LOG_INFO, "HB: Connection closed, stopping heartbeat");
            break;
        }

        time_t t = time(NULL);
        struct tm* tm_info = localtime(&t);
        snprintf(log_buffer, sizeof(log_buffer), 
            "HB: Preparing heartbeat at %02d:%02d:%02d", tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
        log_client_message(LOG_DEBUG, log_buffer);

        memset(&heartbeat, 0, sizeof(Message));
        heartbeat.type = HEARTBEAT;
        heartbeat.length = 0;
        heartbeat.checksum = 0;
        
        if (!check_connection_status()) {
            log_client_message(LOG_ERROR, "HB: Connection check failed before send");
            break;
        }
        
        log_client_message(LOG_DEBUG, "HB: Attempting to send heartbeat");
        if (!send_message_to_server(&heartbeat)) {
            log_client_message(LOG_ERROR, "HB: Failed to send heartbeat");
            handle_network_error();
            break;
        }

        log_client_message(LOG_DEBUG, "HB: Heartbeat sent successfully");
    }

    log_client_message(LOG_INFO, "HB: Heartbeat thread terminated");
    return 0;
}

// Stop network threads
void stop_network_threads(void) {
    networkThreadRunning = false;
    heartbeatThreadRunning = false;
}