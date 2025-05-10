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

// Run the heartbeat receive thread
DWORD WINAPI network_receive_thread(LPVOID lpParam) {
    char log_buffer[256];
    ClientSession* session = get_current_session();
    if (!session) return 1;

    log_client_message(LOG_INFO, "NET: Receive thread started");

    Message msg;
    while (isConnected) {
        memset(&msg, 0, sizeof(Message));
        
        int bytesReceived = recv(session->socket, (char*)&msg, sizeof(Message), 0);
        if (bytesReceived <= 0) {
            isConnected = false;
            log_client_message(LOG_ERROR, "NET: Connection lost");
            break;
        }

        snprintf(log_buffer, sizeof(log_buffer), 
            "NET: Received message type %d, size %d bytes", 
            msg.type, bytesReceived);
        log_client_message(LOG_DEBUG, log_buffer);

        if (msg.type != HEARTBEAT) {
            decrypt_message(&msg, get_session_key());
        }

        switch (msg.type) {
            case HEARTBEAT:
                log_client_message(LOG_DEBUG, "NET: Received heartbeat response");
                break;

            case LOGIN_RESPONSE:
                handle_login_response(&msg);
                break;
                
            case SEND_MESSAGE_RESPONSE:
                handle_message_response(&msg);
                break;
                
            case FETCH_MESSAGES_RESPONSE:
                handle_fetch_messages_response(&msg);
                break;
                
            case USER_STATUS_UPDATE:
                {
                    char username[256];
                    bool is_online;
                    sscanf(msg.data, "%[^:]:%d", username, &is_online);
                    on_user_status_changed(username, is_online);
                }
                break;

            case DISCONNECT_RESPONSE:
                handle_disconnect_response(&msg);
                break;

            case REGISTER_RESPONSE:
                handle_register_response(&msg);
                break;

            default:
                snprintf(log_buffer, sizeof(log_buffer), 
                    "NET: Unknown message type received: %d", msg.type);
                log_client_message(LOG_WARNING, log_buffer);
                break;
        }
    }

    log_client_message(LOG_INFO, "NET: Receive thread terminated");
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

        Sleep(15000);  // 15 sec for test instead of 30 sec TODO: change when test phase are over

        if (!isConnected) {
            log_client_message(LOG_INFO, "HB: Connection closed, stopping heartbeat");
            break;
        }

        snprintf(log_buffer, sizeof(log_buffer), 
            "HB: Preparing heartbeat at %ld", (long)time(NULL));
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
