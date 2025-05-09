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
    ClientSession* session = get_current_session();
    if (!session) return 1;

    Message msg;
    while (isConnected) {
        int bytesReceived = recv(session->socket, (char*)&msg, sizeof(Message), 0);
        if (bytesReceived <= 0) {
            isConnected = false;
            log_client_message(LOG_ERROR, "Connection lost");
            break;
        }

        decrypt_message(&msg, get_session_key());

        switch (msg.type) {
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
                printf("Unknown message type received: %d\n", msg.type);
                break;
        }
    }
    return 0;
}

// Run the heartbeat thread
DWORD WINAPI heartbeat_thread(LPVOID lpParam) {
    ClientSession* session = get_current_session();
    if (!session) return 1;

    Message heartbeat;
    while (isConnected) {
        Sleep(HEARTBEAT_INTERVAL * 1000);

        memset(&heartbeat, 0, sizeof(Message));
        heartbeat.type = HEARTBEAT;
        heartbeat.length = 0;
        
        if (!send_message_to_server(&heartbeat)) {
            log_client_message(LOG_ERROR, "Failed to send heartbeat");
            handle_network_error();
            break;
        }
    }
    return 0;
}