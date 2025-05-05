#include "network/handlenetwork/NetworkHandlers.h"
#include "network/log/ClientLogging.h"
#include "security/NetworkSecurity.h"
#include "callbacks/GuiCallbacks.h"
#include <glib.h>   
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

//Function prototypes for static functions 
static void handle_login_response(Message* msg);
static void handle_message_response(Message* msg);
static void handle_fetch_messages_response(Message* msg);

//Global variables for network management 
SOCKET clientSocket = INVALID_SOCKET;
bool isConnected = false;
HANDLE networkThread = NULL;
HANDLE heartbeatThread = NULL; 
char last_known_address[128] = {0};  
int last_known_port = 0;  

//Network receive thread - handles incoming messages 
static DWORD WINAPI network_receive_thread(LPVOID lpParam) {
    Message msg;
    while (isConnected) {
        int bytesReceived = recv(clientSocket, (char*)&msg, sizeof(Message), 0);
        if (bytesReceived <= 0) {
            isConnected = false;
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

            case CONVERSATION_OPENED:
                break;
                
            case KEY_ROTATION:
                break;
                
            case CONNECTION_ERROR:
                break;
                
            case HEARTBEAT:
                break;
                
            default:
                // Handle unknown message type
                printf("Unknown message type received: %d\n", msg.type);
                break;
        }
    }
    return 0;
}

//Sets socket timeout for connection monitoring 
bool set_socket_timeout(void) {
    DWORD timeout = CONNECTION_TIMEOUT * 1000;
    return setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, 
                     (char*)&timeout, sizeof(timeout)) != SOCKET_ERROR;
}

//Attempts to reconnect to the server 
bool attempt_reconnection(void) {
    if (last_known_address[0] == '\0' || last_known_port == 0) {
        log_client_message(LOG_ERROR, "No previous connection information available");
        return false;
    }

    for (int i = 0; i < MAX_RECONNECT_ATTEMPTS; i++) {
        log_client_message(LOG_INFO, "Attempting reconnection...");
        if (initialize_network(last_known_address, last_known_port)) {
            log_client_message(LOG_INFO, "Reconnection successful");
            return true;
        }
        Sleep(1000 * (i + 1));  // Increasing delay between attempts
    }
    
    log_client_message(LOG_ERROR, "Reconnection failed after maximum attempts");
    return false;
}

// Cleans up network resources 
void cleanup_network(void) {
    if (isConnected) {
        Message logout_msg;
        logout_msg.type = LOGOUT;
        logout_msg.length = 0;
        send_message_to_server(&logout_msg);
        
        isConnected = false;
        
        if (networkThread) {
            if (WaitForSingleObject(networkThread, 1000) == WAIT_TIMEOUT) {
                TerminateThread(networkThread, 0);
            }
            CloseHandle(networkThread);
            networkThread = NULL;
        }
        
        if (heartbeatThread) {
            if (WaitForSingleObject(heartbeatThread, 1000) == WAIT_TIMEOUT) {
                TerminateThread(heartbeatThread, 0);
            }
            CloseHandle(heartbeatThread);
            heartbeatThread = NULL;
        }
        
        if (clientSocket != INVALID_SOCKET) {
            closesocket(clientSocket);
            clientSocket = INVALID_SOCKET;
        }
        
        WSACleanup();
        
        memset(last_known_address, 0, sizeof(last_known_address));
        last_known_port = 0;
    }
}

//Heartbeat thread - maintains connection alive 
static DWORD WINAPI heartbeat_thread(LPVOID lpParam) {
    Message heartbeat;
    heartbeat.type = HEARTBEAT;
    heartbeat.length = 0;

    while (isConnected) {
        Sleep(HEARTBEAT_INTERVAL * 1000);
        if (!send_message_to_server(&heartbeat)) {
            handle_network_error();
            break;
        }
    }
    return 0;
}

//Message response handler
static void handle_message_response(Message* msg) {    
    char username[256], message[768];    
    sscanf(msg->data, "%[^:]:%s", username, message);
    on_message_received(username, message);
}

//Network error handler
void handle_network_error(void) {
    char error_msg[256];
    int error_code = WSAGetLastError();
    snprintf(error_msg, sizeof(error_msg), "Network error: %d", error_code);
    log_client_message(LOG_ERROR, error_msg);
    disconnect_from_server();
}

// Init network connection 
bool initialize_network(const char* address, int port) {
    strncpy(last_known_address, address, sizeof(last_known_address) - 1);
    last_known_port = port;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }

    if (!initialize_security()) {
        WSACleanup();
        return false;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(address);

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    isConnected = true;
    
    networkThread = CreateThread(NULL, 0, network_receive_thread, NULL, 0, NULL);
    heartbeatThread = CreateThread(NULL, 0, heartbeat_thread, NULL, 0, NULL);
    
    if (networkThread == NULL || heartbeatThread == NULL) {
        cleanup_network();
        return false;
    }

    return true;
}

//Send message to server 
bool send_message_to_server(Message* msg) {
    if (!isConnected) return false;

    encrypt_message(msg, get_session_key());
    int result = send(clientSocket, (char*)msg, sizeof(Message), 0);
    decrypt_message(msg, get_session_key());

    return result != SOCKET_ERROR;
}

//Send login request 
bool send_login_request(const char* username, const char* password) {
    Message msg;
    msg.type = LOGIN_REQUEST;
    snprintf(msg.data, sizeof(msg.data), "%s:%s", username, password);
    msg.length = strlen(msg.data);
    return send_message_to_server(&msg);
}

//Send chat message 
bool send_chat_message(const char* username, const char* message) {
    Message msg;
    msg.type = SEND_MESSAGE;
    snprintf(msg.data, sizeof(msg.data), "%s:%s", username, message);
    msg.length = strlen(msg.data);
    return send_message_to_server(&msg);
}

//Request message history
bool request_message_history(const char* username) {
    Message msg;
    msg.type = FETCH_MESSAGES;
    strncpy(msg.data, username, sizeof(msg.data) - 1);
    msg.length = strlen(msg.data);
    return send_message_to_server(&msg);
}

//Disconnect from server 
void disconnect_from_server(void) {
    cleanup_network();
}

//Notify server about conversation opening 
void notify_server_conversation_opened(const char* username) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Opening conversation with %s", username);
    log_client_message(LOG_INFO, log_message);
    
    Message msg;
    msg.type = CONVERSATION_OPENED; 
    strncpy(msg.data, username, sizeof(msg.data) - 1);
    msg.length = strlen(msg.data);
    send_message_to_server(&msg);
}

//Request conversation history 
void request_conversation_history(const char* username) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Requesting history for user: %s", username);
    log_client_message(LOG_DEBUG, log_message);
    
    request_message_history(username);
}

//Subscribe to user messages 
void subscribe_to_messages(const char* username) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Subscribing to messages from: %s", username);
    log_client_message(LOG_INFO, log_message);
    
    Message msg;
    msg.type = SUBSCRIBE_REQUEST; 
    strncpy(msg.data, username, sizeof(msg.data) - 1);
    msg.length = strlen(msg.data);
    send_message_to_server(&msg);
}
//Send registration request 
bool send_register_request(const char* username, const char* password) {
    Message msg;
    msg.type = REGISTER_REQUEST;
    snprintf(msg.data, sizeof(msg.data), "%s:%s", username, password);
    msg.length = strlen(msg.data);
    return send_message_to_server(&msg);
}

//Send logout request 
bool send_logout_request(void) {
    Message msg;
    msg.type = LOGOUT_REQUEST;
    msg.length = 0;
    bool result = send_message_to_server(&msg);
    if (result) {
        cleanup_network();
    }
    return result;
}

//Request user list from server 
void request_user_list(void) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Requesting user list");
    log_client_message(LOG_INFO, log_message);
    
    Message msg;
    msg.type = USER_LIST_REQUEST;
    msg.length = 0;
    send_message_to_server(&msg);
}

//Update user online status 
void update_user_status(const char* username, bool is_online) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Updating status for user %s: %s", 
             username, is_online ? "online" : "offline");
    log_client_message(LOG_INFO, log_message);
    
    Message msg;
    msg.type = USER_STATUS_UPDATE;
    snprintf(msg.data, sizeof(msg.data), "%s:%d", username, is_online);
    msg.length = strlen(msg.data);
    send_message_to_server(&msg);
}

//Handle login response
static void handle_login_response(Message* msg) {
    bool success = false;
    char message[256] = {0};
    
    //in case of parsing error
    if (sscanf(msg->data, "%d:%[^\n]", &success, message) != 2) {
        success = false;
        strncpy(message, "Invalid server response", sizeof(message) - 1);
        log_client_message(LOG_ERROR, "Invalid login response from server");
    }
    
    // Call callback in the principal thread
    log_client_message(LOG_INFO, "Received login response from server");
    g_idle_add((GSourceFunc)on_login_response, g_memdup2(&(struct {
        bool success;
        char message[256];
    }){success, {0}}, sizeof(struct {
        bool success;
        char message[256];
    })));
}

//Callback for fetch message response
static void handle_fetch_messages_response(Message* msg) {   
    // Parse and handle fetched messages    
}