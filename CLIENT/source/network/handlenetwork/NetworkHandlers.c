#include "network/handlenetwork/NetworkHandlers.h"
#include "network/log/ClientLogging.h"
#include "security/NetworkSecurity.h"
#include "callbacks/GuiCallbacks.h"
#include "network/session/ClientSession.h"
#include <glib.h>   
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

// Declare static functions
static void handle_login_response(Message* msg);
static void handle_message_response(Message* msg);
static void handle_fetch_messages_response(Message* msg);
static void handle_register_response(Message* msg);
static void handle_disconnect_response(Message* msg);
static DWORD WINAPI network_receive_thread(LPVOID lpParam);
static DWORD WINAPI heartbeat_thread(LPVOID lpParam);

static NetworkState currentState = NETWORK_STATE_DISCONNECTED;
static char current_user[256] = {0};

//Global variables for network management 
SOCKET clientSocket = INVALID_SOCKET;
bool isConnected = false;
HANDLE networkThread = NULL;
HANDLE heartbeatThread = NULL; 
char last_known_address[128] = {0};  
int last_known_port = 0;  

// Update the network state
void update_network_state(NetworkState newState) {
    currentState = newState;
    char state_msg[64];
    switch(newState) {
        case NETWORK_STATE_DISCONNECTED:
            strcpy(state_msg, "Disconnected");
            break;
        case NETWORK_STATE_CONNECTING:
            strcpy(state_msg, "Connecting");
            break;
        case NETWORK_STATE_CONNECTED:
            strcpy(state_msg, "Connected");
            break;
        case NETWORK_STATE_AUTHENTICATING:
            strcpy(state_msg, "Authenticating");
            break;
        case NETWORK_STATE_AUTHENTICATED:
            strcpy(state_msg, "Authenticated");
            break;
    }
    char log_msg[128];
    snprintf(log_msg, sizeof(log_msg), "Network state changed to: %s", state_msg);
    log_client_message(LOG_INFO, log_msg);
}

// Handle disconnect response
static void handle_disconnect_response(Message* msg) {
    bool success = false;
    char message[256] = {0};

    if (sscanf(msg->data, "%d:%[^\n]", &success, message) != 2) {
        success = false;
        strncpy(message, "Invalid server response", sizeof(message) - 1);
    }
    
    g_idle_add((GSourceFunc)on_disconnect_response, g_memdup2(&(struct {
        bool success;
        char message[256];
    }){success, {0}}, sizeof(struct {
        bool success;
        char message[256];
    })));
}

// Get the current user
const char* get_current_user(void) {
    return current_user;
}

// Check the connection status
bool check_connection_status(void) {
    ClientSession* session = get_current_session();
    if (!isConnected || !session || !is_session_valid_initial(session)) {
        log_client_message(LOG_ERROR, "Not connected to server");
        return false;
    }
    return true;
}

// Initialize the network connection
bool initialize_network(const char* address, int port) {
    log_client_message(LOG_INFO, "Starting network initialization...");
    
    if (isConnected) {
        log_client_message(LOG_WARNING, "Already connected, disconnecting first");
        cleanup_network();
    }
    
    // Validate entry parameters
    if (!address || !*address || port <= 0 || port > 65535) {
        log_client_message(LOG_ERROR, "Invalid address or port parameters");
        return false;
    }

    // Verify IP addr
    struct in_addr addr;
    if (inet_pton(AF_INET, address, &addr) != 1) {
        log_client_message(LOG_ERROR, "Invalid IP address format");
        return false;
    }

    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "WSAStartup failed with error: %d", wsaResult);
        log_client_message(LOG_ERROR, error_msg);
        return false;
    }

    // Init network security
    if (!initialize_security()) {
        log_client_message(LOG_ERROR, "Failed to initialize security");
        WSACleanup();
        return false;
    }

    // Create client socket
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        int error = WSAGetLastError();
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Socket creation failed with error: %d", error);
        log_client_message(LOG_ERROR, error_msg);
        WSACleanup();
        return false;
    }

    // Timeouts config
    DWORD timeout = 30000; // 30 sec
    if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) == SOCKET_ERROR ||
        setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        log_client_message(LOG_ERROR, "Failed to set socket timeouts");
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    // Keepalive config
    struct tcp_keepalive keepAlive_vals;
    keepAlive_vals.onoff = 1;
    keepAlive_vals.keepalivetime = 10000;    // 10 sec
    keepAlive_vals.keepaliveinterval = 1000; // 1 sec
    DWORD bytesReturned = 0;

    if (WSAIoctl(clientSocket, SIO_KEEPALIVE_VALS, &keepAlive_vals,
                 sizeof(keepAlive_vals), NULL, 0, &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
        log_client_message(LOG_WARNING, "Failed to set keepalive values");
    }

    // Buffer config
    int rcvbuf = 65536; // 64KB
    int sndbuf = 65536; // 64KB
    if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, (char*)&rcvbuf, sizeof(rcvbuf)) == SOCKET_ERROR ||
        setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, (char*)&sndbuf, sizeof(sndbuf)) == SOCKET_ERROR) {
        log_client_message(LOG_WARNING, "Failed to set buffer sizes");
    }

    // TCP_NODELAY config
    BOOL noDelay = TRUE;
    if (setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&noDelay, sizeof(noDelay)) == SOCKET_ERROR) {
        log_client_message(LOG_WARNING, "Failed to set TCP_NODELAY");
    }

    // Server addr config
    struct sockaddr_in serverAddr;
    ZeroMemory(&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons((unsigned short)port);
    serverAddr.sin_addr.s_addr = inet_addr(address);

    if (serverAddr.sin_addr.s_addr == INADDR_NONE) {
        log_client_message(LOG_ERROR, "Invalid IP address");
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    // update network state
    update_network_state(NETWORK_STATE_CONNECTING);

    // Try to connect
    char connect_msg[256];
    snprintf(connect_msg, sizeof(connect_msg), "Attempting to connect to %s:%d", address, port);
    log_client_message(LOG_INFO, connect_msg);

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Connect failed with error: %d", error);
        log_client_message(LOG_ERROR, error_msg);
        closesocket(clientSocket);
        WSACleanup();
        update_network_state(NETWORK_STATE_DISCONNECTED);
        return false;
    }

    // Create and validate session
    ClientSession* session = create_client_session(clientSocket);
    if (!session || !is_session_valid_initial(session)) {
        log_client_message(LOG_ERROR, "Invalid session after creation");
        if (session) destroy_client_session(session);
        closesocket(clientSocket);
        WSACleanup();
        update_network_state(NETWORK_STATE_DISCONNECTED);
        return false;
    }

    // Config connection and session
    isConnected = true;
    session->lastActivity = time(NULL);

    if (!set_current_session(session)) {
        log_client_message(LOG_ERROR, "Failed to set current session");
        isConnected = false;
        destroy_client_session(session);
        closesocket(clientSocket);
        WSACleanup();
        update_network_state(NETWORK_STATE_DISCONNECTED);
        return false;
    }

    // Create threads
    //network
    networkThread = CreateThread(NULL, 0, network_receive_thread, NULL, 0, NULL);
    if (!networkThread) {
        log_client_message(LOG_ERROR, "Failed to create network thread");
        isConnected = false;
        destroy_client_session(session);
        set_current_session(NULL);
        closesocket(clientSocket);
        WSACleanup();
        update_network_state(NETWORK_STATE_DISCONNECTED);
        return false;
    }

    //heartbeat
    heartbeatThread = CreateThread(NULL, 0, heartbeat_thread, NULL, 0, NULL);
    if (!heartbeatThread) {
        log_client_message(LOG_ERROR, "Failed to create heartbeat thread");
        isConnected = false;
        TerminateThread(networkThread, 0);
        CloseHandle(networkThread);
        destroy_client_session(session);
        set_current_session(NULL);
        closesocket(clientSocket);
        WSACleanup();
        update_network_state(NETWORK_STATE_DISCONNECTED);
        return false;
    }

    // Saving connection infos
    strncpy(last_known_address, address, sizeof(last_known_address) - 1);
    last_known_address[sizeof(last_known_address) - 1] = '\0';
    last_known_port = port;

    // Update final state
    update_network_state(NETWORK_STATE_CONNECTED);
    log_client_message(LOG_INFO, "Network initialization completed successfully");
    return true;
}

// Clean up the network resources
void cleanup_network(void) {
    if (isConnected) {
        ClientSession* session = get_current_session();
        
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
        
        if (session) {
            destroy_client_session(session);
            set_current_session(NULL);
        }
        
        if (clientSocket != INVALID_SOCKET) {
            closesocket(clientSocket);
            clientSocket = INVALID_SOCKET;
        }
        
        memset(current_user, 0, sizeof(current_user));
        WSACleanup();
        
        memset(last_known_address, 0, sizeof(last_known_address));
        last_known_port = 0;
    }
}

// Handle login response
static void handle_login_response(Message* msg) {
    bool success = false;
    char message[256] = {0};
    char username[256] = {0};
    
    if (sscanf(msg->data, "%d:%[^|]|%s", &success, message, username) != 3) {
        success = false;
        strncpy(message, "Invalid server response", sizeof(message) - 1);
        log_client_message(LOG_ERROR, "Invalid login response from server");
    }
    
    ClientSession* session = get_current_session();
    
    if (success && session) {
        authenticate_session(session, username);
        strncpy(current_user, username, sizeof(current_user) - 1);
        current_user[sizeof(current_user) - 1] = '\0';
        log_client_message(LOG_INFO, "User authenticated successfully");
    } else {
        if (session) {
            invalidate_session(session);
        }
        log_client_message(LOG_WARNING, "Authentication failed");
    }
    
    log_client_message(LOG_INFO, "Received login response from server");
    g_idle_add((GSourceFunc)on_login_response, g_memdup2(&(struct {
        bool success;
        char message[256];
    }){success, {0}}, sizeof(struct {
        bool success;
        char message[256];
    })));
}

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

// Run the heartbeat receive thread
static DWORD WINAPI network_receive_thread(LPVOID lpParam) {
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

// Send login request
bool send_login_request(const char* username, const char* password) {
    if (!check_connection_status()) {
        return false;
    }

    if (!username || !password) {
        log_client_message(LOG_ERROR, "Invalid login credentials");
        return false;
    }

    log_client_message(LOG_INFO, "Preparing login request");
    Message msg;
    memset(&msg, 0, sizeof(Message));
    msg.type = LOGIN_REQUEST;
    
    if (snprintf(msg.data, sizeof(msg.data), "%s:%s", username, password) >= sizeof(msg.data)) {
        log_client_message(LOG_ERROR, "Login credentials too long");
        return false;
    }
    
    msg.length = strlen(msg.data);
    log_client_message(LOG_INFO, "Sending login request...");
    
    return send_message_to_server(&msg);
}

  // Run the heartbeat thread
static DWORD WINAPI heartbeat_thread(LPVOID lpParam) {
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

// Handle network errors
void handle_network_error(void) {
    ClientSession* session = get_current_session();
    char error_msg[256];
    int error_code = WSAGetLastError();
    snprintf(error_msg, sizeof(error_msg), "Network error: %d", error_code);
    log_client_message(LOG_ERROR, error_msg);

    if (session) {
        invalidate_session(session);
    }
    disconnect_from_server();
}

// Disconnect from the server
void disconnect_from_server(void) {
    ClientSession* session = get_current_session();
    if (session && session->isAuthenticated) {
        send_disconnect_request(session->username);
    }
    cleanup_network();
}

// Send a disconnect request
bool send_disconnect_request(const char* username) {
    if (!check_connection_status()) {
        return false;
    }

    Message msg;
    msg.type = LOGOUT_REQUEST;
    strncpy(msg.data, username, sizeof(msg.data) - 1);
    msg.length = strlen(msg.data);
    msg.checksum = calculate_checksum(msg.data, msg.length);

    bool result = send_message_to_server(&msg);
    if (result) {
        cleanup_network();
    }
    return result;
}

// Send a chat message
bool send_chat_message(const char* username, const char* message) {
    if (!check_connection_status()) {
        return false;
    }

    Message msg;
    msg.type = SEND_MESSAGE;
    snprintf(msg.data, sizeof(msg.data), "%s:%s", username, message);
    msg.length = strlen(msg.data);
    return send_message_to_server(&msg);
}

 // Request message history
bool request_message_history(const char* username) {
    if (!check_connection_status()) {
        return false;
    }

    Message msg;
    msg.type = FETCH_MESSAGES;
    strncpy(msg.data, username, sizeof(msg.data) - 1);
    msg.length = strlen(msg.data);
    return send_message_to_server(&msg);
}

// Notify the server about a conversation opening
void notify_server_conversation_opened(const char* username) {
    if (!check_connection_status()) {
        return;
    }

    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Opening conversation with %s", username);
    log_client_message(LOG_INFO, log_message);
    
    Message msg;
    msg.type = CONVERSATION_OPENED; 
    strncpy(msg.data, username, sizeof(msg.data) - 1);
    msg.length = strlen(msg.data);
    send_message_to_server(&msg);
}

// Request conversation history
void request_conversation_history(const char* username) {
    if (!check_connection_status()) {
        return;
    }

    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Requesting history for user: %s", username);
    log_client_message(LOG_DEBUG, log_message);
    
    request_message_history(username);
}

// Subscribe to messages from a user
void subscribe_to_messages(const char* username) {
    if (!check_connection_status()) {
        return;
    }

    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Subscribing to messages from: %s", username);
    log_client_message(LOG_INFO, log_message);
    
    Message msg;
    msg.type = SUBSCRIBE_REQUEST; 
    strncpy(msg.data, username, sizeof(msg.data) - 1);
    msg.length = strlen(msg.data);
    send_message_to_server(&msg);
}

// Send a logout request
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

// Request the user list
void request_user_list(void) {
    if (!check_connection_status()) {
        return;
    }

    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Requesting user list");
    log_client_message(LOG_INFO, log_message);
    
    Message msg;
    msg.type = USER_LIST_REQUEST;
    msg.length = 0;
    send_message_to_server(&msg);
}

// Update the user status
void update_user_status(const char* username, bool is_online) {
    if (!check_connection_status()) {
        return;
    }

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

// Handle message response
static void handle_message_response(Message* msg) {  
    char username[256], message[768];    
    sscanf(msg->data, "%[^:]:%s", username, message);
    on_message_received(username, message);
}

// Parse and handle fetched messages  
static void handle_fetch_messages_response(Message* msg) {   
  
}

// Send a registration request
bool send_registration_request(const char *first_name, const char *last_name, 
    const char *username, const char *email, 
    const char *password, const char *first_question, 
    const char *second_question) {
    
    Message msg;
    msg.type = REGISTER_REQUEST;

    snprintf(msg.data, MAX_MESSAGE_LENGTH, "%s|%s|%s|%s|%s|%s|%s",
             first_name, last_name, username, email, 
             password, first_question, second_question);

    msg.length = strlen(msg.data);
    msg.checksum = calculate_checksum(msg.data, msg.length);

    return send_message_to_server(&msg);  
}

// Handle registration response
static void handle_register_response(Message* msg) {
    bool success = false;
    char message[256] = {0};
    
    if (sscanf(msg->data, "%d:%[^\n]", &success, message) != 2) {
        success = false;
        strncpy(message, "Invalid server response", sizeof(message) - 1);
        log_client_message(LOG_ERROR, "Invalid registration response from server");
    }
    
    log_client_message(LOG_INFO, "Received registration response from server");
    g_idle_add((GSourceFunc)on_register_response, g_memdup2(&(struct {
        bool success;
        char message[256];
    }){success, {0}}, sizeof(struct {
        bool success;
        char message[256];
    })));
}

// Set the current user
void set_current_user(const char* username) {
    if (!check_connection_status()) {
        return;
    }
    
    if (username) {
        strncpy(current_user, username, sizeof(current_user) - 1);
        current_user[sizeof(current_user) - 1] = '\0';
    } else {
        memset(current_user, 0, sizeof(current_user));
    }
}