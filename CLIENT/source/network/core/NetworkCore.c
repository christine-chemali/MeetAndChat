#include "network/session/ClientSession.h"
#include "network/core/NetworkCore.h"
#include "network/core/NetworkThread.h"
#include "network/core/SessionManager.h"
#include "network/core/MessageSender.h"
#include "network/log/ClientLogging.h"
#include "security/NetworkSecurity.h"
#include <glib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

// Global variables for network management
SOCKET clientSocket = INVALID_SOCKET;
bool isConnected = false;
char last_known_address[128] = {0};  
int last_known_port = 0;  

static NetworkState currentState = NETWORK_STATE_DISCONNECTED;

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
    // Save parameters connection till the start
    strncpy(last_known_address, address, sizeof(last_known_address) - 1);
    last_known_address[sizeof(last_known_address) - 1] = '\0';
    last_known_port = port;

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
        
        // do not clean last_known_address and last_known_port
    }
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

// Re init session parameters
void reset_session_parameters(void) {
    ClientSession* session = get_current_session();
    if (session) {
        session->isAuthenticated = false;
        session->lastActivity = 0;
        memset(session->username, 0, sizeof(session->username));
        // Keep the socket but re init everything else
    }
    update_network_state(NETWORK_STATE_DISCONNECTED);
}

// re init the network connection
bool reinitialize_network_connection(void) {
    if (strlen(last_known_address) == 0 || last_known_port <= 0 || last_known_port > 65535) {
        log_client_message(LOG_ERROR, "Invalid stored connection parameters");
        return false;
    }

    reset_session_parameters();
    
    // Wait 1/2 sec before reconnection
    Sleep(500);
    
    return initialize_network(last_known_address, last_known_port);
}

// Secure reconnection
bool safe_reconnect(void) {
    cleanup_network();
    Sleep(500); //wait 1/2 sec before reconnection
    return reinitialize_network_connection();
}