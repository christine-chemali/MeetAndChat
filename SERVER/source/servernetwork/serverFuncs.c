#include "servernetwork/serverFuncs.h"
#include "servernetwork/messageHandler.h"
#include "servernetwork/login/LoginHandler.h"
#include "security/NetworkSecurity.h"
#include "utilsnetwork/Message.h"
#include <stdio.h>
#include <string.h>
#include "servernetwork/ServerSession.h"
#include "serverlogging/ServerLogging.h" 

// Funct to bind the server
int bindServer(SOCKET serverSocket, struct sockaddr_in* address) {
    if (bind(serverSocket, (struct sockaddr*)address, sizeof(*address)) == SOCKET_ERROR) {
        printf("bind failed, error: %d \n ", WSAGetLastError());
        closesocket(serverSocket);
        return 1;
    } else {
        printf("bind successful \n");
        return 0;
    }
}

// Listen to connections
int listenConnection(SOCKET serverSocket) {
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen failed, error: %d", WSAGetLastError());
        closesocket(serverSocket);
        return 1;
    } else {
        printf("now listening... \n");
        return 0;
    }
}

// Client Thread 
DWORD WINAPI clientThread(LPVOID lpParam) {
    SOCKET clientSocket = *(SOCKET*)lpParam;
    free(lpParam);

    ClientSession* session = create_client_session(clientSocket);
    if (!session) {
        closesocket(clientSocket);
        return 1;
    }

    if (!initialize_security()) {
        log_server_message(LOG_ERROR, "Security initialization failed for session");
        destroy_client_session(session);
        closesocket(clientSocket);
        return 1;
    }

    // Generate a new session key and sent it to client 
    if (!send_session_key_to_client(session)) {
        log_server_message(LOG_ERROR, "Failed to send session key to client");
        destroy_client_session(session);
        closesocket(clientSocket);
        return 1;
    }

    HANDLE recvHandle = CreateThread(NULL, 0, recvThread, session, 0, NULL);
    if (recvHandle) {
        CloseHandle(recvHandle);
    } else {
        log_server_message(LOG_ERROR, "Failed to create receive thread");
    }

    return 0;
}

// Funct to receive messages
DWORD WINAPI recvThread(LPVOID lpParam) {
    char log_buffer[256];
    ClientSession* session = (ClientSession*)lpParam;
    if (!session) {
        log_server_message(LOG_ERROR, "RECV: Null session parameter");
        return 1;
    }

    snprintf(log_buffer, sizeof(log_buffer), 
        "RECV: Starting receive thread for socket %d", 
        (int)session->clientSocket);
    log_server_message(LOG_INFO, log_buffer);

    while (1) {
        log_server_message(LOG_DEBUG, "RECV: Waiting for next message...");
        
        Message* msg = receive_message(session->clientSocket);
        if (!msg) {
            snprintf(log_buffer, sizeof(log_buffer), 
                "RECV: Connection lost on socket %d", 
                (int)session->clientSocket);
            log_server_message(LOG_ERROR, log_buffer);
            break;
        }
        
        snprintf(log_buffer, sizeof(log_buffer), 
            "RECV: Got message type %d from socket %d", 
            msg->type, (int)session->clientSocket);
        log_server_message(LOG_DEBUG, log_buffer);
        
        if (!verify_message_checksum(msg)) {
            snprintf(log_buffer, sizeof(log_buffer), 
                "RECV: Checksum verification failed for message type %d", 
                msg->type);
            log_server_message(LOG_ERROR, log_buffer);
            free_message(msg);
            continue;
        }
        
        handle_client_message(session, msg);
        free_message(msg);
    }
    
    if (session->isAuthenticated) {
        snprintf(log_buffer, sizeof(log_buffer), 
            "RECV: Handling logout for socket %d",
            (int)session->clientSocket);
        log_server_message(LOG_INFO, log_buffer);
        handle_logout_request(session);
    }

    closesocket(session->clientSocket);
    free(session);
    return 0;
}

// Funct to handle new connections
bool handle_new_connection(SOCKET clientSocket) {
    ClientSession* session = create_client_session(clientSocket);
    
    if (!session) {
        log_server_message(LOG_ERROR, "Failed to create client session");
        closesocket(clientSocket);
        return false;
    }

    if (!initialize_security()) {
        log_server_message(LOG_ERROR, "Session security initialization failed");
        closesocket(clientSocket);
        destroy_client_session(session);
        return false;
    }

    // Config client thread
    DWORD threadId;
    HANDLE hThread = CreateThread(
        NULL, 
        0, 
        clientThread, 
        session, 
        0, 
        &threadId
    );
    
    if (!hThread) {
        log_server_message(LOG_ERROR, "Thread creation failed");
        closesocket(clientSocket);
        destroy_client_session(session);
        return false;
    }
    
    CloseHandle(hThread);
    return true;
}

// Funct to send key session to client
bool send_session_key_to_client(ClientSession* session) {
    if (!session || !is_security_initialized) {
        log_server_message(LOG_ERROR, "Failed to send session key: invalid session or security not initialized");
        return false;
    }

    Message key_msg;
    memset(&key_msg, 0, sizeof(Message));
    key_msg.type = KEY_ROTATION;
    strncpy(key_msg.data, session_key, sizeof(key_msg.data) - 1);
    key_msg.length = strlen(key_msg.data);
    prepare_message(&key_msg);
    encrypt_message(&key_msg, get_session_key());

    if (!send_message_to_client(session, &key_msg)) {
        log_server_message(LOG_ERROR, "Failed to send session key to client");
        return false;
    }

    log_server_message(LOG_INFO, "Session key sent successfully to client");
    return true;
}