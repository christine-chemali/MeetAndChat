#include "servernetwork/serverFuncs.h"
#include "servernetwork/messageHandler.h"
#include "servernetwork/login/LoginHandler.h"
#include "security/NetworkSecurity.h"
#include "utilsnetwork/Message.h"
#include <stdio.h>
#include <string.h>
#include "servernetwork/ServerSession.h"
#include "serverlogging/ServerLogging.h" 

//bind server
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

//listen connection
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
        log_server_message(ERROR, "Security init failed for session");
        destroy_client_session(session);
        closesocket(clientSocket);
        return 1;
    }

    HANDLE recvHandle = CreateThread(NULL, 0, recvThread, session, 0, NULL);
    if (recvHandle) {
        CloseHandle(recvHandle);
    } else {
        log_server_message(ERROR, "Failed to create recv thread");
    }

    return 0;
}

// Handle receiving client requests
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

// Handle new connection
bool handle_new_connection(SOCKET clientSocket) {
    ClientSession* session = create_client_session(clientSocket);
    
    // Generate a new key of each session 
    if (!initialize_security()) {
        log_server_message(ERROR, "Session security init failed");
        closesocket(clientSocket);
        destroy_client_session(session);
        return false;
    }
    
    // Configurate client thread
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
        log_server_message(ERROR, "Thread creation failed");
        closesocket(clientSocket);
        destroy_client_session(session);
        return false;
    }
    
    CloseHandle(hThread);
    return true;
}


