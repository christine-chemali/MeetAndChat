#include "servernetwork/serverFuncs.h"
#include "serversecurity/ServerSecurity.h"
#include "serverdatabase/ServerDatabase.h"
#include "serverlogging/ServerLogging.h"
#include "servermetrics/ServerMetrics.h"
#include "ServerConfig.h"
#include "utilsnetwork/networkFuncs.h"
#include <stdio.h>

int main() {
    // Load config
    ServerConfig config;
    if (!load_server_config("server_config.ini", &config)) {
        printf("Failed to load configuration\n");
        return 1;
    }

    // Init logging
    if (!init_server_logging(get_db_connection_string(&config))) {
        printf("Failed to initialize server logging\n");
        return 1;
    }
    log_server_message(LOG_INFO, "Server starting...");

    // Init database
    if (!init_server_database(get_db_connection_string(&config))) {
        log_server_message(LOG_ERROR, "Failed to initialize database");
        close_server_logging();
        return 1;
    }
    log_server_message(LOG_INFO, "Database initialized successfully");

    // Init Winsock
    if (!initWinsock()) {
        log_server_message(LOG_ERROR, "Failed to initialize Winsock");
        close_server_database();
        close_server_logging();
        return 1;
    }

    //Init security
    if (!initialize_security()) {
        log_server_message(LOG_ERROR, "Failed to initialize security");
        WSACleanup();
        close_server_database();
        close_server_logging();
        return 1;
    }

    //Create server socket
    SOCKET serverSocket = createSocket();
    if (serverSocket == INVALID_SOCKET) {
        log_server_message(LOG_ERROR, "Failed to create server socket");
        WSACleanup();
        close_server_database();
        close_server_logging();
        return 1;
    }

    struct sockaddr_in serverAddress = createAddress(config.server_host, config.server_port);

    //bind server
    if (bindServer(serverSocket, &serverAddress) == 1) {
        log_server_message(LOG_ERROR, "Failed to bind server");
        WSACleanup();
        close_server_database();
        close_server_logging();
        return 1;
    }

    //listen to connection
    if (listenConnection(serverSocket) == 1) {
        log_server_message(LOG_ERROR, "Failed to listen for connections");
        WSACleanup();
        close_server_database();
        close_server_logging();
        return 1;
    }

    log_server_message(LOG_INFO, "Server started successfully, waiting for connections");

    // Metrics perform thread 
    HANDLE metricsThread = CreateThread(NULL, 0, performanceMonitorThread, NULL, 0, NULL);
    if (metricsThread == NULL) {
        log_server_message(LOG_ERROR, "Failed to create metrics thread");
    }

    while(1) {
        SOCKET clientSocket = accept(serverSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "Connection failed, error: %d", WSAGetLastError());
            log_server_message(LOG_ERROR, error_msg);
            continue;
        }

        log_server_message(LOG_INFO, "New client connected");

        SOCKET* clientPtr = malloc(sizeof(SOCKET));
        if (clientPtr == NULL) {
            log_server_message(LOG_ERROR, "Failed to allocate memory for client socket");
            closesocket(clientSocket);
            continue;
        }
        *clientPtr = clientSocket;

        HANDLE threadHandle = newThread(clientPtr, clientThread);
        if (threadHandle != NULL) {
            CloseHandle(threadHandle);
        }
    }

    // CleanUp
    if (metricsThread) CloseHandle(metricsThread);
    closesocket(serverSocket);
    WSACleanup();
    close_server_database();
    close_server_logging();

    return 0;
}