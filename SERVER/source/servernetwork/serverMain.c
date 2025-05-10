#include "servernetwork/serverFuncs.h"
#include "serversecurity/ServerSecurity.h"
#include "serverdatabase/ServerDatabase.h"
#include "serverlogging/ServerLogging.h"
#include "servermetrics/ServerMetrics.h"
#include "ServerConfig.h"
#include "utilsnetwork/networkFuncs.h"
#include <stdio.h>

int main() {
    char log_buffer[256];

    // Load config
    ServerConfig config;
    if (!load_server_config("server_config.ini", &config)) {
        snprintf(log_buffer, sizeof(log_buffer),
            "INIT: Configuration load failed");
        printf("%s\n", log_buffer);
        return 1;
    }

    // Init logging
    if (!init_server_logging(get_db_connection_string(&config))) {
        snprintf(log_buffer, sizeof(log_buffer),
            "INIT: Logging initialization failed");
        printf("%s\n", log_buffer);
        return 1;
    }
    log_server_message(LOG_INFO, "INIT: Server starting");

    // Init database
    if (!init_server_database(get_db_connection_string(&config))) {
        log_server_message(LOG_ERROR, "INIT: Database initialization failed");
        close_server_logging();
        return 1;
    }
    log_server_message(LOG_INFO, "INIT: Database initialized");

    // Init Winsock
    if (!initWinsock()) {
        log_server_message(LOG_ERROR, "INIT: Winsock initialization failed");
        close_server_database();
        close_server_logging();
        return 1;
    }

    //Init security
    if (!initialize_security()) {
        log_server_message(LOG_ERROR, "INIT: Security initialization failed");
        WSACleanup();
        close_server_database();
        close_server_logging();
        return 1;
    }

    //Create server socket
    SOCKET serverSocket = createSocket();
    if (serverSocket == INVALID_SOCKET) {
        log_server_message(LOG_ERROR, "INIT: Server socket creation failed");
        WSACleanup();
        close_server_database();
        close_server_logging();
        return 1;
    }

    struct sockaddr_in serverAddress = createAddress(config.server_host, config.server_port);

    //bind server
    if (bindServer(serverSocket, &serverAddress) == 1) {
        log_server_message(LOG_ERROR, "INIT: Server bind failed");
        WSACleanup();
        close_server_database();
        close_server_logging();
        return 1;
    }

    //listen to connection
    if (listenConnection(serverSocket) == 1) {
        log_server_message(LOG_ERROR, "INIT: Listen failed");
        WSACleanup();
        close_server_database();
        close_server_logging();
        return 1;
    }

    snprintf(log_buffer, sizeof(log_buffer),
        "INIT: Server started on port %d", config.server_port);
    log_server_message(LOG_INFO, log_buffer);

    // Metrics perform thread 
    HANDLE metricsThread = CreateThread(NULL, 0, performanceMonitorThread, NULL, 0, NULL);
    if (metricsThread == NULL) {
        log_server_message(LOG_ERROR, "INIT: Metrics thread creation failed");
    }

    while(1) {
        SOCKET clientSocket = accept(serverSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            snprintf(log_buffer, sizeof(log_buffer),
                "CONN: Accept failed with error %d", WSAGetLastError());
            log_server_message(LOG_ERROR, log_buffer);
            continue;
        }

        if (!handle_new_connection(clientSocket)) {
            snprintf(log_buffer, sizeof(log_buffer),
                "CONN: Handler failed for socket %d", (int)clientSocket);
            log_server_message(LOG_WARNING, log_buffer);
            closesocket(clientSocket);
            continue;
        }

        snprintf(log_buffer, sizeof(log_buffer),
            "CONN: New connection on socket %d", (int)clientSocket);
        log_server_message(LOG_INFO, log_buffer);

        SOCKET* clientPtr = malloc(sizeof(SOCKET));
        if (clientPtr == NULL) {
            snprintf(log_buffer, sizeof(log_buffer),
                "CONN: Memory allocation failed for socket %d", (int)clientSocket);
            log_server_message(LOG_ERROR, log_buffer);
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