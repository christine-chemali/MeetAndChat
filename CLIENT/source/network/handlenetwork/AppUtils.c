#include "network/handlenetwork/AppUtils.h"
#include "network/log/ClientLogging.h"
#include "network/core/MessageSender.h"
#include "network/core/NetworkCore.h"
#include "network/core/NetworkThread.h"
#include "network/core/SessionManager.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Handles system signals for termination
static void signal_handler(int signum) {
    log_client_message(LOG_INFO, "Received termination signal. Cleaning up...");
    disconnect_from_server();
    close_client_logging();
    exit(signum);
}

// Parses server configuration from a string
bool parse_server_config(const char* connection_info, char* server_address, int* server_port) {
    const char* default_address = "127.0.0.1";
    const int default_port = 8081;
    
    // Parses server configuration from a string
    if (!connection_info || !server_address || !server_port) {
        strncpy(server_address, default_address, 128);
        *server_port = default_port;
        return false;
    }

    // Attempt to parse address and port from connection_info
    if (sscanf(connection_info, "address=%127[^;];port=%d", server_address, server_port) != 2) {
        strncpy(server_address, default_address, 128);
        *server_port = default_port;
        return false;
    }

    return true;
}

// Cleans up application resources
void cleanup_application(GtkApplication* app) {
    disconnect_from_server();
    close_client_logging();
    g_object_unref(app);
}

// Sets up handlers for system signals like SIGINT and SIGTERM
void setup_signal_handlers(void) {
    signal(SIGINT, signal_handler); // Handle interrupt signal (e.g., Ctrl+C)
    signal(SIGTERM, signal_handler); // Handle termination signal
}