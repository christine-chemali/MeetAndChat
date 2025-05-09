#include <gtk/gtk.h>
#include "config.h"
#include "graphics/utils/CssLoading.h"
#include "graphics/login/UiLogin.h"
#include "network/log/ClientLogging.h"
#include "network/core/MessageSender.h"
#include "network/core/NetworkCore.h"
#include "network/core/NetworkThread.h"
#include "network/core/SessionManager.h"
#include "network/handlenetwork/AppUtils.h"
#include <stdio.h>

int main(int argc, char **argv) {
    setup_signal_handlers();

    // Init logging
    char connection_info[256];
    if (read_config_file("config.ini", connection_info) != 0) {
        fprintf(stderr, "Failed to read configuration file\n");
        return 1;
    }
    
    init_client_logging(connection_info); 
    log_client_message(LOG_INFO, "Application is starting...");

    // Parse network configuration
    char server_address[128];
    int server_port;
    if (!parse_server_config(connection_info, server_address, &server_port)) {
        log_client_message(LOG_WARNING, "Using default network configuration");
    }

     // Init network connection
    if (!initialize_network(server_address, server_port)) {
        log_client_message(LOG_ERROR, "Failed to initialize network connection");
        close_client_logging();
        return 1;
    }
    log_client_message(LOG_INFO, "Network connection established");

    // Init GTK app
    GtkApplication *app;
    int status;

    app = gtk_application_new("org.meetandchat.app", G_APPLICATION_DEFAULT_FLAGS);
    if (app == NULL) {
        log_client_message(LOG_ERROR, "Failed to create GTK application");
        disconnect_from_server();
        close_client_logging();
        return 1;
    }

    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    log_client_message(LOG_INFO, "GTK application created");

    // Run the app
    status = g_application_run(G_APPLICATION(app), argc, argv);

    // Handle app startup status
    if (status == 0) {
        GtkWindow *window = gtk_application_get_active_window(app);
        if (window) {
            load_application_css(window);
            log_client_message(LOG_INFO, "CSS loaded successfully");
        } else {
            log_client_message(LOG_WARNING, "No active window found");
        }
    } else {
        log_client_message(LOG_ERROR, "Application run failed");
    }

     // Cleanup and exit
    cleanup_application(app);
    log_client_message(LOG_INFO, "Application shutdown complete");

    return status;
}

