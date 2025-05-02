
#include <gtk/gtk.h>
#include "config.h"
#include "graphics/utils/CssLoading.h"
#include "graphics/login/UiLogin.h"
#include "network/log/ClientLogging.h" 

// Main function
int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

    char connection_info[256];
    if (read_config_file("config.ini", connection_info) != 0) {        
        fprintf(stderr, "Failed to read configuration file\n");        
        return 1;    
    }
    init_client_logging(connection_info);

    log_client_message("Application is starting...");

    app = gtk_application_new("org.meetandchat.app", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);

    log_client_message("GTK application created.");

    status = g_application_run(G_APPLICATION(app), argc, argv);

    if (status == 0) {
        GtkWindow *window = gtk_application_get_active_window(app);
        if (window) {
            load_application_css(window);
            log_client_message("CSS loaded successfully.");
        } else {
            log_client_message("Warning: No active window found.");
        }
    } else {
        log_client_message("Error: Application run failed.");
    }

    g_object_unref(app);
    
    close_client_logging(); 
    return status;
}