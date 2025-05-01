#include <gtk/gtk.h>
#include "graphics/utils/CssLoading.h"
#include "graphics/login/UiLogin.h"

//main 
int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

    app = gtk_application_new("org.gtk.example", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);

    status = g_application_run(G_APPLICATION(app), argc, argv);

    if (status == 0) {
        GtkWindow *window = gtk_application_get_active_window(app);
        if (window) {
            load_application_css(window);
        }
    }

    g_object_unref(app);
    return status;
}

/*
//uncommment when a solution to compile with postgres is founded
#include <gtk/gtk.h>
#include "graphics/utils/CssLoading.h"
#include "graphics/login/UiLogin.h"
#include "network/log/ClientLogging.h" 

// Main function
int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

   //init_client_logging("client.log"); // if it is in log file
    init_client_logging("host=localhost port=5432 dbname=discord user=postgres password=TreeGreen2");

    log_client_message("Application is starting...");

    app = gtk_application_new("org.gtk.example", G_APPLICATION_DEFAULT_FLAGS);
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
*/