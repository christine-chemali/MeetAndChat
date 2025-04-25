#include <gtk/gtk.h>
#include <stdlib.h>
#include "AppData.h"

// Free memory
void free_app_data(AppData *data) {
    if (data != NULL) {
        free(data);
    }
}

//free when quit the app
static void on_main_window_destroy(GtkWidget *widget, AppData *data) {
    free_app_data(data);
    GApplication *app = G_APPLICATION(gtk_window_get_application(GTK_WINDOW(widget)));
    g_application_quit(app);
}

// Give signal to free memory
void connect_window_destroy_signal(GtkWidget *window, AppData *data) {
    g_signal_connect(window, "destroy", G_CALLBACK(on_main_window_destroy), data);
}