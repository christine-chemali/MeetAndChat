#include <gtk/gtk.h>
#include <stdlib.h>
#include "AppData.h"

// Free memory
void free_app_data(AppData *data) {
    if (data != NULL) {
        free(data);
    }
}

// Free the memory allocated for the application data 
static void on_main_window_destroy(GtkWidget *widget, AppData *data) {
    free_app_data(data);
}

// Give signal to free memory
void connect_window_destroy_signal(GtkWidget *window, AppData *data) {
    g_signal_connect(window, "destroy", G_CALLBACK(on_main_window_destroy), data);
}