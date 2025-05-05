#include <gtk/gtk.h>
#include <stdlib.h>
#include "graphics/utils/AppData.h"

// Frees memory allocated for application data
void free_app_data(AppData *data) {
    if (data != NULL) {
        free(data);
    }
}

// Called when the main window is destroyed
static void on_main_window_destroy(GtkWidget *widget, AppData *data) {
    free_app_data(data);
}

// Connects the destroy signal for the window
void connect_window_destroy_signal(GtkWidget *window, AppData *data) {
    g_signal_connect(window, "destroy", G_CALLBACK(on_main_window_destroy), data);
}