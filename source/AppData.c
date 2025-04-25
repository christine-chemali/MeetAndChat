#include <gtk/gtk.h>
#include <stdlib.h>
#include "AppData.h"

//define server data struct
typedef struct {
    char *name;
    // Add all other server data fields
} ServerData;

 // Free the servers list and its contents
void free_app_data(AppData *data) {
    if (data != NULL) {
        if (data->servers != NULL) {
            GList *current_node = data->servers;
            while (current_node != NULL) {
                ServerData *server = (ServerData *)current_node->data;
                free(server);
                current_node = current_node->next;
            }
            g_list_free(data->servers);
            data->servers = NULL; 
        }
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