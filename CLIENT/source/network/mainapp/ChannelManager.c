#include <gtk/gtk.h>
#include <stdlib.h>
#include "logic/mainapp/InputValidation.h"

// Populate channel dropdown
void populate_channel_dropdown(GtkDropDown *dropdown) {

    GtkStringList *string_list = gtk_string_list_new(NULL);
    
    const char *channels[] = {"channel 1", "channel 2", "channel 3", NULL};
    for (int i = 0; channels[i] != NULL; i++) {
        gtk_string_list_append(string_list, channels[i]);
    }
    
    gtk_drop_down_set_model(dropdown, G_LIST_MODEL(string_list));
}

// Delete the selected channel
void delete_selected_channel(GtkWidget *button, GtkDropDown *drop_down) {
    guint selected_index = gtk_drop_down_get_selected(drop_down);
    GtkStringObject *selected_item = GTK_STRING_OBJECT(gtk_drop_down_get_selected_item(drop_down));
    
    if (selected_item) {
        const char *selected_channel = gtk_string_object_get_string(selected_item);
        g_print("Deleting channel: %s\n", selected_channel);
    } else {
        g_print("No channel selected.\n");
    }
}

//Create a channel
void handle_create_channel(GtkWidget *button, GtkEntry *entry) {
    const char *channel_name = gtk_editable_get_text(GTK_EDITABLE(entry));
    
    if (validate_channel_name(channel_name)) {
        g_print("Creating channel: %s\n", channel_name);
        gtk_editable_set_text(GTK_EDITABLE(entry), ""); 
    } else {
        g_print("Invalid channel name\n");
    }
}