#include <gtk/gtk.h>
#include <stdlib.h>
#include "logic/mainapp/InputValidation.h"

// Populate category dropdown
void populate_category_dropdown(GtkDropDown *dropdown) {

    GtkStringList *string_list = gtk_string_list_new(NULL);
    
    const char *categories[] = {"category 1", "category 2", "category 3", NULL};
    for (int i = 0; categories[i] != NULL; i++) {
        gtk_string_list_append(string_list, categories[i]);
    }
    
    gtk_drop_down_set_model(dropdown, G_LIST_MODEL(string_list));
}

// Delete the selected category
void delete_selected_category(GtkWidget *button, GtkDropDown *drop_down) {
    guint selected_index = gtk_drop_down_get_selected(drop_down);
    GtkStringObject *selected_item = GTK_STRING_OBJECT(gtk_drop_down_get_selected_item(drop_down));
    
    if (selected_item) {
        const char *selected_category = gtk_string_object_get_string(selected_item);
        g_print("Deleting category: %s\n", selected_category);
    } else {
        g_print("No category selected.\n");
    }
}

// to create a category
void handle_create_category(GtkWidget *button, GtkEntry *entry) {
    const char *category_name = gtk_editable_get_text(GTK_EDITABLE(entry));
    
    if (validate_category_name(category_name)) {
        g_print("Creating category: %s\n", category_name);
        gtk_editable_set_text(GTK_EDITABLE(entry), ""); 
    } else {
        g_print("Invalid category name\n");
    }
}