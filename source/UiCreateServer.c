#include <gtk/gtk.h>
#include "UiCreateServer.h"
#include "AppData.h"

//Display the create server content
void show_create_server_content(GtkWidget *button, AppData *data) {

    GtkWidget *existing_page = gtk_stack_get_child_by_name(GTK_STACK(data->stack), "create_server");
    if (existing_page) {
        gtk_stack_set_visible_child(GTK_STACK(data->stack), existing_page);
        return;
    }

    GtkWidget *create_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(create_box, 20);
    gtk_widget_set_margin_bottom(create_box, 20);
    gtk_widget_set_margin_start(create_box, 20);
    gtk_widget_set_margin_end(create_box, 20);
    gtk_widget_set_halign(create_box, GTK_ALIGN_START);

    GtkWidget *create_label = gtk_label_new("Create a Server");
    gtk_box_append(GTK_BOX(create_box), create_label);
    
    // Test scrollbar
    for (int i = 0; i < 50; i++) {
    GtkWidget *test_label = gtk_label_new("Test Line");
    gtk_box_append(GTK_BOX(create_box), test_label);
    }

    gtk_stack_add_named(GTK_STACK(data->stack), create_box, "create_server");
    gtk_stack_set_visible_child(GTK_STACK(data->stack), create_box);
}
