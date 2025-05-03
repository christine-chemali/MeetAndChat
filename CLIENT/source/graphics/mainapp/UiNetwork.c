#include <gtk/gtk.h>
#include "graphics/mainapp/UiNetwork.h"
#include "graphics/utils/AppData.h"

//Display the create server content
void show_network_content(GtkWidget *button, AppData *data) {
    GtkWidget *existing_page = gtk_stack_get_child_by_name(GTK_STACK(data->stack), "network");
    if (existing_page) {
        gtk_stack_set_visible_child(GTK_STACK(data->stack), existing_page);
        return;
    }

    // Main container
    GtkWidget *main_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top(main_container, 20);
    gtk_widget_set_margin_bottom(main_container, 8);
    gtk_widget_set_margin_start(main_container, 8);
    gtk_widget_set_margin_end(main_container, 0);

    // Box for the content
    GtkWidget *create_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(create_box, 20);
    gtk_widget_set_margin_bottom(create_box, 20);
    gtk_widget_set_margin_start(create_box, 20);
    gtk_widget_set_margin_end(create_box, 20);
    gtk_widget_set_halign(create_box, GTK_ALIGN_START);

    // Scrolled Window
    GtkWidget *scrolled_window = gtk_scrolled_window_new();
    gtk_widget_set_margin_start(scrolled_window, 10);
    gtk_widget_set_css_classes(scrolled_window, (const char*[]){"channel-area", NULL});
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), 
                                 GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_hexpand(scrolled_window, TRUE);
    gtk_widget_set_vexpand(scrolled_window, TRUE);

    // Content
    GtkWidget *create_label = gtk_label_new("Network");
    gtk_box_append(GTK_BOX(create_box), create_label);
    
    // Test scrollbar
    for (int i = 0; i < 50; i++) {
        GtkWidget *test_label = gtk_label_new("Test Line");
        gtk_box_append(GTK_BOX(create_box), test_label);
    }

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), create_box);
    
    //Append
    gtk_box_append(GTK_BOX(main_container), scrolled_window);

    //Add to stack
    gtk_stack_add_named(GTK_STACK(data->stack), main_container, "network");
    gtk_stack_set_visible_child(GTK_STACK(data->stack), main_container);
}