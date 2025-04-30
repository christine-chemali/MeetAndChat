#include <gtk/gtk.h>
#include "graphics/mainapp/UiCreateServer.h"
#include "graphics/utils/BottomBar.h"

void show_create_server_content(GtkWidget *stack, GCallback return_to_main_callback) {
    // main box
    GtkWidget *create_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top(create_box, 0);
    gtk_widget_set_margin_bottom(create_box, 8);
    gtk_widget_set_margin_start(create_box, 0);
    gtk_widget_set_margin_end(create_box, 0);
    gtk_widget_set_vexpand(create_box, TRUE); 

    // scroll box
    GtkWidget *scrolled_window = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_css_classes(scrolled_window, (const char*[]){"scroll", NULL});
    gtk_widget_set_hexpand(scrolled_window, TRUE); 
    gtk_widget_set_vexpand(scrolled_window, TRUE); 

    // Scroll box content
    GtkWidget *create_content_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(create_content_box, 220, -1); 
    gtk_widget_set_halign(create_content_box, GTK_ALIGN_FILL);
    gtk_widget_set_margin_top(create_content_box, 0);
    gtk_widget_set_margin_bottom(create_content_box, 0);
    gtk_widget_set_margin_start(create_content_box, 0);
    gtk_widget_set_margin_end(create_content_box, 0);
    gtk_widget_set_css_classes(create_content_box, (const char*[]){"user-area", NULL});
    gtk_widget_set_hexpand(create_content_box, TRUE);

    // Title
    GtkWidget *create_server_title_label = gtk_label_new("Create a Server");
    gtk_widget_set_halign(create_server_title_label, GTK_ALIGN_START);
    gtk_widget_set_margin_start(create_server_title_label, 20);
    gtk_widget_set_margin_top(create_server_title_label, 10);
    gtk_widget_set_css_classes(create_server_title_label, (const char *[]){"custom-title", NULL});
    gtk_box_append(GTK_BOX(create_content_box), create_server_title_label);

    // Test scrollbar
    for (int i = 0; i < 50; i++) {
        GtkWidget *test_label = gtk_label_new("Test Line");
        gtk_box_append(GTK_BOX(create_content_box), test_label);
        gtk_widget_set_margin_start(test_label, 25);
        gtk_widget_set_halign(test_label, GTK_ALIGN_START);
    }

    // Add content to scroll box
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), create_content_box);

    // Bottom nav bar
    GtkWidget *bottom_bar = create_bottom_bar(stack, return_to_main_callback);    
    gtk_box_append(GTK_BOX(create_box), scrolled_window);
    gtk_box_append(GTK_BOX(create_box), bottom_bar);

    // Add main box to stack
    gtk_stack_add_named(GTK_STACK(stack), create_box, "create_server");
}