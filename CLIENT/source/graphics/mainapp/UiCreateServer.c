#include <gtk/gtk.h>
#include "graphics/mainapp/UiCreateServer.h"
#include "graphics/utils/BottomBar.h"
#include "graphics/utils/DisplayPage.h"
#include "graphics/mainapp/UiCreateParameters.h"
#include "graphics/mainapp/UiCreateCategory.h" 
#include "graphics/utils/TopBar.h"

//Create a server content page
void show_create_server_content(GtkWidget *stack, GCallback return_to_main_callback) {
    // main box
    GtkWidget *create_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top(create_box, 0);
    gtk_widget_set_margin_bottom(create_box, 8);
    gtk_widget_set_margin_start(create_box, 0);
    gtk_widget_set_margin_end(create_box, 0);
    
    int container_width = 220;

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

    // Container for labels and buttons    
    GtkWidget *parameter_container = gtk_box_new(GTK_ORIENTATION_VERTICAL,5);
    gtk_widget_set_size_request(parameter_container, container_width, -1);
    gtk_widget_set_halign(parameter_container, GTK_ALIGN_CENTER);

    // Top bar
    GtkWidget *top_bar = create_top_bar(stack);
    gtk_box_append(GTK_BOX(parameter_container), top_bar);

    // Title
    GtkWidget *create_server_title_label = gtk_label_new("Set up a server");
    gtk_widget_set_halign(create_server_title_label, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(create_server_title_label, 0);
    gtk_widget_set_margin_top(create_server_title_label, 10);
    gtk_widget_set_css_classes(create_server_title_label, (const char *[]){"custom-title", NULL});
    gtk_box_append(GTK_BOX(parameter_container), create_server_title_label);

    //label
    GtkWidget *create_server_label = gtk_label_new("CREATE A SERVER");
    gtk_widget_set_halign(create_server_label, GTK_ALIGN_START);
    gtk_widget_set_margin_start(create_server_label, 0);
    gtk_widget_set_margin_top(create_server_label, 10);
    gtk_widget_set_css_classes(create_server_label, (const char *[]){"custom-label-title", NULL});
    gtk_box_append(GTK_BOX(parameter_container), create_server_label);

    //entry
    GtkWidget *create_server_entry = gtk_entry_new();
    gtk_widget_set_size_request(create_server_entry, 200, -1);
    gtk_entry_set_placeholder_text(GTK_ENTRY(create_server_entry), "Server name");
    gtk_widget_set_css_classes(create_server_entry, (const char *[]){"custom-entry", NULL});
    gtk_box_append(GTK_BOX(parameter_container), create_server_entry);
    
    //button
    GtkWidget *create_server_button = gtk_button_new_with_label("LAUNCH THE NEW SERVER");
   // g_signal_connect(create_server_button, "clicked", G_CALLBACK(show_parameters), stack); //TODO : change the function
    gtk_widget_set_css_classes(create_server_button,(const char *[]){"custom-button", NULL});
    gtk_widget_set_margin_top(create_server_button, 5);
    gtk_box_append(GTK_BOX(parameter_container), create_server_button);

    gtk_box_append(GTK_BOX(create_content_box),parameter_container);

    // Add content to scroll box
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), create_content_box);

    // Bottom nav bar
    GtkWidget *bottom_bar = create_bottom_bar(stack, return_to_main_callback);    
    gtk_box_append(GTK_BOX(create_box), scrolled_window);
    gtk_box_append(GTK_BOX(create_box), bottom_bar);

    // Show server parameters
    show_server_parameters_content(stack, G_CALLBACK(show_main));
    show_create_category_content(stack, G_CALLBACK(show_main));

    // Add main box to stack
    gtk_stack_add_named(GTK_STACK(stack), create_box, "create_server");
}