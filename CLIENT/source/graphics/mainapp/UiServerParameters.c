#include <gtk/gtk.h>
#include "graphics/mainapp/UiCreateParameters.h"
#include "graphics/utils/BottomBar.h"
#include "graphics/utils/DisplayPage.h"
#include "network/mainapp/ChannelManager.h"


//Create server parameter content page
void show_server_parameters_content(GtkWidget *stack, GCallback return_to_main_callback) {
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

    //Container for Labels and buttons
    GtkWidget *create_parameter_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(create_parameter_container, container_width, -1);
    gtk_widget_set_halign(create_parameter_container, GTK_ALIGN_CENTER);
    
    // Title
    GtkWidget *create_server_parameters_title = gtk_label_new("Server parameters");
    gtk_widget_set_halign(create_server_parameters_title, GTK_ALIGN_START);
    gtk_widget_set_margin_start(create_server_parameters_title, 0);
    gtk_widget_set_margin_top(create_server_parameters_title, 10);
    gtk_widget_set_css_classes(create_server_parameters_title, (const char *[]){"custom-title", NULL});
    gtk_box_append(GTK_BOX(create_parameter_container), create_server_parameters_title);

    GtkWidget *create_category_label = gtk_label_new("Create a category");
    gtk_widget_set_halign(create_category_label, GTK_ALIGN_START);
    gtk_widget_set_margin_start(create_category_label, 0);
    gtk_widget_set_margin_top(create_category_label, 10);
    gtk_widget_set_css_classes(create_category_label, (const char *[]){"custom-label", NULL});
    gtk_box_append(GTK_BOX(create_parameter_container), create_category_label);

    GtkWidget *create_category_entry = gtk_entry_new();
    gtk_widget_set_size_request(create_category_entry, 200, -1);
    gtk_widget_set_css_classes(create_category_entry, (const char *[]){"custom-entry", NULL});
    gtk_box_append(GTK_BOX(create_parameter_container), create_category_entry);
    
    GtkWidget *create_category_button = gtk_button_new_with_label("ADD A NEW CATEGORY");
    /*g_signal_connect(create_category_button, "clicked", G_CALLBACK(handle_create_category), stack);*/
    gtk_widget_set_css_classes(create_category_button,(const char *[]){"custom-button", NULL});
    gtk_widget_set_margin_top(create_category_button, 5);
    gtk_box_append(GTK_BOX(create_parameter_container), create_category_button);

    GtkWidget *create_channel_label = gtk_label_new("Create a channel");
    gtk_widget_set_halign(create_channel_label, GTK_ALIGN_START);
    gtk_widget_set_margin_start(create_channel_label, 0);
    gtk_widget_set_margin_top(create_channel_label, 10);
    gtk_widget_set_css_classes(create_channel_label, (const char *[]){"custom-label", NULL});
    gtk_box_append(GTK_BOX(create_parameter_container), create_channel_label);

    GtkWidget *create_channel_entry = gtk_entry_new();
    gtk_widget_set_size_request(create_channel_entry, 200, -1);
    gtk_widget_set_css_classes(create_channel_entry, (const char*[]){"custom-entry", NULL});
    gtk_box_append(GTK_BOX(create_parameter_container), create_channel_entry);

    GtkWidget *create_channel_button = gtk_button_new_with_label("ADD A NEW CHANNEL");
    /*g_signal_connect(create_channel_button, "clicked", G_CALLBACK(handle_create_channel), stack);*/
    gtk_widget_set_css_classes(create_channel_button, (const char*[]){"custom-button", NULL});
    gtk_widget_set_margin_top(create_channel_button, 5);
    gtk_box_append(GTK_BOX(create_parameter_container), create_channel_button);
    
    gtk_box_append(GTK_BOX(create_content_box), create_parameter_container);

    // Delete a channel
    // Show the channel dropdown menu and delete button
    GtkWidget *dropdown_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *channel_dropdown = gtk_drop_down_new(NULL, NULL);
    populate_channel_dropdown(GTK_DROP_DOWN(channel_dropdown));

    // Uncomment the thread to fetch channels from the server
    /* 
    g_thread_new("fetch_channels_thread", fetch_channels, channel_dropdown);
    */
    gtk_box_append(GTK_BOX(dropdown_box), channel_dropdown);

    GtkWidget *delete_channel_button = gtk_button_new_with_label("DELETE SELECTED CHANNEL");
    gtk_widget_set_css_classes(delete_channel_button, (const char *[]){"custom-button", NULL});
    gtk_widget_set_margin_top(delete_channel_button, 5); 

    g_signal_connect(delete_channel_button, "clicked", G_CALLBACK(delete_selected_channel), channel_dropdown);
    gtk_box_append(GTK_BOX(dropdown_box), delete_channel_button);

    gtk_box_append(GTK_BOX(create_parameter_container), dropdown_box);

    // Add content to scroll box
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), create_content_box);

    // Bottom nav bar
    GtkWidget *bottom_bar = create_bottom_bar(stack, return_to_main_callback);    
    gtk_box_append(GTK_BOX(create_box), scrolled_window);
    gtk_box_append(GTK_BOX(create_box), bottom_bar);

    // Add main box to stack
    gtk_stack_add_named(GTK_STACK(stack), create_box, "server_parameters");
}