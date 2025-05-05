#include <gtk/gtk.h>
#include <stdlib.h>
#include "graphics/mainapp/UiCreateServer.h"
#include "graphics/utils/AppData.h"
#include "graphics/mainapp/UiUserContent.h"
#include "graphics/mainapp/UiMessageList.h"
#include "graphics/mainapp/UiChannelList.h"
#include "graphics/utils/BottomBar.h"
#include "graphics/utils/DisplayPage.h"
#include "graphics/mainapp/UiNetwork.h"
#include "graphics/mainapp/UiNotification.h"
#include "network/handlenetwork/NetworkHandlers.h"


// Display channels and messages
void display_channels_for_server(const char *server_name, AppData *data) {
    const char *page_name = (strcmp(server_name, "Messages") == 0) ? "messages_window" : server_name;
    
    GtkWidget *existing_page = gtk_stack_get_child_by_name(GTK_STACK(data->stack), page_name);
    if (existing_page) {
        gtk_stack_set_visible_child(GTK_STACK(data->stack), existing_page);
        return;
    }

    if (strcmp(server_name, "Messages") == 0) {
        display_messages(GTK_STACK(data->stack));
    } else {
        display_channels(GTK_STACK(data->stack), server_name);
    }
}

// Callback function when a server or message button is clicked
static void on_server_button_clicked(GtkButton *button, AppData *data) {
    const char *button_name = gtk_widget_get_name(GTK_WIDGET(button));
    
    // Display channels for the server
    display_channels_for_server(button_name, data);
}

// Function to show the main content after login
void show_first_main_content(GtkWidget *stack, GCallback return_to_login_callback) {
    // Create main container
    GtkWidget *main_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top(main_container, 20);
    gtk_widget_set_margin_bottom(main_container, 8);
    gtk_widget_set_margin_start(main_container, 8);
    gtk_widget_set_margin_end(main_container, 0);

    // Initialize AppData
    AppData *data = malloc(sizeof(AppData));
    if (!data) {
        g_critical("Failed to allocate memory for AppData");
        return;
    }
    *data = (AppData){0};
    data->left_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_box_set_homogeneous(GTK_BOX(data->left_box), FALSE);
    gtk_widget_set_margin_top(data->left_box, 5);

    // Message button
    GtkWidget *message_button = gtk_button_new();
    GtkWidget *message_icon = gtk_image_new_from_file("CLIENT/media/icons/message.png");
    gtk_image_set_pixel_size(GTK_IMAGE(message_icon), 25); 
    gtk_button_set_child(GTK_BUTTON(message_button), message_icon); 
    gtk_widget_set_css_classes(message_button, (const char *[]){"icon-button", NULL});
    gtk_widget_set_name(message_button, "Messages");  
    g_signal_connect(message_button, "clicked", G_CALLBACK(on_server_button_clicked), data);
    gtk_box_append(GTK_BOX(data->left_box), message_button);

    // Server buttons
    for (int i = 1; i <= 3; i++) {
        GtkWidget *server_button = gtk_button_new_with_label(g_strdup_printf("S%d", i));
        gtk_widget_set_css_classes(server_button, (const char *[]){"server-button", NULL});
        g_signal_connect(server_button, "clicked", G_CALLBACK(on_server_button_clicked), data);
        gtk_box_append(GTK_BOX(data->left_box), server_button);
    }

    // Create Server Button
    GtkWidget *create_button = gtk_button_new();
    GtkWidget *create_icon = gtk_image_new_from_file("CLIENT/media/icons/add.png");
    gtk_button_set_child(GTK_BUTTON(create_button), create_icon); 
    gtk_image_set_pixel_size(GTK_IMAGE(create_icon), 25); 
    g_signal_connect(create_button, "clicked", G_CALLBACK(show_create), stack);
    gtk_widget_set_css_classes(create_button, (const char *[]){"icon-button", NULL}); //css
    gtk_box_append(GTK_BOX(data->left_box), create_button);

    // Network button
    GtkWidget *network_button = gtk_button_new();
    GtkWidget *network_icon = gtk_image_new_from_file("CLIENT/media/icons/network.png");
    gtk_button_set_child(GTK_BUTTON(network_button), network_icon); 
    gtk_image_set_pixel_size(GTK_IMAGE(network_icon), 25); 
    g_signal_connect(network_button, "clicked", G_CALLBACK(show_network_content), data);
    gtk_widget_set_css_classes(network_button, (const char *[]){"icon-button", NULL});
    gtk_box_append(GTK_BOX(data->left_box), network_button);

    // Right area (stack for channels)
    data->stack = gtk_stack_new();
    GtkWidget *scrolled_window = gtk_scrolled_window_new();

    gtk_widget_set_margin_start(scrolled_window, 10);
    gtk_widget_set_css_classes(scrolled_window, (const char*[]){"channel-area", NULL});
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_NEVER, GTK_POLICY_NEVER);
    gtk_widget_set_hexpand(scrolled_window, TRUE); 
    gtk_widget_set_vexpand(scrolled_window, TRUE); 

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), data->stack);

    // Content box: hold left and right area
    GtkWidget *content_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_set_homogeneous(GTK_BOX(content_box), FALSE);

    gtk_box_append(GTK_BOX(content_box), data->left_box);
    gtk_box_append(GTK_BOX(content_box), scrolled_window);

    // Add containers to main container
    gtk_box_append(GTK_BOX(main_container), content_box);

    // Bottom bar
    GtkWidget *bottom_bar = create_bottom_bar(stack, return_to_login_callback);
    gtk_box_append(GTK_BOX(main_container), bottom_bar);

    // Show user content
    show_create_server_content(stack, G_CALLBACK(show_main));
    show_notification_content(stack, G_CALLBACK(show_main));
    show_user_content(stack, G_CALLBACK(show_main));

    // Add main container to stack
    gtk_stack_add_named(GTK_STACK(stack), main_container, "main_window");
    gtk_stack_set_visible_child(GTK_STACK(stack), main_container);
}
