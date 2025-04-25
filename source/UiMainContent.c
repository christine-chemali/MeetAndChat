
    #include <gtk/gtk.h>
    #include <stdlib.h>
    #include "UiCreateServer.h"
    #include "AppData.h"

    // Display channels
    void display_channels_for_server(const char *server_name, AppData *data) {
        GtkWidget *existing_page = gtk_stack_get_child_by_name(GTK_STACK(data->stack), server_name);
        if (existing_page) {
            gtk_stack_set_visible_child(GTK_STACK(data->stack), existing_page);
            return;
        }

        if (strcmp(server_name, "Messages") == 0) {
            // Create a list of private conversations
            GtkWidget *messages_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
            gtk_widget_set_margin_top(messages_box, 20);
            gtk_widget_set_margin_bottom(messages_box, 20);
            gtk_widget_set_margin_start(messages_box, 20);
            gtk_widget_set_margin_end(messages_box, 20);
            gtk_widget_set_halign(messages_box, GTK_ALIGN_START);

            // Example of the user private interlocutor
            const char *conversations[] = {"User1", "User2", "User3"};
            for (int i = 0; i < 3; i++) {
                GtkWidget *conv_label = gtk_label_new(conversations[i]);
                gtk_widget_set_halign(conv_label, GTK_ALIGN_START);
                gtk_box_append(GTK_BOX(messages_box), conv_label);
            }

            gtk_stack_add_named(GTK_STACK(data->stack), messages_box, server_name);
            gtk_stack_set_visible_child(GTK_STACK(data->stack), messages_box);
        } else {
            // Existing server channels display code
            GtkWidget *channel_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
            gtk_widget_set_margin_top(channel_box, 20);
            gtk_widget_set_margin_bottom(channel_box, 20);
            gtk_widget_set_margin_start(channel_box, 20);
            gtk_widget_set_margin_end(channel_box, 20);
            gtk_widget_set_halign(channel_box, GTK_ALIGN_START);

            const char *channels[] = {"Général", "Développement", "Random"};
            for (int i = 0; i < 3; i++) {
                GtkWidget *channel_label = gtk_label_new(channels[i]);
                gtk_widget_set_halign(channel_label, GTK_ALIGN_START);
                gtk_box_append(GTK_BOX(channel_box), channel_label);
            }

            gtk_stack_add_named(GTK_STACK(data->stack), channel_box, server_name);
            gtk_stack_set_visible_child(GTK_STACK(data->stack), channel_box);
        }
    }

    // when server or message button clicked
    static void on_server_button_clicked(GtkButton *button, AppData *data) {
        const char *button_name = gtk_widget_get_name(GTK_WIDGET(button));
        display_channels_for_server(button_name, data);
    }

    // To create the main window
    void show_first_main_content(GtkWidget *stack, GCallback return_to_login_callback) {
        // Main container box
        GtkWidget *main_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        gtk_widget_set_margin_top(main_container, 20);
        gtk_widget_set_margin_bottom(main_container, 8);
        gtk_widget_set_margin_start(main_container, 8);
        gtk_widget_set_margin_end(main_container, 0);

        // left box servers
        AppData *data = malloc(sizeof(AppData));
        if (!data) {
            g_critical("Impossible to allocate data for AppData");
            return;
        }
        *data = (AppData){0};
        data->left_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
        gtk_box_set_homogeneous(GTK_BOX(data->left_box), FALSE);
        gtk_widget_set_margin_top(data->left_box, 5);

        // Message button
        GtkWidget *message_button = gtk_button_new();
        GtkWidget *message_icon = gtk_image_new_from_file("./media/icons/message.png");
        gtk_image_set_pixel_size(GTK_IMAGE(message_icon), 25); 
        gtk_button_set_child(GTK_BUTTON(message_button), message_icon); 
        gtk_widget_set_css_classes(message_button, (const char *[]){"icon-button", NULL});
        gtk_widget_set_name(message_button, "Messages");  
        g_signal_connect(message_button, "clicked", G_CALLBACK(on_server_button_clicked), data);
        gtk_box_append(GTK_BOX(data->left_box), message_button);

        // buttons server (THIS HAD TO CHANGE should be created after the server is create)
        for (int i = 1; i <= 3; i++) {
            GtkWidget *server_button = gtk_button_new_with_label(g_strdup_printf("S%d", i));
            gtk_widget_set_css_classes(server_button, (const char *[]){"server-button", NULL});
            g_signal_connect(server_button, "clicked", G_CALLBACK(on_server_button_clicked), data);
            gtk_box_append(GTK_BOX(data->left_box), server_button);
        }
        // create a server
        GtkWidget *create_button = gtk_button_new();
        GtkWidget *create_icon = gtk_image_new_from_file("./media/icons/add.png");
        gtk_button_set_child(GTK_BUTTON(create_button), create_icon); 
        gtk_image_set_pixel_size(GTK_IMAGE(create_icon), 25); 
        g_signal_connect(create_button, "clicked", G_CALLBACK(show_create_server_content), data);
        gtk_widget_set_css_classes(create_button, (const char *[]){"icon-button", NULL}); //css
        gtk_box_append(GTK_BOX(data->left_box), create_button);

        // network
        GtkWidget *network_button = gtk_button_new();
        GtkWidget *network_icon = gtk_image_new_from_file("./media/icons/network.png");
        gtk_button_set_child(GTK_BUTTON(network_button), network_icon); 
        gtk_image_set_pixel_size(GTK_IMAGE(network_icon), 25); 
        g_signal_connect(network_button, "clicked", G_CALLBACK(return_to_login_callback), stack); // change here
        gtk_widget_set_css_classes(network_button, (const char *[]){"icon-button", NULL}); //css
        gtk_box_append(GTK_BOX(data->left_box), network_button);

        // Right area
        data->stack = gtk_stack_new();
        GtkWidget *scrolled_window = gtk_scrolled_window_new();

        gtk_widget_set_margin_start(scrolled_window, 10);
        gtk_widget_set_css_classes(scrolled_window, (const char*[]){"channel-area", NULL});
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), data->stack);

        // content_box: hold left and right area
        GtkWidget *content_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        gtk_box_set_homogeneous(GTK_BOX(content_box), FALSE);

        gtk_box_append(GTK_BOX(content_box), data->left_box);
        gtk_box_append(GTK_BOX(content_box), scrolled_window);

        // Bottom bar
        GtkWidget *bottom_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_set_hexpand(bottom_bar, TRUE);
        gtk_widget_set_margin_top(bottom_bar, 8);
        gtk_widget_set_margin_end(bottom_bar, 8);
        gtk_widget_set_halign(bottom_bar, GTK_ALIGN_END);

        // home button
        GtkWidget *home_button = gtk_button_new();
        GtkWidget *home_icon = gtk_image_new_from_file("./media/icons/home.png");
        gtk_button_set_child(GTK_BUTTON(home_button), home_icon); 
        gtk_image_set_pixel_size(GTK_IMAGE(home_icon), 25); 
        g_signal_connect(home_button, "clicked", G_CALLBACK(return_to_login_callback), stack); 
        gtk_widget_set_css_classes(home_button, (const char *[]){"icon-button", NULL}); //css

        // notification button
        GtkWidget *notification_button = gtk_button_new();
        GtkWidget *notification_icon = gtk_image_new_from_file("./media/icons/notification.png");
        gtk_button_set_child(GTK_BUTTON(notification_button), notification_icon); 
        gtk_image_set_pixel_size(GTK_IMAGE(notification_icon), 25); 
        g_signal_connect(notification_button, "clicked", G_CALLBACK(return_to_login_callback), stack); 
        gtk_widget_set_css_classes(notification_button, (const char *[]){"icon-button", NULL}); //css

        // User button
        GtkWidget *user_button = gtk_button_new();
        GtkWidget *user_icon = gtk_image_new_from_file("./media/icons/me.png");
        gtk_button_set_child(GTK_BUTTON(user_button), user_icon); 
        gtk_image_set_pixel_size(GTK_IMAGE(user_icon), 25); 
        g_signal_connect(user_button, "clicked", G_CALLBACK(return_to_login_callback), stack);
        gtk_widget_set_css_classes(user_button, (const char *[]){"icon-button", NULL}); //css

        // Disconnect button
        GtkWidget *return_link = gtk_button_new();
        GtkWidget *icon = gtk_image_new_from_file("./media/icons/disconnect.png");
        gtk_button_set_child(GTK_BUTTON(return_link), icon); 
        g_signal_connect(return_link, "clicked", G_CALLBACK(return_to_login_callback), stack);
        gtk_widget_set_css_classes(return_link, (const char *[]){"disconnect-button", NULL}); //css

        gtk_box_append(GTK_BOX(bottom_bar), home_button);
        gtk_box_append(GTK_BOX(bottom_bar), notification_button);
        gtk_box_append(GTK_BOX(bottom_bar), user_button);
        gtk_box_append(GTK_BOX(bottom_bar), return_link);

        //add containers to main container
        gtk_box_append(GTK_BOX(main_container), content_box);
        gtk_box_append(GTK_BOX(main_container), bottom_bar);

        gtk_widget_set_hexpand(scrolled_window, TRUE);
        gtk_widget_set_vexpand(scrolled_window, TRUE);

        // Add main container to stack
        gtk_stack_add_named(GTK_STACK(stack), main_container, "main_window");
        gtk_stack_set_visible_child(GTK_STACK(stack), main_container);
    }
