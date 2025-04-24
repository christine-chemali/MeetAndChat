
    #include <gtk/gtk.h>
    #include <stdlib.h>

    // to stock data structure
    typedef struct {
        GtkWidget *left_box;
        GtkWidget *stack;
        GList *servers; 
    } AppData;

    // Display channels
    void display_channels_for_server(const char *server_name, AppData *data) {
        //verify if exist
        GtkWidget *existing_page = gtk_stack_get_child_by_name(GTK_STACK(data->stack), server_name);
        if (existing_page) {
            gtk_stack_set_visible_child(GTK_STACK(data->stack), existing_page);
            return;
        }

        GtkWidget *channel_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
        gtk_widget_set_margin_top(channel_box, 20);
        gtk_widget_set_margin_bottom(channel_box, 20);
        gtk_widget_set_margin_start(channel_box, 20);
        gtk_widget_set_margin_end(channel_box, 20);
        gtk_widget_set_halign(channel_box, GTK_ALIGN_START);

        // example of channels
        const char *channels[] = {"Général", "Développement", "Random"};
        for (int i = 0; i < 3; i++) {
            GtkWidget *channel_label = gtk_label_new(channels[i]);
            gtk_widget_set_halign(channel_label, GTK_ALIGN_START);
            gtk_box_append(GTK_BOX(channel_box), channel_label);
        }

        // Display content in the right area
        gtk_stack_add_named(GTK_STACK(data->stack), channel_box, server_name);
        gtk_stack_set_visible_child(GTK_STACK(data->stack), channel_box);
    }

    // when server button clicked
    static void on_server_button_clicked(GtkButton *button, AppData *data) {
        const char *server_name = gtk_button_get_label(button);
        display_channels_for_server(server_name, data);
    }

    // To create the main window
    void show_first_main_content(GtkWidget *stack, GCallback return_to_login_callback) {
        // Main container box
        GtkWidget *main_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        gtk_widget_set_margin_top(main_container, 20);
        gtk_widget_set_margin_bottom(main_container, 20);
        gtk_widget_set_margin_start(main_container, 20);
        gtk_widget_set_margin_end(main_container, 20);

        // left box servers
        AppData *data = malloc(sizeof(AppData));
        if (!data) {
            g_critical("Impossible to allocate data for AppData");
            return;
        }
        *data = (AppData){0};
        data->left_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
        gtk_box_set_homogeneous(GTK_BOX(data->left_box), FALSE);

        // buttons server (THIS HAD TO CHANGE should be created after the server is create)
        for (int i = 1; i <= 3; i++) {
            GtkWidget *server_button = gtk_button_new_with_label(g_strdup_printf("Serveur %d", i));
            g_signal_connect(server_button, "clicked", G_CALLBACK(on_server_button_clicked), data);
            gtk_box_append(GTK_BOX(data->left_box), server_button);
        }
        // add here a button to create a server

        // Right area
        data->stack = gtk_stack_new();
        GtkWidget *scrolled_window = gtk_scrolled_window_new();

        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), data->stack);

        // content_box: hold left and right area
        GtkWidget *content_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        gtk_box_set_homogeneous(GTK_BOX(content_box), FALSE);

        gtk_box_append(GTK_BOX(content_box), data->left_box);
        gtk_box_append(GTK_BOX(content_box), scrolled_window);

        // Bottom bar
        GtkWidget *bottom_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        gtk_widget_set_hexpand(bottom_bar, TRUE);

            //return to login disconnect ?
        GtkWidget *return_link = gtk_button_new_with_label("x");
        g_signal_connect(return_link, "clicked", return_to_login_callback, stack);

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
