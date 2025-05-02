#include <gtk/gtk.h>
#include "graphics/mainapp/UiCreateParameters.h"
#include "graphics/utils/BottomBar.h"
#include "graphics/utils/DisplayPage.h"
#include "network/mainapp/ChannelManager.h"
#include "graphics/utils/TopBar.h"


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

    // Top bar
    GtkWidget *top_bar = create_top_bar(stack);
    gtk_box_append(GTK_BOX(create_parameter_container), top_bar);
    
    // Title
    GtkWidget *create_server_parameters_title = gtk_label_new("Set up a channel");
    gtk_widget_set_halign(create_server_parameters_title, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(create_server_parameters_title, 0);
    gtk_widget_set_margin_top(create_server_parameters_title, 5);
    gtk_widget_set_css_classes(create_server_parameters_title, (const char *[]){"custom-title", NULL});
    gtk_box_append(GTK_BOX(create_parameter_container), create_server_parameters_title);

    // CHANNEL
    //Create a channel label
    GtkWidget *create_channel_label = gtk_label_new("CREATE A CHANNEL");
    gtk_widget_set_halign(create_channel_label, GTK_ALIGN_START);
    gtk_widget_set_margin_start(create_channel_label, 0);
    gtk_widget_set_margin_top(create_channel_label, 5);
    gtk_widget_set_css_classes(create_channel_label, (const char *[]){"custom-label-title", NULL});
    
    // Delete a channel label
    GtkWidget *delete_channel_label = gtk_label_new("DELETE A CHANNEL");
    gtk_widget_set_halign(delete_channel_label, GTK_ALIGN_START);
    gtk_widget_set_margin_start(delete_channel_label, 0);
    gtk_widget_set_margin_top(delete_channel_label, 5);
    gtk_widget_set_css_classes(delete_channel_label, (const char *[]){"custom-label-title", NULL});
    
    // Channel dropdown list
    GtkWidget *dropdown_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *channel_dropdown = gtk_drop_down_new(NULL, NULL);
    populate_channel_dropdown(GTK_DROP_DOWN(channel_dropdown));

    // Uncomment the thread to fetch channels from the server
   // g_thread_new("fetch_channels_thread", fetch_channels, channel_dropdown);

    //Create a channel entry
    GtkWidget *create_channel_entry = gtk_entry_new();
    gtk_widget_set_size_request(create_channel_entry, 200, -1);
    g_object_set_data(G_OBJECT(create_channel_entry), "dropdown", channel_dropdown);
    gtk_entry_set_placeholder_text(GTK_ENTRY(create_channel_entry), "Channel name");
    gtk_widget_set_css_classes(create_channel_entry, (const char*[]){"custom-entry", NULL});

    // Channel Type Section
    GtkWidget *channel_type_label = gtk_label_new("Channel type");
    gtk_widget_set_halign(channel_type_label, GTK_ALIGN_START);
    //gtk_widget_set_margin_top(channel_type_label, 5);
    gtk_widget_set_css_classes(channel_type_label, (const char*[]){"custom-label-title", NULL});

    // Text Channel Box
    GtkWidget *text_channel_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_set_margin_top(text_channel_box, 5);

    // Text Channel Icon (#)
    GtkWidget *text_channel_icon = gtk_image_new_from_file("CLIENT/media/icons/hashtag.png");
    gtk_widget_set_size_request(text_channel_icon, 24, 24);

    // Text Channel Info Box
    GtkWidget *text_info_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    GtkWidget *text_label = gtk_label_new("Text");
    gtk_widget_set_halign(text_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(text_label, (const char*[]){"custom-sublabel", NULL});

    GtkWidget *text_description = gtk_label_new("Send messages, share\nfiles, and communicate.");
    gtk_label_set_wrap(GTK_LABEL(text_description), TRUE);
    gtk_widget_set_size_request(text_description, 100, -1);
    gtk_widget_set_halign(text_description, GTK_ALIGN_START);

    // Text Radio Button
    GtkWidget *text_radio = gtk_check_button_new();
    gtk_check_button_set_active(GTK_CHECK_BUTTON(text_radio), TRUE);
    gtk_widget_set_margin_start(text_radio, 40);
    gtk_widget_set_halign(text_radio, GTK_ALIGN_END);

    // Voice Channel Box
    GtkWidget *voice_channel_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_set_margin_top(voice_channel_box, 5);

    // Voice Channel Icon
    GtkWidget *voice_channel_icon = gtk_image_new_from_file("CLIENT/media/icons/voice.png");
    gtk_widget_set_size_request(voice_channel_icon, 24, 24);

    // Voice Channel Info Box
    GtkWidget *voice_info_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    GtkWidget *voice_label = gtk_label_new("Voice");
    gtk_widget_set_halign(voice_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(voice_label, (const char*[]){"custom-sublabel", NULL});

    GtkWidget *voice_description = gtk_label_new("Join voice calls and share\nyour screen in real-time.");
    gtk_label_set_wrap(GTK_LABEL(voice_description), TRUE);
    gtk_widget_set_size_request(voice_description, 100, -1);
    gtk_widget_set_halign(voice_description, GTK_ALIGN_START);
    
    // Voice Radio Button
    GtkWidget *voice_radio = gtk_check_button_new();
    gtk_check_button_set_group(GTK_CHECK_BUTTON(voice_radio), GTK_CHECK_BUTTON(text_radio));
    gtk_widget_set_margin_start(voice_radio, 35);

    // Private Channel Box
    GtkWidget *private_channel_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    // Private Channel Description
    GtkWidget *private_description = gtk_label_new("Private channels can only be viewed and\naccessed by selected members and roles.");
    gtk_label_set_wrap(GTK_LABEL(private_description), TRUE);
    gtk_widget_set_size_request(private_description, 100, -1);
    gtk_widget_set_halign(private_description, GTK_ALIGN_START);
    gtk_widget_set_margin_top(private_description, 5);

    // Private Toggle Box
    GtkWidget *private_toggle_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);

    // Private Channel Icon
    GtkWidget *private_channel_icon = gtk_image_new_from_file("CLIENT/media/icons/lock.png");
    gtk_widget_set_size_request(private_channel_icon, 24, 24);
    
    // Private Channel Label
    GtkWidget *private_label = gtk_label_new("Private Channel");
    gtk_widget_set_halign(private_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(private_label, (const char*[]){"custom-sublabel", NULL});

    // Private Toggle Switch
    GtkWidget *private_switch = gtk_switch_new();
    gtk_widget_set_margin_start(private_switch, 50);
    gtk_widget_set_css_classes(private_switch, (const char*[]){"small-switch", NULL});

    // Create a channel button
    GtkWidget *create_channel_button = gtk_button_new_with_label("ADD A NEW CHANNEL");
    g_signal_connect(create_channel_button, "clicked", G_CALLBACK(handle_create_channel), create_channel_entry); 
    gtk_widget_set_css_classes(create_channel_button, (const char*[]){"custom-button", NULL});
    gtk_widget_set_margin_top(create_channel_button, 5);
    
    //Delete channel button
    GtkWidget *delete_channel_button = gtk_button_new_with_label("DELETE THE SELECTED CHANNEL");
    gtk_widget_set_css_classes(delete_channel_button, (const char *[]){"custom-button", NULL});
    gtk_widget_set_margin_top(delete_channel_button, 5); 

    g_signal_connect(delete_channel_button, "clicked", G_CALLBACK(delete_selected_channel), channel_dropdown);

    //Append channel label and entry
    gtk_box_append(GTK_BOX(create_parameter_container), create_channel_label);
    gtk_box_append(GTK_BOX(create_parameter_container), create_channel_entry);

    // Append all elements

    gtk_box_append(GTK_BOX(text_info_box), text_label);
    gtk_box_append(GTK_BOX(text_info_box), text_description);

    gtk_box_append(GTK_BOX(text_channel_box), text_channel_icon);
    gtk_box_append(GTK_BOX(text_channel_box), text_info_box);
    gtk_box_append(GTK_BOX(text_channel_box), text_radio);

    gtk_box_append(GTK_BOX(voice_info_box), voice_label);
    gtk_box_append(GTK_BOX(voice_info_box), voice_description);

    gtk_box_append(GTK_BOX(voice_channel_box), voice_channel_icon);
    gtk_box_append(GTK_BOX(voice_channel_box), voice_info_box);
    gtk_box_append(GTK_BOX(voice_channel_box), voice_radio);

    gtk_box_append(GTK_BOX(private_toggle_box), private_channel_icon);
    gtk_box_append(GTK_BOX(private_toggle_box), private_label);
    gtk_box_append(GTK_BOX(private_toggle_box), private_switch);

    gtk_box_append(GTK_BOX(private_channel_box), private_description);
    gtk_box_append(GTK_BOX(private_channel_box), private_toggle_box);

    // Add to main container
    gtk_box_append(GTK_BOX(create_parameter_container), channel_type_label);
    gtk_box_append(GTK_BOX(create_parameter_container), text_channel_box);
    gtk_box_append(GTK_BOX(create_parameter_container), voice_channel_box);
    gtk_box_append(GTK_BOX(create_parameter_container), private_channel_box);

    // append box

    gtk_box_append(GTK_BOX(create_parameter_container), create_channel_button);
    gtk_box_append(GTK_BOX(create_content_box), create_parameter_container);
    gtk_box_append(GTK_BOX(create_parameter_container), delete_channel_label);
    gtk_box_append(GTK_BOX(dropdown_box), channel_dropdown);
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