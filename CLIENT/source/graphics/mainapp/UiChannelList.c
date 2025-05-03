
#include <gtk/gtk.h>
#include <stdlib.h>
#include "graphics/mainapp/UiChannelList.h"
#include "graphics/utils/AppData.h"

   void display_channels(GtkStack *stack, const char *server_name) {
    //main box
    GtkWidget *main_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top(main_container, 20);
    gtk_widget_set_margin_bottom(main_container, 8);
    gtk_widget_set_margin_start(main_container, 8);
    gtk_widget_set_margin_end(main_container, 0);

    // channels box
    GtkWidget *channel_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(channel_box, 20);
    gtk_widget_set_margin_bottom(channel_box, 20);
    gtk_widget_set_margin_start(channel_box, 20);
    gtk_widget_set_margin_end(channel_box, 20);
    gtk_widget_set_halign(channel_box, GTK_ALIGN_START);

    // Scrolled Window
    GtkWidget *scrolled_window = gtk_scrolled_window_new();
    gtk_widget_set_margin_start(scrolled_window, 10);
    gtk_widget_set_css_classes(scrolled_window, (const char*[]){"channel-area", NULL});
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), 
                                 GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_hexpand(scrolled_window, TRUE);
    gtk_widget_set_vexpand(scrolled_window, TRUE);

    // to test
    const char *channels[] = {"Général", "Développement", "Random"};
    for (int i = 0; i < 3; i++) {
        GtkWidget *channel_label = gtk_label_new(channels[i]);
        gtk_widget_set_halign(channel_label, GTK_ALIGN_START);
        gtk_box_append(GTK_BOX(channel_box), channel_label);
    }

    // Test scrollbar
    for (int i = 0; i < 50; i++) {
        GtkWidget *test_label = gtk_label_new("Test Line");
        gtk_box_append(GTK_BOX(channel_box), test_label);
    }

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), channel_box);
    gtk_box_append(GTK_BOX(main_container), scrolled_window);

    gtk_stack_add_named(stack, main_container, server_name);
    gtk_stack_set_visible_child(stack, main_container);
}