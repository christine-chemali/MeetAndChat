#include <gtk/gtk.h>
#include <stdlib.h>
#include "graphics/mainapp/UiChannelList.h"
#include "graphics/utils/AppData.h"

void display_channels(GtkStack *stack, const char *server_name) {
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
        // Test scrollbar
        for (int i = 0; i < 50; i++) {
        GtkWidget *test_label = gtk_label_new("Test Line");
        gtk_box_append(GTK_BOX(channel_box), test_label);
    }
    gtk_stack_add_named(stack, channel_box, server_name);
    gtk_stack_set_visible_child(stack, channel_box);
}