#include <gtk/gtk.h>
#include <stdlib.h>
#include "UiMessageList.h"
#include "AppData.h"

void display_messages(GtkStack *stack, const char *server_name) {
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

    gtk_stack_add_named(stack, messages_box, server_name);
    gtk_stack_set_visible_child(stack, messages_box);
}