#include "graphics/utils/TopBar.h"


static void switch_to_server_page(GtkWidget *button, GtkWidget *stack) {
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "create_server");
}

static void switch_to_parameters_page(GtkWidget *button, GtkWidget *stack) {
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "server_parameters");
}

static void switch_to_category_page(GtkWidget *button, GtkWidget *stack) {
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "create_category");
}

GtkWidget* create_top_bar(GtkWidget *stack) {

    GtkWidget *top_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_margin_top(top_bar, 10);
    gtk_widget_set_margin_bottom(top_bar, 10);
    
    GtkWidget *buttons_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10); 
    gtk_widget_set_hexpand(buttons_box, TRUE);
    gtk_widget_set_halign(buttons_box, GTK_ALIGN_END); 
    gtk_widget_set_css_classes(buttons_box, (const char*[]){"top-bar", NULL}); 
    
    GtkWidget *server_button = gtk_button_new();
    GtkWidget *server_icon = gtk_image_new_from_file("CLIENT/media/icons/server.png");
    gtk_button_set_child(GTK_BUTTON(server_button), server_icon);
    
    GtkWidget *category_icon_button = gtk_button_new();
    GtkWidget *category_icon = gtk_image_new_from_file("CLIENT/media/icons/category.png");
    gtk_button_set_child(GTK_BUTTON(category_icon_button), category_icon);

    GtkWidget *channel_button = gtk_button_new();
    GtkWidget *channel_icon = gtk_image_new_from_file("CLIENT/media/icons/channel.png");
    gtk_button_set_child(GTK_BUTTON(channel_button), channel_icon);
    
    gtk_widget_set_css_classes(server_button, (const char*[]){"icon-button", NULL});
    gtk_widget_set_css_classes(category_icon_button, (const char*[]){"icon-button", NULL});
    gtk_widget_set_css_classes(channel_button, (const char*[]){"icon-button", NULL});
    
    g_signal_connect(server_button, "clicked", G_CALLBACK(switch_to_server_page), stack);
    g_signal_connect(category_icon_button, "clicked", G_CALLBACK(switch_to_category_page), stack);
    g_signal_connect(channel_button, "clicked", G_CALLBACK(switch_to_parameters_page), stack);
    
    gtk_widget_set_margin_end(buttons_box, 5);
    
    gtk_box_append(GTK_BOX(buttons_box), server_button);
    gtk_box_append(GTK_BOX(buttons_box), category_icon_button);
    gtk_box_append(GTK_BOX(buttons_box), channel_button);

    gtk_box_append(GTK_BOX(top_bar), buttons_box);
    
    return top_bar;
}