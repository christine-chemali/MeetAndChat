#include <gtk/gtk.h>
#include "UiUserContent.h"
#include "BottomBar.h"


// to display forgot password content page
void show_user_content(GtkWidget *stack, GCallback return_to_main_callback) {
    GtkWidget *user_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(user_box, 20);
    gtk_widget_set_margin_bottom(user_box, 20);
    gtk_widget_set_margin_start(user_box, 20);
    gtk_widget_set_margin_end(user_box, 20);
    
    int container_width = 220;

    //Title
    GtkWidget *user_title_container = gtk_box_new(GTK_ORIENTATION_VERTICAL,0);
    gtk_widget_set_size_request(user_title_container, container_width, -1);
    gtk_widget_set_halign(user_title_container, GTK_ALIGN_CENTER);

    GtkWidget *user_title_label = gtk_label_new("Profile");
    gtk_widget_set_halign(user_title_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(user_title_label, (const char *[]){"custom-title", NULL});


    GtkWidget *return_button = gtk_button_new_with_label("Return to Main");
    g_signal_connect(return_button, "clicked", return_to_main_callback, stack);
    gtk_widget_set_css_classes(return_button, (const char *[]){"link-account-button", NULL});
    gtk_box_append(GTK_BOX(user_box), return_button);

    // Add container to main box
    gtk_box_append(GTK_BOX(user_box), user_title_container);

    // Add bottom bar
    GtkWidget *bottom_bar = create_bottom_bar(stack, return_to_main_callback);    
    gtk_box_append(GTK_BOX(user_box), bottom_bar);
    
    gtk_stack_add_named(GTK_STACK(stack), user_box, "user_profile");
}