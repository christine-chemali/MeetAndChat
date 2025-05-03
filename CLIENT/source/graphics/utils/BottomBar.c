#include "graphics/utils/BottomBar.h"
#include "graphics/mainapp/UiUserContent.h"
#include "graphics/utils/DisplayPage.h"
#include "graphics/mainapp/UiNotification.h"
#include "graphics/login/UiLogin.h"

//Bottom Bar
GtkWidget *create_bottom_bar(GtkWidget *stack, GCallback return_to_login_callback)
{
    GtkWidget *bottom_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_hexpand(bottom_bar, TRUE);
    gtk_widget_set_margin_top(bottom_bar, 8);
    gtk_widget_set_margin_end(bottom_bar, 8);
    gtk_widget_set_halign(bottom_bar, GTK_ALIGN_END);

    // Home button
    GtkWidget *home_button = gtk_button_new();
    GtkWidget *home_icon = gtk_image_new_from_file("CLIENT/media/icons/home.png");
    gtk_button_set_child(GTK_BUTTON(home_button), home_icon);
    gtk_image_set_pixel_size(GTK_IMAGE(home_icon), 25);
    g_signal_connect(home_button, "clicked", G_CALLBACK(on_home_button_clicked), stack);
    gtk_widget_set_css_classes(home_button, (const char *[]){"icon-button", NULL});

    // Notification button
    GtkWidget *notification_button = gtk_button_new();
    GtkWidget *notification_icon = gtk_image_new_from_file("CLIENT/media/icons/notification.png");
    gtk_button_set_child(GTK_BUTTON(notification_button), notification_icon);
    gtk_image_set_pixel_size(GTK_IMAGE(notification_icon), 25);
    /*g_signal_connect(notification_button, "clicked", return_to_login_callback, stack);*/
    g_signal_connect(notification_button, "clicked", G_CALLBACK(show_notification), stack);
    gtk_widget_set_css_classes(notification_button, (const char *[]){"icon-button", NULL});

    // User button
    GtkWidget *user_button = gtk_button_new();
    GtkWidget *user_icon = gtk_image_new_from_file("CLIENT/media/icons/me.png");
    gtk_button_set_child(GTK_BUTTON(user_button), user_icon);
    gtk_image_set_pixel_size(GTK_IMAGE(user_icon), 25);
    g_signal_connect(user_button, "clicked", G_CALLBACK(show_user), stack);
    gtk_widget_set_css_classes(user_button, (const char *[]){"icon-button", NULL});

    // Disconnect button
    GtkWidget *return_link = gtk_button_new();
    GtkWidget *icon = gtk_image_new_from_file("CLIENT/media/icons/disconnect.png");
    gtk_button_set_child(GTK_BUTTON(return_link), icon);
    g_signal_connect(return_link, "clicked", G_CALLBACK(on_disconnect_button_clicked), stack);
    gtk_widget_set_css_classes(return_link, (const char *[]){"disconnect-button", NULL});

    //Append box
    gtk_box_append(GTK_BOX(bottom_bar), home_button);
    gtk_box_append(GTK_BOX(bottom_bar), notification_button);
    gtk_box_append(GTK_BOX(bottom_bar), user_button);
    gtk_box_append(GTK_BOX(bottom_bar), return_link);

    return bottom_bar;
}