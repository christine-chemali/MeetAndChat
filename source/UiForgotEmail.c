#include <gtk/gtk.h>

// had to change for future action connect with database
static void handle_forgot_email_choice(GtkWidget *widget, gpointer data)
{
    GtkWidget *stack = GTK_WIDGET(data);
    g_print("Email Choice confirmed\n");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "login");
}
// forgot email page content
void show_forgot_email_content(GtkWidget *stack, GCallback return_to_login_callback) {
    GtkWidget *forgot_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(forgot_box, 20);
    gtk_widget_set_margin_bottom(forgot_box, 20);
    gtk_widget_set_margin_start(forgot_box, 20);
    gtk_widget_set_margin_end(forgot_box, 20);

    GtkWidget *change_email_radio = gtk_check_button_new_with_label("Change email");

    GtkWidget *confirm_button = gtk_button_new_with_label("Confirm");
    g_signal_connect(confirm_button, "clicked", G_CALLBACK(handle_forgot_email_choice), stack);

    GtkWidget *return_link = gtk_button_new_with_label("Return to Login");
    g_signal_connect(return_link, "clicked", return_to_login_callback, stack);

    gtk_box_append(GTK_BOX(forgot_box), change_email_radio);
    gtk_box_append(GTK_BOX(forgot_box), confirm_button);
    gtk_box_append(GTK_BOX(forgot_box), return_link);

    gtk_stack_add_named(GTK_STACK(stack), forgot_box, "forgot_email");
}