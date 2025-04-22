#include <gtk/gtk.h>

// had to change for future action with database
static void handle_create_account_choice(GtkWidget *widget, gpointer data)
{
    GtkWidget *stack = GTK_WIDGET(data);
    g_print("Create account Choice confirmed\n");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "login");
}
// Create account page content
void show_create_account_content(GtkWidget *stack, GCallback return_to_login_callback) {
    GtkWidget *account_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(account_box, 20);
    gtk_widget_set_margin_bottom(account_box, 20);
    gtk_widget_set_margin_start(account_box, 20);
    gtk_widget_set_margin_end(account_box, 20);


    GtkWidget *confirm_button = gtk_button_new_with_label("Confirm");
    g_signal_connect(confirm_button, "clicked", G_CALLBACK(handle_create_account_choice), stack);

    GtkWidget *return_link = gtk_button_new_with_label("Return to Login");
    g_signal_connect(return_link, "clicked", return_to_login_callback, stack);

    gtk_box_append(GTK_BOX(account_box), confirm_button);
    gtk_box_append(GTK_BOX(account_box), return_link);

    gtk_stack_add_named(GTK_STACK(stack), account_box, "create_account");
}