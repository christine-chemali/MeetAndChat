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

    int container_width = 220;
    // User identification
    GtkWidget *identify_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_size_request(identify_container, container_width, -1);
    gtk_widget_set_halign(identify_container, GTK_ALIGN_CENTER);

    GtkWidget *first_name_label = gtk_label_new("First Name*:");
    gtk_widget_set_halign(first_name_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(first_name_label, (const char *[]){"custom-label", NULL});//css

    GtkWidget *first_name_entry = gtk_entry_new();
    gtk_widget_set_size_request(first_name_entry, 200, -1);
    gtk_widget_set_css_classes(first_name_entry, (const char *[]){"custom-entry",NULL});//css

    GtkWidget *last_name_label = gtk_label_new("Last Name*:");
    gtk_widget_set_halign(last_name_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(last_name_label, (const char *[]){"custom-label", NULL}); //css

    GtkWidget *last_name_entry = gtk_entry_new();
    gtk_widget_set_size_request(last_name_entry, 200, -1);
    gtk_widget_set_css_classes(last_name_entry, (const char *[]){"custom-entry", NULL});//css

    GtkWidget *username_label = gtk_label_new("Username*:");
    gtk_widget_set_halign(username_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(username_label, (const char *[]){"custom-label", NULL});//css

    GtkWidget *username_entry = gtk_entry_new();
    gtk_widget_set_size_request(username_entry, 200, -1);
    gtk_widget_set_css_classes(username_entry, (const char *[]){"custom-entry", NULL});//css

    gtk_box_append(GTK_BOX(identify_container), first_name_label);
    gtk_box_append(GTK_BOX(identify_container), first_name_entry);
    gtk_box_append(GTK_BOX(identify_container), last_name_label);
    gtk_box_append(GTK_BOX(identify_container), last_name_entry);
    gtk_box_append(GTK_BOX(identify_container), username_label);
    gtk_box_append(GTK_BOX(identify_container), username_entry);

    // Buttons : Get started and return
    GtkWidget *action_button_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_size_request(action_button_container, container_width, -1);
    gtk_widget_set_halign(action_button_container, GTK_ALIGN_CENTER);

    GtkWidget *confirm_button = gtk_button_new_with_label("REGISTER");
    g_signal_connect(confirm_button, "clicked", G_CALLBACK(handle_create_account_choice), stack);
    gtk_widget_set_css_classes(confirm_button, (const char *[]){"custom-button", NULL}); //css
    gtk_widget_set_margin_top(confirm_button, 5);

    GtkWidget *return_link = gtk_button_new_with_label("Return to Login");
    g_signal_connect(return_link, "clicked", return_to_login_callback, stack);
    gtk_widget_set_css_classes(return_link,(const char *[]){"link-account-button", NULL}); //css
    gtk_widget_set_margin_top(return_link, 5);

    gtk_box_append(GTK_BOX(action_button_container), confirm_button);
    gtk_box_append(GTK_BOX(action_button_container), return_link);
    
    //Add containers to main box
    gtk_box_append(GTK_BOX(account_box), identify_container);
    gtk_box_append(GTK_BOX(account_box), action_button_container);


    gtk_stack_add_named(GTK_STACK(stack), account_box, "create_account");
}