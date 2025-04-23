#include <gtk/gtk.h>

// had to change for future action connect database
static void handle_forgot_password(GtkWidget *widget, gpointer data)
{
    GtkWidget *stack = GTK_WIDGET(data);
    g_print("Choice confirmed\n");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "login");
}
// to display forgot password content page
void show_forgot_password_content(GtkWidget *stack, GCallback return_to_login_callback) {
    GtkWidget *forgot_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(forgot_box, 20);
    gtk_widget_set_margin_bottom(forgot_box, 20);
    gtk_widget_set_margin_start(forgot_box, 20);
    gtk_widget_set_margin_end(forgot_box, 20);
    
    int container_width = 220;

    //Title
    GtkWidget *change_password_title_container = gtk_box_new(GTK_ORIENTATION_VERTICAL,0);
    gtk_widget_set_size_request(change_password_title_container, container_width, -1);
    gtk_widget_set_halign(change_password_title_container, GTK_ALIGN_CENTER);

    GtkWidget *change_password_title_label = gtk_label_new("RESET");
    gtk_widget_set_halign(change_password_title_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(change_password_title_label, (const char *[]){"custom-title", NULL});

    GtkWidget *change_password_text_label = gtk_label_new("Get an brand new password!");
    gtk_widget_set_halign(change_password_text_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(change_password_text_label, (const char *[]){"custom-text", NULL});

    gtk_box_append(GTK_BOX(change_password_title_container), change_password_title_label);
    gtk_box_append(GTK_BOX(change_password_title_container), change_password_text_label);

    //AUthentificate questions
    GtkWidget *question_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(question_container, container_width, -1);
    gtk_widget_set_halign(question_container, GTK_ALIGN_CENTER);

    GtkWidget *authenticate_text_label = gtk_label_new("Confirm your identity:");
    gtk_widget_set_halign(authenticate_text_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(authenticate_text_label, (const char *[]){"custom-label", NULL}); // css

    GtkWidget *authenticate_first_question_label = gtk_label_new("What is your favorite cartoon character*?");
    gtk_widget_set_halign(authenticate_first_question_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(authenticate_first_question_label, (const char *[]){"custom-label", NULL}); // css

    GtkWidget *authenticate_first_question_entry = gtk_entry_new();
    gtk_widget_set_size_request(authenticate_first_question_entry, 200, -1);
    gtk_widget_set_css_classes(authenticate_first_question_entry, (const char *[]){"custom-entry", NULL}); // css

    GtkWidget *authenticate_second_question_label = gtk_label_new("What is the weirdest food you've eaten*?");
    gtk_widget_set_halign(authenticate_second_question_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(authenticate_second_question_label, (const char *[]){"custom-label", NULL}); // css

    GtkWidget *authenticate_second_question_entry = gtk_entry_new();
    gtk_widget_set_size_request(authenticate_second_question_entry, 200, -1);
    gtk_widget_set_css_classes(authenticate_second_question_entry, (const char *[]){"custom-entry", NULL}); // css

    gtk_box_append(GTK_BOX(question_container), authenticate_text_label);
    gtk_box_append(GTK_BOX(question_container), authenticate_first_question_label);
    gtk_box_append(GTK_BOX(question_container), authenticate_first_question_entry);
    gtk_box_append(GTK_BOX(question_container), authenticate_second_question_label);
    gtk_box_append(GTK_BOX(question_container), authenticate_second_question_entry);

    
    //Buttons : Change and return to login
    GtkWidget *change_buttons_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_size_request(change_buttons_container, container_width, -1);
    gtk_widget_set_halign(change_buttons_container, GTK_ALIGN_CENTER);

    GtkWidget *change_button = gtk_button_new_with_label("UPDATE");
    g_signal_connect(change_button, "clicked", G_CALLBACK(handle_forgot_password), stack);
    gtk_widget_set_css_classes(change_button,(const char *[]){"custom-button", NULL}); //css
    gtk_widget_set_margin_top(change_button, 5);

    GtkWidget *return_link = gtk_button_new_with_label("Return to Login");
    g_signal_connect(return_link, "clicked", return_to_login_callback, stack);
    gtk_widget_set_css_classes(return_link,(const char *[]){"link-account-button", NULL}); //css
    gtk_widget_set_margin_top(return_link, 5);

    gtk_box_append(GTK_BOX(change_buttons_container), change_button);
    gtk_box_append(GTK_BOX(change_buttons_container), return_link);

    // Add container to main box
    gtk_box_append(GTK_BOX(forgot_box), change_password_title_container);
    gtk_box_append(GTK_BOX(forgot_box), question_container);
    gtk_box_append(GTK_BOX(forgot_box), change_buttons_container);

    gtk_stack_add_named(GTK_STACK(stack), forgot_box, "forgot_password");
}