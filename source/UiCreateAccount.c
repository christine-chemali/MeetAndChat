#include <gtk/gtk.h>
#include "Utils.h"

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
    //Title
    GtkWidget *account_title_container = gtk_box_new(GTK_ORIENTATION_VERTICAL,0);
    gtk_widget_set_size_request(account_title_container, container_width, -1);
    gtk_widget_set_halign(account_title_container, GTK_ALIGN_CENTER);

    GtkWidget *account_title_label = gtk_label_new("SIGN UP");
    gtk_widget_set_halign(account_title_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(account_title_label, (const char *[]){"custom-title", NULL});

    GtkWidget *account_text_label = gtk_label_new("Get started!");
    gtk_widget_set_halign(account_text_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(account_text_label, (const char *[]){"custom-text", NULL});

    gtk_box_append(GTK_BOX(account_title_container), account_title_label);
    gtk_box_append(GTK_BOX(account_title_container), account_text_label);

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

    GtkWidget *email_label = gtk_label_new("Email*:");
    gtk_widget_set_halign(email_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(email_label, (const char *[]){"custom-label", NULL});//css
    
    GtkWidget *email_entry = gtk_entry_new();
    gtk_widget_set_size_request(email_entry, 200, -1);
    gtk_widget_set_css_classes(email_entry, (const char *[]){"custom-entry", NULL});//css

    gtk_box_append(GTK_BOX(identify_container), first_name_label);
    gtk_box_append(GTK_BOX(identify_container), first_name_entry);
    gtk_box_append(GTK_BOX(identify_container), last_name_label);
    gtk_box_append(GTK_BOX(identify_container), last_name_entry);
    gtk_box_append(GTK_BOX(identify_container), username_label);
    gtk_box_append(GTK_BOX(identify_container), username_entry);
    gtk_box_append(GTK_BOX(identify_container), email_label);
    gtk_box_append(GTK_BOX(identify_container), email_entry);

    //Password
    GtkWidget *account_password_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(account_password_container, container_width, -1);
    gtk_widget_set_halign(account_password_container, GTK_ALIGN_CENTER);

    GtkWidget *account_password_label = gtk_label_new("Password*:");
    gtk_widget_set_halign(account_password_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(account_password_label, (const char *[]){"custom-label", NULL}); // css

    GtkWidget *account_password_entry = gtk_entry_new(); 
    gtk_entry_set_visibility(GTK_ENTRY(account_password_entry), FALSE);
    gtk_widget_set_size_request(account_password_entry, 200, -1);
    gtk_widget_set_css_classes(account_password_entry, (const char *[]){"custom-entry", NULL}); // css

    GtkWidget *password_label_checkbox_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_set_spacing(GTK_BOX(password_label_checkbox_box), 115); 

    GtkWidget *account_retype_password_label = gtk_label_new("Re-type password*:");
    gtk_widget_set_halign(account_retype_password_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(account_retype_password_label, (const char *[]){"custom-label", NULL}); // css

    GtkWidget *retype_password_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(retype_password_entry), FALSE);
    gtk_widget_set_size_request(retype_password_entry, 200, -1);
    gtk_widget_set_css_classes(retype_password_entry, (const char *[]){"custom-entry", NULL}); // css

    GtkWidget *show_account_password_check = gtk_check_button_new_with_label("Show");
    gtk_widget_set_halign(show_account_password_check, GTK_ALIGN_END);
    g_signal_connect(show_account_password_check, "toggled", G_CALLBACK(toggle_passwordVisibility), account_password_entry);
    g_signal_connect(show_account_password_check, "toggled", G_CALLBACK(toggle_passwordVisibility), retype_password_entry);
    gtk_widget_set_css_classes(show_account_password_check, (const char *[]){"custom-checkbox", NULL}); // css

    gtk_box_append(GTK_BOX(password_label_checkbox_box), account_password_label);
    gtk_box_append(GTK_BOX(password_label_checkbox_box), show_account_password_check);

    gtk_box_append(GTK_BOX(account_password_container), password_label_checkbox_box);
    gtk_box_append(GTK_BOX(account_password_container), account_password_entry);
    gtk_box_append(GTK_BOX(account_password_container), account_retype_password_label);
    gtk_box_append(GTK_BOX(account_password_container), retype_password_entry);

    //Recover questions
    GtkWidget *recover_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(recover_container, container_width, -1);
    gtk_widget_set_halign(recover_container, GTK_ALIGN_CENTER);

    GtkWidget *recover_label = gtk_label_new("To recover your account, please answer:");
    gtk_widget_set_halign(recover_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(recover_label, (const char *[]){"custom-label", NULL}); // css

    GtkWidget *recover_first_question_label = gtk_label_new("What is your favorite cartoon character*?");
    gtk_widget_set_halign(recover_first_question_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(recover_first_question_label, (const char *[]){"custom-label", NULL}); // css

    GtkWidget *first_question_entry = gtk_entry_new();
    gtk_widget_set_size_request(first_question_entry, 200, -1);
    gtk_widget_set_css_classes(first_question_entry, (const char *[]){"custom-entry", NULL}); // css

    GtkWidget *recover_second_question_label = gtk_label_new("What is the weirdest food you've eaten*?");
    gtk_widget_set_halign(recover_second_question_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(recover_second_question_label, (const char *[]){"custom-label", NULL}); // css

    GtkWidget *second_question_entry = gtk_entry_new();
    gtk_widget_set_size_request(second_question_entry, 200, -1);
    gtk_widget_set_css_classes(second_question_entry, (const char *[]){"custom-entry", NULL}); // css

    gtk_box_append(GTK_BOX(recover_container), recover_label);
    gtk_box_append(GTK_BOX(recover_container), recover_first_question_label);
    gtk_box_append(GTK_BOX(recover_container), first_question_entry);
    gtk_box_append(GTK_BOX(recover_container), recover_second_question_label);
    gtk_box_append(GTK_BOX(recover_container), second_question_entry);

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
    gtk_box_append(GTK_BOX(account_box), account_title_container);
    gtk_box_append(GTK_BOX(account_box), identify_container);
    gtk_box_append(GTK_BOX(account_box), account_password_container);
    gtk_box_append(GTK_BOX(account_box), recover_container);
    gtk_box_append(GTK_BOX(account_box), action_button_container);

    gtk_stack_add_named(GTK_STACK(stack), account_box, "create_account");
}