#include "callbacks/CreateAccountCallbacks.h"
#include "network/handlenetwork/NetworkHandlers.h"
#include "network/log/ClientLogging.h"
#include "graphics/utils/Utils.h"
#include "logic/login/ValidationProcess.h"
#include "callbacks/GuiCallbacks.h"

void on_create_account_button_clicked(GtkButton *button, CreateAccountData *data) {
    const char *first_name = gtk_editable_get_text(GTK_EDITABLE(data->first_name_entry));
    const char *last_name = gtk_editable_get_text(GTK_EDITABLE(data->last_name_entry));
    const char *username = gtk_editable_get_text(GTK_EDITABLE(data->username_entry));
    const char *email = gtk_editable_get_text(GTK_EDITABLE(data->email_entry));
    const char *password = gtk_editable_get_text(GTK_EDITABLE(data->password_entry));
    const char *retype_password = gtk_editable_get_text(GTK_EDITABLE(data->retype_password_entry));
    const char *first_question = gtk_editable_get_text(GTK_EDITABLE(data->first_question_entry));
    const char *second_question = gtk_editable_get_text(GTK_EDITABLE(data->second_question_entry));

    // Verify if entries are empty
    if (strlen(first_name) == 0 || strlen(last_name) == 0 || 
        strlen(username) == 0 || strlen(email) == 0 || 
        strlen(password) == 0 || strlen(retype_password) == 0 ||
        strlen(first_question) == 0 || strlen(second_question) == 0) {
        log_client_message(LOG_WARNING, "Registration fields are empty");
        show_custom_dialog("Error", "Please fill in all fields");
        return;
    }

    // Validate email
    if (!validate_email(email)) {
        log_client_message(LOG_WARNING, "Invalid email format");
        show_custom_dialog("Error", "Invalid email format");
        return;
    }

    // Validate password
    if (!validate_password(password)) {
        log_client_message(LOG_WARNING, "Invalid password format");
        show_custom_dialog("Error", "Password must be at least 10 characters long and contain uppercase, lowercase, number and special character");
        return;
    }

    // Check if passwords match
    if (strcmp(password, retype_password) != 0) {
        log_client_message(LOG_WARNING, "Passwords do not match");
        show_custom_dialog("Error", "Passwords do not match");
        return;
    }

    // Send registration request
    log_client_message(LOG_INFO, "Sending registration request");
    if (!send_registration_request(first_name, last_name, username, email, password, first_question, second_question)) {
        show_custom_dialog("Error", "Failed to send registration request");
        return;
    }

}

//free memory create account page
void cleanup_create_account_interface(CreateAccountData *data) {
    log_client_message(LOG_INFO, "Cleaning up create account interface");
    if (data) {
        g_free(data);
    }
}